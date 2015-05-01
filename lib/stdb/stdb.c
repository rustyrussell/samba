#include "stdb.h"
#include "includes.h"
#include <util/util_tdb.h>
#include <crypto/sha256.h>
#include <system/filesys.h>

/* All the world's a Linux! */
#include <sys/sysinfo.h>

/* We can have an ~4GB tdb, so this needs to be larger than that.
 * We assume 64 bit off_t */
#define MAX_LOG_SIZE (8ULL * 1024 * 1024 * 1024)

static struct stdb_context *stdbs;

struct stdb_context {
	struct stdb_context *next;
	struct tdb_context *tdb;
	const char *syncname;
	int soft_sync_fd;
	enum TDB_ERROR stdb_err;
	SHA256_CTX sha;
	unsigned int tdb_transaction_nest;
};

enum stdb_logtype {
	STDB_WIPE_ALL = 1,
	STDB_STORE = 2,
	STDB_DELETE = 3,
	STDB_APPEND = 4,
	STDB_DELFLAGS = 5,
	STDB_ADDFLAGS = 6,
	STDB_TRANSACTION_CANCEL = 7,
	STDB_TRANSACTION_COMMIT = 8
};

/* We use offset 1, unused by tdb itself. */
static bool grab_tdb_synclock(struct tdb_context *tdb)
{
	struct flock fl;

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 1;
	fl.l_len = 1;

	return fcntl(tdb_fd(tdb), F_SETLKW, &fl) == 0;
}

static void drop_tdb_synclock(struct tdb_context *tdb)
{
	struct flock fl;

	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 1;
	fl.l_len = 1;

	fcntl(tdb_fd(tdb), F_SETLKW, &fl);
}

/* FIXME: This should be in libreplace!  Or utils, or something... */
static time_t boot_time(void)
{
	struct sysinfo sinfo;

	if (sysinfo(&sinfo) == 0)
		return time(NULL) - sinfo.uptime;
	return 0;
}

/* If log file is older than boot, reconstruct */
static bool file_too_old(struct stdb_context *stdb)
{
	struct stat st;
	time_t boot = boot_time();

	/* If this fails, we're in deep trouble: restore should fail */
	if (fstat(stdb->soft_sync_fd, &st) != 0)
		return true;

	return (st.st_mtime < boot);
}

/* Write an entry to the log, and add it to the SHA hash. */
static bool log_write_raw(int fd, enum stdb_logtype type,
			  const TDB_DATA a, const TDB_DATA b, int flags,
			  SHA256_CTX *sha)
{
	struct iovec iov[3]; /* le_vals, a, b */
	int32_t le_vals[4]; /* type, flags, asize, bsize */
	int i, tot_len;

	/* The "softsync disabled" case. */
	if (fd < 0)
		return true;

	SIVAL(&le_vals[0], 0, type);
	SIVAL(&le_vals[3], 0, flags);
	SIVAL(&le_vals[4], 0, a.dsize);
	SIVAL(&le_vals[5], 0, b.dsize);

	/* We use writev, as we need atomic writes. */
	iov[0].iov_base = &le_vals;
	iov[0].iov_len = sizeof(le_vals);
	iov[1].iov_base = a.dptr;
	iov[1].iov_len = a.dsize;
	iov[2].iov_base = b.dptr;
	iov[2].iov_len = b.dsize;

	tot_len = 0;
	for (i = 0; i < sizeof(iov)/sizeof(iov[0]); i++) {
		samba_SHA256_Update(sha, iov[i].iov_base, iov[i].iov_len);
		tot_len += iov[i].iov_len;
	}

	/* This *only* preserves ordering if we're inside a transaction,
	 * since we can race with more than one writer. */
	if (writev(fd, iov, sizeof(iov)/sizeof(iov[0])) != tot_len) {
		return false;
	}
		    
	return true;
}

struct tolog_info {
	int log_fd;
	bool ok;
	SHA256_CTX sha;	
};

static int tdb_tolog(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data,
		     void *info_)
{
	struct tolog_info *info = info_;

	if (!log_write_raw(info->log_fd, STDB_STORE, key, data, TDB_INSERT,
			   &info->sha)) {
		info->ok = false;
		return 1; /* stop traverse. */
	}
	return 0;
}

static bool commit_transaction(int fd, SHA256_CTX *sha)
{
	char checksum[SHA256_DIGEST_LENGTH];

	if (!log_write_raw(fd, STDB_TRANSACTION_COMMIT, tdb_null, tdb_null, 0, sha)) {
		return false;
	}

	samba_SHA256_Final(checksum, sha);
	/* Re-initialize for next time. */
	samba_SHA256_Init(sha);

	/* We write the checksum RAW, since it can't checksum itself. */
	return write(fd, checksum, sizeof(checksum)) == sizeof(checksum);
}

/* The log file initially contains instructions to recreate the db. */
static bool init_soft_sync(struct stdb_context *stdb, int fd)
{
	struct tolog_info info;
	int dirfd, trav;

	samba_SHA256_Init(&info.sha);
	info.log_fd = fd;
	info.ok = true;
	
	/* Dump existing database in there. */
	trav = tdb_traverse_read(stdb->tdb, tdb_tolog, &info);
	if (trav < 0 || !info.ok) {
		return false;
	}

	if (!commit_transaction(fd, &info.sha)) {
		return false;
	}

	if (fsync(fd) != 0) {
		return false;
	}

	return true;
}

/* This is how we detect if the log has already been rotated. mode is
 * saved here as an optimization, since we're stating anyway. */
static bool files_equal(int fd1, int fd2, mode_t *mode)
{
	struct stat st1, st2;

	fstat(fd1, &st1);
	fstat(fd2, &st2);
	/* Either mode will do: only used if they're equal. */
	*mode = st2.st_mode;

	return st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino;
}
		
/* After a transaction commit, we may compress log. */
static bool maybe_flip_log(struct stdb_context *stdb)
{
	TALLOC_CTX *ctx;
	char *tmpname, *dirname;
	int fd, dirfd;
	mode_t mode;

	if (lseek(stdb->soft_sync_fd, 0, SEEK_END) < MAX_LOG_SIZE) {
		return true;
	}

	/* Our log is full, create fresh one to replace it. */
	ctx = talloc_new(stdb);
	if (!ctx) {
		return false;
	}

	tmpname = talloc_asprintf(ctx, "%s.tmp", stdb->syncname);
	dirname = talloc_strdup(ctx, stdb->syncname);

	if (!tmpname || !dirname) {
		goto fail;
	}
		
	if (strrchr(dirname, '/')) {
		*strrchr(dirname, '/') = '\0';
	} else {
		dirname = talloc_strdup(ctx, ".");
		if (!dirname) {
			goto fail;
		}
	}

	/* Only one process at a time. */
	if (!grab_tdb_synclock(stdb->tdb)) {
		goto fail;
	}

	/* Check if it has already flipped. */
	fd = open(stdb->syncname, O_APPEND|O_RDWR);
	if (fd < 0) {
		goto fail_unlock;
	}
	if (!files_equal(fd, stdb->soft_sync_fd, &mode)) {
		/* Already done, switch to new one. */
		close(stdb->soft_sync_fd);
		stdb->soft_sync_fd = fd;
		drop_tdb_synclock(stdb->tdb);
		return true;
	}
	close(fd);

	/* If an old one exists, implies it died with lock, which is OK */
	fd = open(tmpname, O_APPEND|O_RDWR|O_CREAT|O_TRUNC, mode);
	if (fd < 0) {
		goto fail_unlock;
	}

	/* Dump full tdb into it: this is equivalent to compressing
	 * the existing log. */
	if (!init_soft_sync(stdb, fd)) {
		goto fail_deltmp;
	}

	/* Now rename, and sync dir to ensure it sticks.  We don't
	 * really care if users see the old log in future, *but* if
	 * everyone closes it, blocks inside it could be reused before
	 * the directory is updated on disk, corrupting it further
	 * back than we would expect.
	 */
	dirfd = open(dirname, O_RDONLY);
	if (dirfd < 0) {
		goto fail_deltmp;
	}

	if (rename(tmpname, stdb->syncname) != 0) {
		goto fail_closedirfd;
	}
	fsync(dirfd);
	close(dirfd);

	close(stdb->soft_sync_fd);
	stdb->soft_sync_fd = fd;
	drop_tdb_synclock(stdb->tdb);
	talloc_free(ctx);
	return true;

fail_closedirfd:
	close(dirfd);
fail_deltmp:
	close(fd);
	unlink(tmpname);
fail_unlock:
	drop_tdb_synclock(stdb->tdb);
fail:
	talloc_free(ctx);
	return false;
}

/* FIXME: We can use mmap and mutexes to implement our own append
 * semantics, which would be faster than a syscall. */
static bool log_write(struct stdb_context *stdb, enum stdb_logtype type,
		      const TDB_DATA a, const TDB_DATA b, int flags)
{
	if (!log_write_raw(stdb->soft_sync_fd, type, a, b, flags, &stdb->sha)) {
		stdb->stdb_err = TDB_ERR_IO;
		return false;
	}
	return true;
}

static bool log_add(struct stdb_context *stdb, enum stdb_logtype type)
{
	return log_write(stdb, type, tdb_null, tdb_null, 0);
}

static bool log_add_data(struct stdb_context *stdb, enum stdb_logtype type,
			 TDB_DATA data)
{
	return log_write(stdb, type, data, tdb_null, 0);
}

static bool log_add_key_data_flag(struct stdb_context *stdb,
				  enum stdb_logtype type, 
				  TDB_DATA key,
				  TDB_DATA data, int flags)
{
	return log_write(stdb, type, key, data, flags);
}

static bool log_add_key_data(struct stdb_context *stdb,
			     enum stdb_logtype type, 
			     TDB_DATA key,
			     TDB_DATA data)
{
	return log_write(stdb, type, key, data, 0);
}

static bool log_add_flag(struct stdb_context *stdb,
			 enum stdb_logtype type, 
			 int flags)
{
	return log_write(stdb, type, tdb_null, tdb_null, flags);
}

/* This assumes no file descriptor sharing, so seek pointer is
 * reliable. */
static bool log_read(int fd, enum stdb_logtype *type,
		     TDB_DATA *a, TDB_DATA *b, int *flags,
		     SHA256_CTX *sha)
{
	int32_t le_vals[4]; /* type, flags, asize, bsize */
	int i, tot_len;
	uint64_t now;

	/* The "softsync disabled" case. */
	if (fd < 0)
		return false;

	if (read(fd, &le_vals, sizeof(le_vals)) != sizeof(le_vals)) {
		return false;
	}

	*type = IVAL(&le_vals[0], 0);
	*flags = IVAL(&le_vals[1], 0);
	
	a->dsize = IVAL(&le_vals[2], 0);
	if (a->dsize != 0) {
		a->dptr = malloc(a->dsize);
		if (!a->dptr) {
			return false;
		}
		if (read(fd, a->dptr, a->dsize) != a->dsize) {
			free(a->dptr);
			return false;
		}
	} else
		a->dptr = NULL;

	b->dsize = IVAL(&le_vals[3], 0);
	if (b->dsize != 0) {
		b->dptr = malloc(b->dsize);
		if (!b->dptr) {
			free(a->dptr);
			return false;
		}
		if (read(fd, b->dptr, b->dsize) != b->dsize) {
			free(a->dptr);
			free(b->dptr);
			return false;
		}
	} else
		b->dptr = NULL;

	samba_SHA256_Update(sha, &le_vals, sizeof(le_vals));
	samba_SHA256_Update(sha, a->dptr, a->dsize);
	samba_SHA256_Update(sha, b->dptr, b->dsize);

	return true;
}

static bool checksum_correct(int fd, SHA256_CTX *sha)
{
	char checksum[SHA256_DIGEST_LENGTH], expect[SHA256_DIGEST_LENGTH];

	if (read(fd, checksum, sizeof(checksum)) != sizeof(checksum)) {
		return false;
	}
	samba_SHA256_Final(expect, sha);
	return memcmp(checksum, expect, sizeof(expect)) == 0;
}

/* We could avoid a transaction here, but we want transactional
 * semantics (eg. we transaction_cancel if log transaction_cancels)
 */
static bool recreate_tdb_from_log(struct stdb_context *stdb)
{
	SHA256_CTX sha;
	enum stdb_logtype type;
	TDB_DATA a, b;
	int flags;

	samba_SHA256_Init(&sha);
	if (tdb_transaction_start(stdb->tdb) != 0)
		return false;

	if (tdb_wipe_all(stdb->tdb) != 0)
		return false;
	
	while (log_read(stdb->soft_sync_fd, &type, &a, &b, &flags, &sha)) {
		switch (type) {
		case STDB_WIPE_ALL:
			if (tdb_wipe_all(stdb->tdb) != 0) {
				return false;
			}
			break;
		case STDB_STORE:
			if (tdb_store(stdb->tdb, a, b, flags) != 0) {
				return false;
			}
			break;
		case STDB_DELETE:
			if (tdb_delete(stdb->tdb, a) != 0) {
				return false;
			}
			break;
		case STDB_APPEND:
			if (tdb_append(stdb->tdb, a, b) != 0) {
				return false;
			}
			break;
		case STDB_DELFLAGS:
			tdb_remove_flags(stdb->tdb, flags);
			break;
		case STDB_ADDFLAGS:
			tdb_add_flags(stdb->tdb, flags);
			break;
		case STDB_TRANSACTION_CANCEL:
			if (tdb_transaction_cancel(stdb->tdb) != 0) {
				return false;
			}
			/* Start a new one immediately. */
			if (tdb_transaction_start(stdb->tdb) != 0) {
				return false;
			}
			break;
		case STDB_TRANSACTION_COMMIT:
			if (!checksum_correct(stdb->soft_sync_fd, &sha)) {
				return false;
			}
			if (tdb_transaction_commit(stdb->tdb) != 0) {
				return false;
			}
			/* Start a new one immediately. */
			if (tdb_transaction_start(stdb->tdb) != 0) {
				return false;
			}
			break;
		default:
			return false;
		}
	}

	/* We should have an outstanding transction, so this should succeed. */
	return tdb_transaction_cancel(stdb->tdb) == 0;
}

struct stdb_context *stdb_open(TALLOC_CTX *ctx,
			       const char *name, int hash_size, int tdb_flags,
			       int open_flags, mode_t mode,
			       const struct tdb_logging_context *log_ctx,
			       bool soft_sync)
{
	struct stdb_context *stdb = talloc(ctx, struct stdb_context);
	int fd;

	if (!stdb) {
		return NULL;
	}
	stdb->tdb = tdb_open_ex(name, hash_size, tdb_flags, open_flags,
				mode, log_ctx, NULL);
	stdb->stdb_err = TDB_SUCCESS;
	samba_SHA256_Init(&stdb->sha);
	stdb->tdb_transaction_nest = 0;

	if (!stdb->tdb) {
		talloc_free(stdb);
		return NULL;
	}

	stdb->soft_sync_fd = -1;

	/* Don't do softsync on internal tdbs. */
	if (tdb_flags & TDB_INTERNAL)
		return stdb;

	/* FIXME: Check recovery, return fail if it's needed. */
	if ((open_flags & O_ACCMODE) != O_RDONLY)
		return stdb;

	/* Don't do softsync if not asked to. */
	if (!soft_sync)
		return stdb;

	stdb->syncname = talloc_asprintf(ctx, "%s.softsync", name);
	if (!stdb->syncname) {
		goto fail;
	}

	/* Lock on TDB protects creation of synclog. */
	if (!grab_tdb_synclock(stdb->tdb)) {
		goto fail;
	}

	stdb->soft_sync_fd = open(stdb->syncname, O_APPEND|O_RDWR);

	/* If it doesn't exist create it. */
	if (stdb->soft_sync_fd < 0) {
		if (errno == ENOENT) {
			stdb->soft_sync_fd = open(stdb->syncname,
						  O_CREAT|O_EXCL|O_APPEND|O_RDWR,
						  mode);
		}
		/* Create failed, or non-ENOENT error */
		if (stdb->soft_sync_fd < 0) {
			goto fail;
		}
		if (!init_soft_sync(stdb, stdb->soft_sync_fd)) {
			goto fail;
		}
	}

	if (file_too_old(stdb)) {
		if (!recreate_tdb_from_log(stdb)) {
			goto fail;
		}
	}

	/* Sew into global list. */
	stdb->next = stdbs;
	stdbs = stdb;

	/* Drop synclock */
	drop_tdb_synclock(stdb->tdb);
	return stdb;

fail:
	tdb_close(stdb->tdb);
	talloc_free(stdb);
	return NULL;

}

enum TDB_ERROR stdb_error(struct stdb_context *stdb)
{
	if (stdb->stdb_err == TDB_SUCCESS) {
		return tdb_error(stdb->tdb);
	}
	return stdb->stdb_err;
}

const char *stdb_errorstr(struct stdb_context *stdb)
{
	/* FIXME: There's only one error! */
	if (stdb->stdb_err != TDB_SUCCESS) {
		return "Soft syncing sunk.";
	}
	return tdb_errorstr(stdb->tdb);
}

TDB_DATA stdb_fetch(struct stdb_context *stdb, TDB_DATA key)
{
	return tdb_fetch(stdb->tdb, key);
}

int stdb_parse_record(struct stdb_context *stdb, TDB_DATA key,
			      int (*parser)(TDB_DATA key, TDB_DATA data,
					    void *private_data),
			      void *private_data)
{
	return tdb_parse_record(stdb->tdb, key, parser, private_data);
}

/* This could fail because it doesn't exist: only log if it succeeds */
int stdb_delete(struct stdb_context *stdb, TDB_DATA key)
{
	int ret;

	ret = tdb_delete(stdb->tdb, key);
	if (ret == 0) {
		if (!log_add_data(stdb, STDB_DELETE, key)) {
			return -1;
		}
	}
	return ret;	
}

/* This could fail because it does(n't) exist: only log if it succeeds */
int stdb_store(struct stdb_context *stdb, TDB_DATA key, TDB_DATA dbuf, int flag)
{
	int ret;

	ret = tdb_store(stdb->tdb, key, dbuf, flag);
	if (ret == 0) {
		if (!log_add_key_data_flag(stdb, STDB_STORE, key, dbuf, flag)) {
			ret = -1;
		}
	}
	return ret;
}

/* This could fail because it doesn't exist: only log if it succeeds */
int stdb_append(struct stdb_context *stdb, TDB_DATA key, TDB_DATA new_dbuf)
{
	int ret;

	ret = tdb_append(stdb->tdb, key, new_dbuf);
	
	if (ret == 0) {
		if (!log_add_key_data(stdb, STDB_APPEND, key, new_dbuf)) {
			return -1;
		}
	}
	return ret;
}

int stdb_close(struct stdb_context *stdb)
{
	struct stdb_context **i;

	/* Delete from global list. */
	for (i = &stdbs; *i; i = &(*i)->next) {
		if (*i == stdb) {
			*i = stdb->next;
			break;
		}
	}

	close(stdb->soft_sync_fd);
	return tdb_close(stdb->tdb);
}

TDB_DATA stdb_firstkey(struct stdb_context *stdb)
{
	return tdb_firstkey(stdb->tdb);
}

TDB_DATA stdb_nextkey(struct stdb_context *stdb, TDB_DATA key)
{
	return tdb_nextkey(stdb->tdb, key);
}

int stdb_traverse(struct stdb_context *stdb, tdb_traverse_func fn, void *private_data)
{
	return tdb_traverse(stdb->tdb, fn, private_data);
}

int stdb_traverse_read(struct stdb_context *stdb, tdb_traverse_func fn, void *private_data)
{
	return tdb_traverse_read(stdb->tdb, fn, private_data);
}

int stdb_exists(struct stdb_context *stdb, TDB_DATA key)
{
	return tdb_exists(stdb->tdb, key);
}

int stdb_transaction_start(struct stdb_context *stdb)
{
	int ret = tdb_transaction_start(stdb->tdb);
	if (ret == 0)
		stdb->tdb_transaction_nest++;
	return ret;
}

int stdb_transaction_start_nonblock(struct stdb_context *stdb)
{
	int ret = tdb_transaction_start_nonblock(stdb->tdb);
	if (ret == 0)
		stdb->tdb_transaction_nest++;
	return ret;
}

int stdb_transaction_prepare_commit(struct stdb_context *stdb)
{
	return tdb_transaction_prepare_commit(stdb->tdb);
}

int stdb_transaction_commit(struct stdb_context *stdb)
{
	char checksum[SHA256_DIGEST_LENGTH];

	stdb->tdb_transaction_nest--;
	if (stdb->tdb_transaction_nest == 0) {
		if (stdb->soft_sync_fd != -1
		    && !commit_transaction(stdb->soft_sync_fd, &stdb->sha)) {
			return -1;
		}
		if (!maybe_flip_log(stdb)) {
			return -1;
		}
	}
	return tdb_transaction_commit(stdb->tdb);
}

int stdb_transaction_cancel(struct stdb_context *stdb)
{
	int ret;

	ret = tdb_transaction_cancel(stdb->tdb);

	if (ret == 0) {
		stdb->tdb_transaction_nest--;
		if (stdb->tdb_transaction_nest == 0) {
			if (!log_add(stdb, STDB_TRANSACTION_CANCEL)) {
				return -1;
			}
		}
	}
	return ret;
}

void stdb_add_flags(struct stdb_context *stdb, unsigned flag)
{
	/* Seqnum flags matters, since we need to start updating seqnum. */
	if (flag & TDB_SEQNUM) {
		log_add_flag(stdb, STDB_ADDFLAGS, flag);
	}
	tdb_add_flags(stdb->tdb, flag);
}

void stdb_remove_flags(struct stdb_context *stdb, unsigned flag)
{
	if (flag & TDB_SEQNUM) {
		log_add_flag(stdb, STDB_DELFLAGS, flag);
	}
	tdb_remove_flags(stdb->tdb, flag);
}

void stdb_enable_seqnum(struct stdb_context *stdb)
{
	log_add_flag(stdb, STDB_ADDFLAGS, TDB_SEQNUM);
	tdb_enable_seqnum(stdb->tdb);
}

int stdb_check(struct stdb_context *stdb,
	       int (*check) (TDB_DATA key, TDB_DATA data, void *private_data),
	       void *private_data)
{
	/* FIXME: Replay log file and check against tdb? */
	return tdb_check(stdb->tdb, check, private_data);
}

int stdb_rescue(struct stdb_context *stdb,
	       void (*walk) (TDB_DATA key, TDB_DATA data, void *private_data),
	       void *private_data)
{
	/* FIXME: Replay log file to reconstruct? */
	return tdb_rescue(stdb->tdb, walk, private_data);
}

int stdb_wipe_all(struct stdb_context *stdb)
{
	if (!log_add(stdb, STDB_WIPE_ALL)) {
		return -1;
	}
	return tdb_wipe_all(stdb->tdb);
}

static bool stdb_only_reopen(struct stdb_context *stdb)
{
	if (stdb->soft_sync_fd >= 0) {
		close(stdb->soft_sync_fd);
		stdb->soft_sync_fd = open(stdb->syncname, O_APPEND|O_RDWR);
		if (stdb->soft_sync_fd < 0) {
			return false;
		}
	}
	return true;
}

int stdb_reopen(struct stdb_context *stdb)
{
	if (!stdb_only_reopen(stdb)) {
		stdb_close(stdb);
		return -1;
	}

	/* Careful: if this fails, it will free tdb! */
	if (tdb_reopen(stdb->tdb) != 0) {
		close(stdb->soft_sync_fd);
		talloc_free(stdb);
		return -1;
	}
	return 0;
}

int stdb_reopen_all(int parent_longlived)
{
	struct stdb_context *stdb;

	for (stdb = stdbs; stdb; stdb = stdb->next)
		if (stdb_only_reopen(stdb) != 0) {
			stdb_close(stdb);
			return -1;
		}

	return tdb_reopen_all(parent_longlived);
}

int stdb_repack(struct stdb_context *stdb)
{
	return tdb_repack(stdb->tdb);
}

int stdb_chainlock(struct stdb_context *stdb, TDB_DATA key)
{
	return tdb_chainlock(stdb->tdb, key);
}

int stdb_chainlock_nonblock(struct stdb_context *stdb, TDB_DATA key)
{
	return tdb_chainlock_nonblock(stdb->tdb, key);
}

int stdb_chainunlock(struct stdb_context *stdb, TDB_DATA key)
{
	return tdb_chainunlock(stdb->tdb, key);
}

int stdb_chainlock_read(struct stdb_context *stdb, TDB_DATA key)
{
	return tdb_chainlock_read(stdb->tdb, key);
}

int stdb_chainunlock_read(struct stdb_context *stdb, TDB_DATA key)
{
	return tdb_chainunlock_read(stdb->tdb, key);
}

int stdb_chainlock_mark(struct stdb_context *stdb, TDB_DATA key)
{
	return tdb_chainlock_mark(stdb->tdb, key);
}

int stdb_chainlock_unmark(struct stdb_context *stdb, TDB_DATA key)
{
	return tdb_chainlock_unmark(stdb->tdb, key);
}

void stdb_setalarm_sigptr(struct stdb_context *stdb, volatile sig_atomic_t *sigptr)
{
	tdb_setalarm_sigptr(stdb->tdb, sigptr);
}

int stdb_lockall(struct stdb_context *stdb)
{
	return tdb_lockall(stdb->tdb);
}

int stdb_lockall_nonblock(struct stdb_context *stdb)
{
	return tdb_lockall_nonblock(stdb->tdb);
}

int stdb_unlockall(struct stdb_context *stdb)
{
	return tdb_unlockall(stdb->tdb);
}

int stdb_lockall_read(struct stdb_context *stdb)
{
	return tdb_lockall_read(stdb->tdb);
}

int stdb_lockall_read_nonblock(struct stdb_context *stdb)
{
	return tdb_lockall_read_nonblock(stdb->tdb);
}

int stdb_unlockall_read(struct stdb_context *stdb)
{
	return tdb_unlockall_read(stdb->tdb);
}

int stdb_lockall_mark(struct stdb_context *stdb)
{
	return tdb_lockall_mark(stdb->tdb);
}

int stdb_lockall_unmark(struct stdb_context *stdb)
{
	return tdb_lockall_unmark(stdb->tdb);
}

const char *stdb_name(struct stdb_context *stdb)
{
	return tdb_name(stdb->tdb);
}

int stdb_fd(struct stdb_context *stdb)
{
	return tdb_fd(stdb->tdb);
}

tdb_log_func stdb_log_fn(struct stdb_context *stdb)
{
	return tdb_log_fn(stdb->tdb);
}

void *stdb_get_logging_private(struct stdb_context *stdb)
{
	return tdb_get_logging_private(stdb->tdb);
}

int stdb_get_seqnum(struct stdb_context *stdb)
{
	return tdb_get_seqnum(stdb->tdb);
}

int stdb_hash_size(struct stdb_context *stdb)
{
	return tdb_hash_size(stdb->tdb);
}

size_t stdb_map_size(struct stdb_context *stdb)
{
	return tdb_map_size(stdb->tdb);
}

int stdb_get_flags(struct stdb_context *stdb)
{
	return tdb_get_flags(stdb->tdb);
}
