#ifndef __STDB_H__
#define __STDB_H__
#include <replace.h>
#include <tdb.h>
#include <talloc.h>

/* 
   Unix SMB/CIFS implementation.

   soft-syncing wrapper around trivial database library
   Based on TDB: Copyright (C) Andrew Tridgell 1999-2004

   Copyright Rusty Russell IBM Corporation 2015   

     ** NOTE! The following LGPL license applies to the tdb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

struct stdb_context;

/**
 * @brief Get the tdb underneath an stdb
 *
 * @param[in]  stdb      The stdb
 *
 * @return              The tdb.
 */
struct tdb_context *stdb_to_tdb(struct stdb_context *stdb);

struct stdb_context *stdb_open(TALLOC_CTX *ctx,
			       const char *name, int hash_size, int tdb_flags,
			       int open_flags, mode_t mode,
			       const struct tdb_logging_context *log_ctx,
			       bool soft_sync);

/**
 * @brief Get the stdb last error code.
 *
 * @param[in]  stdb      The stdb to get the error code from.
 *
 * @return              A TDB_ERROR code.
 *
 * @see TDB_ERROR
 */
enum TDB_ERROR stdb_error(struct stdb_context *stdb);

/**
 * @brief Get a error string for the last tdb error
 *
 * @param[in]  stdb      The stdb to get the error code from.
 *
 * @return              An error string.
 */
const char *stdb_errorstr(struct stdb_context *stdb);

/**
 * @brief Fetch an entry in the database given a key.
 *
 * The caller must free the resulting data.
 *
 * @param[in]  stdb      The stdb to fetch the key.
 *
 * @param[in]  key      The key to fetch.
 *
 * @return              The key entry found in the database, NULL on error with
 *                      TDB_ERROR set.
 *
 * @see stdb_error()
 * @see stdb_errorstr()
 */
TDB_DATA stdb_fetch(struct stdb_context *stdb, TDB_DATA key);

/**
 * @brief Hand a record to a parser function without allocating it.
 *
 * This function is meant as a fast stdb_fetch alternative for large records
 * that are frequently read. The "key" and "data" arguments point directly
 * into the stdb shared memory, they are not aligned at any boundary.
 *
 * @warning The parser is called while stdb holds a lock on the record. DO NOT
 * call other stdb routines from within the parser. Also, for good performance
 * you should make the parser fast to allow parallel operations.
 *
 * @param[in]  stdb      The stdb to parse the record.
 *
 * @param[in]  key      The key to parse.
 *
 * @param[in]  parser   The parser to use to parse the data.
 *
 * @param[in]  private_data A private data pointer which is passed to the parser
 *                          function.
 *
 * @return              -1 if the record was not found. If the record was found,
 *                      the return value of "parser" is passed up to the caller.
 */
int stdb_parse_record(struct stdb_context *stdb, TDB_DATA key,
			      int (*parser)(TDB_DATA key, TDB_DATA data,
					    void *private_data),
			      void *private_data);

/**
 * @brief Delete an entry in the database given a key.
 *
 * @param[in]  stdb      The stdb to delete the key.
 *
 * @param[in]  key      The key to delete.
 *
 * @return              0 on success, -1 if the key doesn't exist.
 */
int stdb_delete(struct stdb_context *stdb, TDB_DATA key);

/**
 * @brief Store an element in the database.
 *
 * This replaces any existing element with the same key.
 *
 * @param[in]  stdb      The stdb to store the entry.
 *
 * @param[in]  key      The key to use to store the entry.
 *
 * @param[in]  dbuf     The data to store under the key.
 *
 * @param[in]  flag     The flags to store the key:\n\n
 *                      TDB_INSERT: Don't overwrite an existing entry.\n
 *                      TDB_MODIFY: Don't create a new entry\n
 *
 * @return              0 on success, -1 on error with error code set.
 *
 * @see stdb_error()
 * @see stdb_errorstr()
 */
int stdb_store(struct stdb_context *stdb, TDB_DATA key, TDB_DATA dbuf, int flag);

/**
 * @brief Append data to an entry.
 *
 * If the entry doesn't exist, it will create a new one.
 *
 * @param[in]  stdb      The database to use.
 *
 * @param[in]  key      The key to append the data.
 *
 * @param[in]  new_dbuf The data to append to the key.
 *
 * @return              0 on success, -1 on error with error code set.
 *
 * @see stdb_error()
 * @see stdb_errorstr()
 */
int stdb_append(struct stdb_context *stdb, TDB_DATA key, TDB_DATA new_dbuf);

/**
 * @brief Close a database.
 *
 * @param[in]  stdb      The database to close. The context will be free'd.
 *
 * @return              0 for success, -1 on error.
 *
 * @note Don't call stdb_error() after this function cause the stdb context will
 *       be freed on error.
 */
int stdb_close(struct stdb_context *stdb);

/**
 * @brief Find the first entry in the database and return its key.
 *
 * The caller must free the returned data.
 *
 * @param[in]  stdb      The database to use.
 *
 * @return              The first entry of the database, an empty TDB_DATA entry
 *                      if the database is empty.
 */
TDB_DATA stdb_firstkey(struct stdb_context *stdb);

/**
 * @brief Find the next entry in the database, returning its key.
 *
 * The caller must free the returned data.
 *
 * @param[in]  stdb      The database to use.
 *
 * @param[in]  key      The key from which you want the next key.
 *
 * @return              The next entry of the current key, an empty TDB_DATA
 *                      entry if there is no entry.
 */
TDB_DATA stdb_nextkey(struct stdb_context *stdb, TDB_DATA key);

/**
 * @brief Traverse the entire database.
 *
 * While traversing the function fn(stdb, key, data, state) is called on each
 * element. If fn is NULL then it is not called. A non-zero return value from
 * fn() indicates that the traversal should stop. Traversal callbacks may not
 * start transactions.
 *
 * @warning The data buffer given to the callback fn does NOT meet the alignment
 * restrictions malloc gives you.
 *
 * @param[in]  stdb      The database to traverse.
 *
 * @param[in]  fn       The function to call on each entry.
 *
 * @param[in]  private_data The private data which should be passed to the
 *                          traversing function.
 *
 * @return              The record count traversed, -1 on error.
 */
int stdb_traverse(struct stdb_context *stdb, tdb_traverse_func fn, void *private_data);

/**
 * @brief Traverse the entire database.
 *
 * While traversing the database the function fn(stdb, key, data, state) is
 * called on each element, but marking the database read only during the
 * traversal, so any write operations will fail. This allows stdb to use read
 * locks, which increases the parallelism possible during the traversal.
 *
 * @param[in]  stdb      The database to traverse.
 *
 * @param[in]  fn       The function to call on each entry.
 *
 * @param[in]  private_data The private data which should be passed to the
 *                          traversing function.
 *
 * @return              The record count traversed, -1 on error.
 */
int stdb_traverse_read(struct stdb_context *stdb, tdb_traverse_func fn, void *private_data);

/**
 * @brief Check if an entry in the database exists.
 *
 * @note 1 is returned if the key is found and 0 is returned if not found this
 * doesn't match the conventions in the rest of this module, but is compatible
 * with gdbm.
 *
 * @param[in]  stdb      The database to check if the entry exists.
 *
 * @param[in]  key      The key to check if the entry exists.
 *
 * @return              1 if the key is found, 0 if not.
 */
int stdb_exists(struct stdb_context *stdb, TDB_DATA key);

/**
 * @brief Start a transaction.
 *
 * All operations after the transaction start can either be committed with
 * stdb_transaction_commit() or cancelled with stdb_transaction_cancel().
 *
 * If you call stdb_transaction_start() again on the same stdb context while a
 * transaction is in progress, then the same transaction buffer is re-used. The
 * number of stdb_transaction_{commit,cancel} operations must match the number
 * of successful stdb_transaction_start() calls.
 *
 * Note that transactions are by default disk synchronous, and use a recover
 * area in the database to automatically recover the database on the next open
 * if the system crashes during a transaction. You can disable the synchronous
 * transaction recovery setup using the TDB_NOSYNC flag, which will greatly
 * speed up operations at the risk of corrupting your database if the system
 * crashes.
 *
 * Operations made within a transaction are not visible to other users of the
 * database until a successful commit.
 *
 * @param[in]  stdb      The database to start the transaction.
 *
 * @return              0 on success, -1 on error with error code set.
 *
 * @see stdb_error()
 * @see stdb_errorstr()
 */
int stdb_transaction_start(struct stdb_context *stdb);

/**
 * @brief Start a transaction, non-blocking.
 *
 * @param[in]  stdb      The database to start the transaction.
 *
 * @return              0 on success, -1 on error with error code set.
 *
 * @see stdb_error()
 * @see stdb_errorstr()
 * @see stdb_transaction_start()
 */
int stdb_transaction_start_nonblock(struct stdb_context *stdb);

/**
 * @brief Prepare to commit a current transaction, for two-phase commits.
 *
 * Once prepared for commit, the only allowed calls are stdb_transaction_commit()
 * or stdb_transaction_cancel(). Preparing allocates disk space for the pending
 * updates, so a subsequent commit should succeed (barring any hardware
 * failures).
 *
 * @param[in]  stdb      The database to prepare the commit.
 *
 * @return              0 on success, -1 on error with error code set.
 *
 * @see stdb_error()
 * @see stdb_errorstr()
 */
int stdb_transaction_prepare_commit(struct stdb_context *stdb);

/**
 * @brief Commit a current transaction.
 *
 * This updates the database and releases the current transaction locks.
 *
 * @param[in]  stdb      The database to commit the transaction.
 *
 * @return              0 on success, -1 on error with error code set.
 *
 * @see stdb_error()
 * @see stdb_errorstr()
 */
int stdb_transaction_commit(struct stdb_context *stdb);

/**
 * @brief Cancel a current transaction.
 *
 * This discards all write and lock operations that have been made since the
 * transaction started.
 *
 * @param[in]  stdb      The stdb to cancel the transaction on.
 *
 * @return              0 on success, -1 on error with error code set.
 *
 * @see stdb_error()
 * @see stdb_errorstr()
 */
int stdb_transaction_cancel(struct stdb_context *stdb);

/**
 * @brief Add flags to the database.
 *
 * @param[in]  stdb      The database to add the flags.
 *
 * @param[in]  flag     The stdb flags to add.
 */
void stdb_add_flags(struct stdb_context *stdb, unsigned flag);

/**
 * @brief Remove flags from the database.
 *
 * @param[in]  stdb      The database to remove the flags.
 *
 * @param[in]  flag     The stdb flags to remove.
 */
void stdb_remove_flags(struct stdb_context *stdb, unsigned flag);

/**
 * @brief Enable sequence number handling on an open stdb.
 *
 * @param[in]  stdb      The database to enable sequence number handling.
 *
 * @see stdb_get_seqnum()
 */
void stdb_enable_seqnum(struct stdb_context *stdb);

/**
 * @brief Check the consistency of the database.
 *
 * This check the consistency of the database calling back the check function
 * (if non-NULL) on each record.  If some consistency check fails, or the
 * supplied check function returns -1, stdb_check returns -1, otherwise 0.
 *
 * @note The logging function (if set) will be called with additional
 * information on the corruption found.
 *
 * @param[in]  stdb      The database to check.
 *
 * @param[in]  check    The check function to use.
 *
 * @param[in]  private_data the private data to pass to the check function.
 *
 * @return              0 on success, -1 on error with error code set.
 *
 * @see stdb_error()
 * @see stdb_errorstr()
 */
int stdb_check(struct stdb_context *stdb,
	      int (*check) (TDB_DATA key, TDB_DATA data, void *private_data),
	      void *private_data);

/**
 * @brief Dump all possible records in a corrupt database.
 *
 * This is the only way to get data out of a database where stdb_check() fails.
 * It will call walk() with anything which looks like a database record; this
 * may well include invalid, incomplete or duplicate records.
 *
 * @param[in]  stdb      The database to check.
 *
 * @param[in]  walk     The walk function to use.
 *
 * @param[in]  private_data the private data to pass to the walk function.
 *
 * @return              0 on success, -1 on error with error code set.
 *
 * @see stdb_error()
 * @see stdb_errorstr()
 */
int stdb_rescue(struct stdb_context *stdb,
	       void (*walk) (TDB_DATA key, TDB_DATA data, void *private_data),
	       void *private_data);

/**
 * @brief Check if support for TDB_MUTEX_LOCKING is available at runtime.
 *
 * On some systems the API for pthread_mutexattr_setrobust() is not available.
 * On other systems there are some bugs in the interaction between glibc and
 * the linux kernel.
 *
 * This function provides a runtime check if robust mutexes are really
 * available.
 *
 * This needs to be called and return true before TDB_MUTEX_LOCKING
 * can be used at runtime.
 *
 * @note This calls fork(), but the SIGCHILD handling should be transparent.
 *
 * @return              true if supported, false otherwise.
 *
 * @see TDB_MUTEX_LOCKING
 */
bool stdb_runtime_check_for_robust_mutexes(void);

/* @} ******************************************************************/

/* Low level locking functions: use with care */
/* wipe and repack */
int stdb_wipe_all(struct stdb_context *stdb);
int stdb_repack(struct stdb_context *stdb);

/**
 * @brief Reopen a stdb.
 *
 * This can be used after a fork to ensure that we have an independent seek
 * pointer from our parent and to re-establish locks.
 *
 * @param[in]  stdb      The database to reopen. It will be free'd on error!
 *
 * @return              0 on success, -1 on error.
 *
 * @note Don't call stdb_error() after this function cause the stdb context will
 *       be freed on error.
 */
int stdb_reopen(struct stdb_context *stdb);

/**
 * @brief Reopen all stdb's
 *
 * If the parent is longlived (ie. a parent daemon architecture), we know it
 * will keep it's active lock on a stdb opened with CLEAR_IF_FIRST. Thus for
 * child processes we don't have to add an active lock. This is essential to
 * improve performance on systems that keep POSIX locks as a non-scalable data
 * structure in the kernel.
 *
 * @param[in]  parent_longlived Wether the parent is longlived or not.
 *
 * @return              0 on success, -1 on error.
 */
int stdb_reopen_all(int parent_longlived);

/* These are simple wrappers, for your sedding convenience. */
int stdb_chainlock(struct stdb_context *stdb, TDB_DATA key);
int stdb_chainlock_nonblock(struct stdb_context *stdb, TDB_DATA key);
int stdb_chainunlock(struct stdb_context *stdb, TDB_DATA key);
int stdb_chainlock_read(struct stdb_context *stdb, TDB_DATA key);
int stdb_chainunlock_read(struct stdb_context *stdb, TDB_DATA key);
int stdb_chainlock_mark(struct stdb_context *stdb, TDB_DATA key);
int stdb_chainlock_unmark(struct stdb_context *stdb, TDB_DATA key);
void stdb_setalarm_sigptr(struct stdb_context *stdb, volatile sig_atomic_t *sigptr);
int stdb_lockall(struct stdb_context *stdb);
int stdb_lockall_nonblock(struct stdb_context *stdb);
int stdb_unlockall(struct stdb_context *stdb);
int stdb_lockall_read(struct stdb_context *stdb);
int stdb_lockall_read_nonblock(struct stdb_context *stdb);
int stdb_unlockall_read(struct stdb_context *stdb);
int stdb_lockall_mark(struct stdb_context *stdb);
int stdb_lockall_unmark(struct stdb_context *stdb);
const char *stdb_name(struct stdb_context *stdb);
int stdb_fd(struct stdb_context *stdb);
tdb_log_func stdb_log_fn(struct stdb_context *stdb);
void *stdb_get_logging_private(struct stdb_context *stdb);
int stdb_get_seqnum(struct stdb_context *stdb);
int stdb_hash_size(struct stdb_context *stdb);
size_t stdb_map_size(struct stdb_context *stdb);
int stdb_get_flags(struct stdb_context *stdb);

#ifdef  __cplusplus
}
#endif

#endif /* stdb.h */
