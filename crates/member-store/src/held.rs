//! A database that can be closed while others still hold the store.
//!
//! A network's stores are shared: every state read from them holds them, so
//! the last holder going is not something anybody can wait for. A recovery
//! has to move the files all the same, and Windows will not copy or remove a
//! file a process holds open (`recovery-repairs` design §1). So the store is
//! closed on request: writes under way end first, waited for rather than
//! polled, and then the file is let go. A read still under way is answered
//! that the database is closed (redb's own close), and every use after that
//! is told the same.

use std::sync::{Condvar, Mutex};

use redb::{Database, ReadTransaction, ReadableDatabase, StorageError, TransactionError};

/// The database, until it is closed.
pub(crate) struct Held {
    db: Mutex<Option<Database>>,
    /// Whether it is closing, and how many writes are under way.
    writes: Mutex<(bool, usize)>,
    /// Told when a write ends.
    ended: Condvar,
}

/// What every use is told once the database is closed.
fn closed() -> TransactionError {
    TransactionError::Storage(StorageError::DatabaseClosed)
}

impl Held {
    pub(crate) fn new(db: Database) -> Self {
        Self { db: Mutex::new(Some(db)), writes: Mutex::new((false, 0)), ended: Condvar::new() }
    }

    /// Begins a read, or says the database is closed.
    pub(crate) fn begin_read(&self) -> Result<ReadTransaction, TransactionError> {
        let held = self.db.lock().map_err(|_| closed())?;
        held.as_ref().ok_or_else(closed)?.begin_read()
    }

    /// Begins a write, counted until it ends, or says the database is closed.
    pub(crate) fn begin_write(&self) -> Result<Writing<'_>, TransactionError> {
        {
            let mut writes = self.writes.lock().map_err(|_| closed())?;
            if writes.0 {
                return Err(closed());
            }
            writes.1 = writes.1.saturating_add(1);
        }
        let counted = Counted(self);
        let transaction = {
            let held = self.db.lock().map_err(|_| closed())?;
            held.as_ref().ok_or_else(closed)?.begin_write()?
        };
        Ok(Writing { transaction, counted })
    }

    /// Closes the database: no write begins from now on, those under way are
    /// waited for, and the file is let go. Blocks until then; writes are
    /// bounded by their own work. Closing twice does nothing more.
    pub(crate) fn close(&self) {
        if let Ok(mut writes) = self.writes.lock() {
            writes.0 = true;
            while writes.1 > 0 {
                match self.ended.wait(writes) {
                    Ok(next) => writes = next,
                    Err(_) => return,
                }
            }
        }
        let taken = self.db.lock().ok().and_then(|mut held| held.take());
        if let Some(db) = taken {
            // No write is under way, so this closes the file now; a read
            // still under way is told the database is closed.
            let _closed = db.close();
        }
    }
}

/// A write under way, counted until it ends.
struct Counted<'a>(&'a Held);

impl Drop for Counted<'_> {
    fn drop(&mut self) {
        if let Ok(mut writes) = self.0.writes.lock() {
            writes.1 = writes.1.saturating_sub(1);
        }
        self.0.ended.notify_all();
    }
}

/// A write transaction, counted as under way until it is committed, aborted
/// or dropped.
pub(crate) struct Writing<'a> {
    /// Dropped before the count is: declared first.
    transaction: redb::WriteTransaction,
    counted: Counted<'a>,
}

impl Writing<'_> {
    /// Commits the write, and only then counts it as ended.
    pub(crate) fn commit(self) -> Result<(), redb::CommitError> {
        let Self { transaction, counted } = self;
        let committed = transaction.commit();
        drop(counted);
        committed
    }
}

impl core::ops::Deref for Writing<'_> {
    type Target = redb::WriteTransaction;

    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}

impl core::ops::DerefMut for Writing<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.transaction
    }
}
