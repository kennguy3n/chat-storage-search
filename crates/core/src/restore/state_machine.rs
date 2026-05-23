//! `restore_state` persistence layer.
//!
//! The [`RestoreState`] enum, transition rules, and serde wire
//! form live in
//! [`crate::local_store::state_machines`] —
//! `state_machine.rs` here only owns the SQL.
//!
//! The `restore_state` table is a single-row table (`CHECK
//! (id = 1)`); the helper API mirrors that:
//!
//! * [`load`] returns `Option<(RestoreState, Option<String>)>`
//!   (no row → restore has not started yet).
//! * [`save`] / [`transition`] insert-or-update the singleton row,
//!   enforcing forward-only motion via
//!   [`RestoreState::try_transition`].

use rusqlite::{params, Connection, OptionalExtension};

use crate::local_store::state_machines::RestoreState;
use crate::Error;

/// Read the current restore state. `None` means the
/// `restore_state` row has not been written yet (restore has not
/// started).
pub fn load(conn: &Connection) -> Result<Option<(RestoreState, Option<String>)>, Error> {
    let row: Option<(String, Option<String>)> = conn
        .query_row(
            "SELECT state, notes FROM restore_state WHERE id = 1",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
        )
        .optional()
        .map_err(|e| Error::Storage(e.to_string().into()))?;
    let parsed = row
        .map(|(state_str, notes)| {
            state_str
                .parse::<RestoreState>()
                .map(|st| (st, notes))
                .map_err(|e| Error::Storage(format!("invalid restore_state: {e}").into()))
        })
        .transpose()?;
    Ok(parsed)
}

/// Insert-or-update the singleton restore-state row to `state`.
///
/// Does **not** consult `try_transition`. Callers that want
/// linear-only motion should use [`transition`] instead.
pub fn save(conn: &Connection, state: RestoreState, notes: Option<&str>) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO restore_state(id, state, notes) VALUES (1, ?1, ?2)
         ON CONFLICT(id) DO UPDATE SET state = excluded.state,
                                       notes = excluded.notes",
        params![state.to_string(), notes],
    )
    .map_err(|e| Error::Storage(e.to_string().into()))?;
    Ok(())
}

/// Transition the persisted restore state to `to`, enforcing
/// linear-forward motion via
/// [`RestoreState::try_transition`].
///
/// If the row does not exist yet, the only legal initial state is
/// [`RestoreState::IdentityRestored`].
pub fn transition(
    conn: &Connection,
    to: RestoreState,
    notes: Option<&str>,
) -> Result<RestoreState, Error> {
    let current = load(conn)?;
    match current {
        None => {
            if to != RestoreState::IdentityRestored {
                return Err(Error::Storage(format!(
                    "restore_state row missing — initial state must be \
                     identity_restored, got {to}"
                ).into()));
            }
            save(conn, to, notes)?;
            Ok(to)
        }
        Some((from, _)) => {
            let next = RestoreState::try_transition(from, to)
                .map_err(|e| Error::Storage(e.to_string().into()))?;
            save(conn, next, notes)?;
            Ok(next)
        }
    }
}

/// Reset the `restore_state` row by deleting it. Used by the
/// orchestrator when a restore aborts and the user retries from
/// scratch.
pub fn reset(conn: &Connection) -> Result<(), Error> {
    conn.execute("DELETE FROM restore_state WHERE id = 1", [])
        .map_err(|e| Error::Storage(e.to_string().into()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_store::db::LocalStoreDb;
    use crate::local_store::state_machines::RestoreState::*;

    fn fresh_db() -> LocalStoreDb {
        LocalStoreDb::open_in_memory(&[0x21; 32]).expect("open in-memory")
    }

    #[test]
    fn load_returns_none_before_first_write() {
        let db = fresh_db();
        assert!(load(db.connection()).unwrap().is_none());
    }

    #[test]
    fn save_then_load_round_trips() {
        let db = fresh_db();
        save(db.connection(), ManifestVerified, Some("note-1")).unwrap();
        let loaded = load(db.connection()).unwrap().unwrap();
        assert_eq!(loaded.0, ManifestVerified);
        assert_eq!(loaded.1.as_deref(), Some("note-1"));
    }

    #[test]
    fn save_overwrites_singleton_row() {
        let db = fresh_db();
        save(db.connection(), IdentityRestored, None).unwrap();
        save(db.connection(), RootKeysUnwrapped, None).unwrap();
        let loaded = load(db.connection()).unwrap().unwrap();
        assert_eq!(loaded.0, RootKeysUnwrapped);
    }

    #[test]
    fn transition_from_empty_requires_identity_restored() {
        let db = fresh_db();
        let err = transition(db.connection(), RootKeysUnwrapped, None).unwrap_err();
        assert!(err.to_string().contains("initial state"), "got {err}");
        // The legal first transition succeeds.
        let st = transition(db.connection(), IdentityRestored, None).unwrap();
        assert_eq!(st, IdentityRestored);
    }

    #[test]
    fn transition_walks_the_full_chain() {
        let db = fresh_db();
        let chain = [
            IdentityRestored,
            RootKeysUnwrapped,
            ManifestVerified,
            SkeletonRestored,
            SearchRestored,
            RecentMessagesRestored,
            MediaLazyRestoreEnabled,
            FullRestoreComplete,
        ];
        for &state in &chain {
            transition(db.connection(), state, None).unwrap();
        }
        assert_eq!(
            load(db.connection()).unwrap().unwrap().0,
            FullRestoreComplete
        );
    }

    #[test]
    fn transition_rejects_illegal_skip() {
        let db = fresh_db();
        transition(db.connection(), IdentityRestored, None).unwrap();
        // Skip RootKeysUnwrapped → ManifestVerified — illegal.
        let err = transition(db.connection(), ManifestVerified, None).unwrap_err();
        assert!(
            err.to_string().contains("identity_restored") || err.to_string().contains("Illegal"),
            "got {err}"
        );
    }

    #[test]
    fn transition_rejects_backwards_motion() {
        let db = fresh_db();
        transition(db.connection(), IdentityRestored, None).unwrap();
        transition(db.connection(), RootKeysUnwrapped, None).unwrap();
        let err = transition(db.connection(), IdentityRestored, None).unwrap_err();
        assert!(
            err.to_string().contains("root_keys_unwrapped") || err.to_string().contains("Illegal"),
            "got {err}"
        );
    }

    #[test]
    fn reset_clears_the_row() {
        let db = fresh_db();
        save(db.connection(), ManifestVerified, None).unwrap();
        reset(db.connection()).unwrap();
        assert!(load(db.connection()).unwrap().is_none());
    }

    #[test]
    fn snake_case_round_trip_via_display_and_fromstr() {
        for st in [
            IdentityRestored,
            RootKeysUnwrapped,
            ManifestVerified,
            SkeletonRestored,
            SearchRestored,
            RecentMessagesRestored,
            MediaLazyRestoreEnabled,
            FullRestoreComplete,
        ] {
            let s = st.to_string();
            let back: RestoreState = s.parse().unwrap();
            assert_eq!(back, st);
        }
    }
}
