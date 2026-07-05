//! Shared process-environment lock for tests.
//!
//! Rust 2024 makes environment mutation unsafe because the process environment is global and may
//! be read by other threads or foreign code. Tests that mutate env must hold this crate-wide lock
//! for the entire period where the value matters, including awaits and spawned background work.

#![cfg(test)]

use std::{
    ffi::OsString,
    marker::PhantomData,
    sync::{Mutex, MutexGuard},
};

static ENV_LOCK: Mutex<()> = Mutex::new(());

pub fn lock() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap()
}

pub struct EnvScope<'a> {
    saved: Vec<(&'static str, Option<OsString>)>,
    _lock: PhantomData<&'a MutexGuard<'static, ()>>,
}

impl<'a> EnvScope<'a> {
    pub fn save(_lock: &'a MutexGuard<'static, ()>, keys: &[&'static str]) -> Self {
        let saved: Vec<_> = keys
            .iter()
            .map(|key| (*key, std::env::var_os(key)))
            .collect();
        // SAFETY: the borrowed guard proves the shared test env lock is held.
        unsafe {
            for key in keys {
                std::env::remove_var(key);
            }
        }
        Self {
            saved,
            _lock: PhantomData,
        }
    }
}

impl Drop for EnvScope<'_> {
    fn drop(&mut self) {
        for (key, value) in &self.saved {
            match value {
                // SAFETY: the lifetime tied to the borrowed guard ensures the shared test env lock
                // is still held while this guard is dropped.
                Some(value) => unsafe { std::env::set_var(key, value) },
                // SAFETY: as above — the borrowed guard proves the shared test env lock is held.
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }
}

pub struct EnvVarGuard<'a> {
    key: &'static str,
    old: Option<OsString>,
    _lock: PhantomData<&'a MutexGuard<'static, ()>>,
}

impl<'a> EnvVarGuard<'a> {
    pub fn set(
        _lock: &'a MutexGuard<'static, ()>,
        key: &'static str,
        value: impl Into<OsString>,
    ) -> Self {
        let old = std::env::var_os(key);
        // SAFETY: the borrowed guard proves the shared test env lock is held.
        unsafe { std::env::set_var(key, value.into()) };
        Self {
            key,
            old,
            _lock: PhantomData,
        }
    }

    pub fn unset(_lock: &'a MutexGuard<'static, ()>, key: &'static str) -> Self {
        let old = std::env::var_os(key);
        // SAFETY: the borrowed guard proves the shared test env lock is held.
        unsafe { std::env::remove_var(key) };
        Self {
            key,
            old,
            _lock: PhantomData,
        }
    }
}

impl Drop for EnvVarGuard<'_> {
    fn drop(&mut self) {
        match &self.old {
            // SAFETY: the lifetime tied to the borrowed guard ensures the shared test env lock is
            // still held while this guard is dropped.
            Some(value) => unsafe { std::env::set_var(self.key, value) },
            // SAFETY: as above — the borrowed guard proves the shared test env lock is held.
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}
