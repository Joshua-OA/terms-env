//! Library surface of the terms-env CLI. Exists so integration tests can
//! exercise internal components (e.g. UI state machines) without spawning
//! processes; all real behavior still flows through `main.rs`.
pub mod ui;
