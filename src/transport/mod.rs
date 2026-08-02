//! Transports.
//!
//! The `Transport` trait — the single abstraction of the project, per
//! `aidd_docs/INSTALL.md` — is deliberately *not* declared yet. It gets written
//! when the second implementation (`transport::direct`, v2) exists to justify
//! it. At this milestone there is one concrete transport and nothing to
//! abstract over.

pub mod direct;
pub mod tor;
