// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound

//! Hand-rolled, allocation-frugal, bounds-checked DNS wire codec.
//!
//! This module replaces `hickory-proto`'s message parsing and serialization on
//! Runbound's own data path (serving, forwarding, AXFR, DDNS, local-zone
//! signing). It owns a single internal message representation shared by the
//! fast (XDP) and slow paths, so there is one codec to audit instead of two.
//!
//! Design goals, in priority order:
//! 1. **Safety** — no panics, no unbounded loops, no over-reads on any input.
//!    The decoder is the single bounds-checked choke point; name decompression
//!    is triple-bounded (see [`name`]).
//! 2. **Fidelity** — a forwarder must pass through record types it does not
//!    understand without mangling them (RFC 3597). Unknown types keep their
//!    number and opaque RDATA.
//! 3. **Speed** — small names live inline (no allocation), reads are
//!    inlined big-endian, and the hot loops are SIMD-friendly. Correctness is
//!    proven first (differential fuzzing against hickory as an oracle); the
//!    micro-optimization / ASM pass comes after, never before, the proofs.

// Phase 1 ships the codec ahead of its consumers: the constants and a few
// builder helpers are exercised by tests and the differential oracle but are
// not yet called from the serving path (phase 2). Until that wiring lands the
// binary-crate dead-code lint flags them; this allow is scoped to the codec
// module and is to be removed once phase 2 consumes the surface.
#![allow(dead_code)]

pub mod consts;
pub mod decoder;
pub mod edns;
pub mod encoder;
pub mod error;
pub mod header;
pub mod message;
pub mod name;
pub mod present;
pub mod question;
pub mod rdata;
pub mod record;

#[cfg(test)]
mod oracle;

// These re-exports are the module's public surface. The wider tree starts
// consuming them in phase 2 (serving path); until then the binary-crate dead
// -code lint flags them, so silence it here rather than scatter full paths.
#[allow(unused_imports)]
pub use self::{
    decoder::Decoder,
    edns::Edns,
    encoder::Encoder,
    error::{WireError, WireResult},
    header::Header,
    message::Message,
    name::Name,
    question::Question,
    rdata::Rdata,
    record::Record,
};
