//! wormhole: a live connection between coding-agent sessions on different machines that
//! share one repository. See docs/design.md.

pub mod daemon;
pub mod delegation;
pub mod glob;
pub mod hookcmd;
pub mod hub;
pub mod install;
pub mod local;
pub mod mcp;
pub mod proto;
pub mod repo;
pub mod text;
pub mod tls;
