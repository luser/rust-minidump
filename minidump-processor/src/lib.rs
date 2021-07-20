//! A library for producing stack traces and other useful information from minidump files.
//!
//! You can use the [minidump](https://crates.io/minidump) crate to parse a minidump file, and then
//! use the [`process_minidump`] function to produce stack traces. If you provide paths to
//! Breakpad-format .sym files, the stack traces will include function and source line information.
//!
//! [`process_minidump`]: fn.process_minidump.html

mod dwarf_symbolizer;
mod exploitability;
mod process_state;
mod processor;
mod stackwalker;
mod symbols;
mod system_info;

pub use crate::dwarf_symbolizer::DwarfSymbolizer;
pub use crate::process_state::*;
pub use crate::processor::*;
pub use crate::stackwalker::*;
pub use crate::symbols::*;
pub use crate::system_info::*;
