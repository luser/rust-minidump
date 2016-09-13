// Copyright 2016 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

use std::env;
use std::ffi::OsStr;
use std::path::Path;
use std::io::Write;

extern crate breakpad_symbols;
extern crate minidump;

use breakpad_symbols::relative_symbol_path;
use minidump::*;

const USAGE : &'static str = "Usage: dumpmodules [-v|-d] <minidump>
Print full paths of modules from a minidump that were loaded in the crashed
process.

Options:
  -v  Also print debug IDs
  -d  Print relative paths to symbol files that would be loaded instead of
      module paths.";

#[derive(PartialEq)]
enum Verbose {
    Yes,
    No,
}

enum PrintMode {
    Modules,
    SymbolPaths,
}

fn print_minidump_modules<T: AsRef<Path>>(path: T,
                                          mode: PrintMode,
                                          verbose: Verbose) {
    match Minidump::read_path(path.as_ref()) {
        Ok(mut dump) => {
            if let Ok(module_list) = dump.get_stream::<MinidumpModuleList>() {
                for module in module_list.iter() {
                    match mode {
                        PrintMode::Modules => {
                            print!("{}", module.code_file());
                            if verbose == Verbose::Yes {
                                print!("\t");
                                if let Some(debug_id) = module.debug_identifier() {
                                    print!("{}", debug_id);
                                }
                            }
                            println!("");
                        }
                        PrintMode::SymbolPaths => {
                            if let Some(path) = relative_symbol_path(module, "sym") {
                                println!("{}", path);
                            }
                        }
                    }
                }
            }
        },
        Err(err) => {
            let mut stderr = std::io::stderr();
            writeln!(&mut stderr, "Error reading dump: {:?}", err).unwrap();
        }
    }
}

#[cfg_attr(test, allow(dead_code))]
fn main() {
    let mut verbose = Verbose::No;
    let mut mode = PrintMode::Modules;
    let mut stderr = std::io::stderr();
    for arg in env::args_os().skip(1) {
        if arg == OsStr::new("-v") {
            verbose = Verbose::Yes;
        } else if arg == OsStr::new("-d") {
            mode = PrintMode::SymbolPaths;
        } else if arg.to_str().map(|s| s.starts_with("-")).unwrap_or(false) {
            writeln!(&mut stderr, "Unknown argument {:?}", arg).unwrap();
            break;
        } else {
            return print_minidump_modules(arg, mode, verbose);
        }
    }
    writeln!(&mut stderr, "{}", USAGE).unwrap();
}