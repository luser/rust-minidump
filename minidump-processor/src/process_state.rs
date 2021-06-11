// Copyright 2015 Ted Mielczarek. See the COPYRIGHT
// file at the top-level directory of this distribution.

//! The state of a process.

use std::borrow::{Borrow, Cow};
use std::collections::HashSet;
use std::io;
use std::io::prelude::*;

use crate::exploitability::Exploitability;
use crate::system_info::SystemInfo;
use crate::FrameSymbolizer;
use chrono::prelude::*;
use minidump::system_info::Cpu;
use minidump::*;
use serde_json::json;

/// Indicates how well the instruction pointer derived during
/// stack walking is trusted. Since the stack walker can resort to
/// stack scanning, it can wind up with dubious frames.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum FrameTrust {
    /// Unknown
    None,
    /// Scanned the stack, found this.
    Scan,
    /// Found while scanning stack using call frame info.
    CfiScan,
    /// Derived from frame pointer.
    FramePointer,
    /// Derived from call frame info.
    CallFrameInfo,
    /// Explicitly provided by some external stack walker.
    PreWalked,
    /// Given as instruction pointer in a context.
    Context,
}

/// A single stack frame produced from unwinding a thread's stack.
#[derive(Debug)]
pub struct StackFrame {
    // The program counter location as an absolute virtual address.
    //
    // - For the innermost called frame in a stack, this will be an exact
    //   program counter or instruction pointer value.
    //
    // - For all other frames, this address is within the instruction that
    //   caused execution to branch to this frame's callee (although it may
    //   not point to the exact beginning of that instruction). This ensures
    //   that, when we look up the source code location for this frame, we
    //   get the source location of the call, not of the point at which
    //   control will resume when the call returns, which may be on the next
    //   line. (If the compiler knows the callee never returns, it may even
    //   place the call instruction at the very end of the caller's machine
    //   code, such that the "return address" (which will never be used)
    //   immediately after the call instruction is in an entirely different
    //   function, perhaps even from a different source file.)
    //
    // On some architectures, the return address as saved on the stack or in
    // a register is fine for looking up the point of the call. On others, it
    // requires adjustment. ReturnAddress returns the address as saved by the
    // machine.
    pub instruction: u64,

    // The module in which the instruction resides.
    pub module: Option<MinidumpModule>,

    /// The function name, may be omitted if debug symbols are not available.
    pub function_name: Option<String>,

    /// The start address of the function, may be omitted if debug symbols
    /// are not available.
    pub function_base: Option<u64>,

    /// The size, in bytes, of the arguments pushed on the stack for this function.
    /// WIN STACK unwinding needs this value to work; it's otherwise uninteresting.
    pub parameter_size: Option<u32>,

    /// The source file name, may be omitted if debug symbols are not available.
    pub source_file_name: Option<String>,

    /// The (1-based) source line number, may be omitted if debug symbols are
    /// not available.
    pub source_line: Option<u32>,

    /// The start address of the source line, may be omitted if debug symbols
    /// are not available.
    pub source_line_base: Option<u64>,

    /// Amount of trust the stack walker has in the instruction pointer
    /// of this frame.
    pub trust: FrameTrust,

    /// The CPU context containing register state for this frame.
    pub context: MinidumpContext,
}

/// Information about the results of unwinding a thread's stack.
#[derive(Debug, PartialEq)]
pub enum CallStackInfo {
    /// Everything went great.
    Ok,
    /// No `MinidumpContext` was provided, couldn't do anything.
    MissingContext,
    /// No stack memory was provided, couldn't unwind past the top frame.
    MissingMemory,
    /// The CPU type is unsupported.
    UnsupportedCpu,
    /// This thread wrote the minidump, it was skipped.
    DumpThreadSkipped,
}

/// A stack of `StackFrame`s produced as a result of unwinding a thread.
pub struct CallStack {
    /// The stack frames.
    /// By convention, the stack frame at index 0 is the innermost callee frame,
    /// and the frame at the highest index in a call stack is the outermost
    /// caller.
    pub frames: Vec<StackFrame>,
    /// Information about this `CallStack`.
    pub info: CallStackInfo,
    /// The name of the thread, if known.
    pub thread_name: Option<String>,
}

/// The state of a process as recorded by a `Minidump`.
pub struct ProcessState {
    /// The PID of the process.
    pub process_id: Option<u32>,
    /// When the minidump was written.
    pub time: DateTime<Utc>,
    /// When the process started, if available
    pub process_create_time: Option<DateTime<Utc>>,
    /// If the process crashed, a `CrashReason` describing the crash reason.
    pub crash_reason: Option<CrashReason>,
    /// If the process crashed, the raw exception code.
    pub exception_code: Option<u32>,
    /// The memory address implicated in the crash.
    ///
    /// If the process crashed, and if the crash reason implicates memory,
    /// this is the memory address that caused the crash. For data access
    /// errors this will be the data address that caused the fault. For code
    /// errors, this will be the address of the instruction that caused the
    /// fault.
    pub crash_address: Option<u64>,
    /// A string describing an assertion that was hit, if present.
    pub assertion: Option<String>,
    /// The index of the thread that requested a dump be written.
    /// If a dump was produced as a result of a crash, this
    /// will point to the thread that crashed.  If the dump was produced as
    /// by user code without crashing, and the dump contains extended Breakpad
    /// information, this will point to the thread that requested the dump.
    /// If the dump was not produced as a result of an exception and no
    /// extended Breakpad information is present, this field will be
    /// `None`.
    pub requesting_thread: Option<usize>,
    /// Stacks for each thread (except possibly the exception handler
    /// thread) at the time of the crash.
    pub threads: Vec<CallStack>,
    // TODO:
    // thread_memory_regions
    /// Information about the system on which the minidump was written.
    pub system_info: SystemInfo,
    /// Linux Standard Base Info
    pub linux_standard_base: Option<MinidumpLinuxLsbRelease>,
    pub mac_crash_info: Option<Vec<RawMacCrashInfo>>,
    /// The modules that were loaded into the process represented by the
    /// `ProcessState`.
    pub modules: MinidumpModuleList,
    pub unloaded_modules: MinidumpUnloadedModuleList,
    // modules_without_symbols
    // modules_with_corrupt_symbols
    pub exploitability: Option<Exploitability>,
    pub unknown_streams: Vec<MinidumpUnknownStream>,
    pub unimplemented_streams: Vec<MinidumpUnimplementedStream>,
}

impl FrameTrust {
    /// Return a string describing how a stack frame was found
    /// by the stackwalker.
    pub fn description(&self) -> &'static str {
        match *self {
            FrameTrust::Context => "given as instruction pointer in context",
            FrameTrust::PreWalked => "recovered by external stack walker",
            FrameTrust::CallFrameInfo => "call frame info",
            FrameTrust::CfiScan => "call frame info with scanning",
            FrameTrust::FramePointer => "previous frame's frame pointer",
            FrameTrust::Scan => "stack scanning",
            FrameTrust::None => "unknown",
        }
    }

    fn json_name(&self) -> &'static str {
        match *self {
            FrameTrust::Context => "context",
            FrameTrust::PreWalked => "prewalked",
            FrameTrust::CallFrameInfo => "cfi",
            FrameTrust::CfiScan => "cfi_scan",
            FrameTrust::FramePointer => "frame_pointer",
            FrameTrust::Scan => "scan",
            FrameTrust::None => "non",
        }
    }
}

impl StackFrame {
    /// Create a `StackFrame` from a `MinidumpContext`.
    pub fn from_context(context: MinidumpContext, trust: FrameTrust) -> StackFrame {
        StackFrame {
            instruction: context.get_instruction_pointer(),
            module: None,
            function_name: None,
            function_base: None,
            parameter_size: None,
            source_file_name: None,
            source_line: None,
            source_line_base: None,
            trust,
            context,
        }
    }

    /// Return the actual return address, as saved on the stack or in a
    /// register. See the comments for `StackFrame::instruction` for details.
    pub fn return_address(&self) -> u64 {
        self.instruction
    }
}

impl FrameSymbolizer for StackFrame {
    fn get_instruction(&self) -> u64 {
        self.instruction
    }
    fn set_function(&mut self, name: &str, base: u64, parameter_size: u32) {
        self.function_name = Some(String::from(name));
        self.function_base = Some(base);
        self.parameter_size = Some(parameter_size);
    }
    fn set_source_file(&mut self, file: &str, line: u32, base: u64) {
        self.source_file_name = Some(String::from(file));
        self.source_line = Some(line);
        self.source_line_base = Some(base);
    }
}

fn basename(f: &str) -> &str {
    match f.rfind(|c| c == '/' || c == '\\') {
        None => f,
        Some(index) => &f[(index + 1)..],
    }
}

fn print_registers<T: Write>(f: &mut T, ctx: &MinidumpContext) -> io::Result<()> {
    let registers: Cow<HashSet<&str>> = match ctx.valid {
        MinidumpContextValidity::All => {
            let gpr = ctx.general_purpose_registers();
            let set: HashSet<&str> = gpr.iter().cloned().collect();
            Cow::Owned(set)
        }
        MinidumpContextValidity::Some(ref which) => Cow::Borrowed(which),
    };

    // Iterate over registers in a known order.
    let mut output = String::new();
    for reg in ctx.general_purpose_registers() {
        if registers.contains(reg) {
            let reg_val = ctx.format_register(reg);
            let next = format!(" {: >5} = {}", reg, reg_val);
            if output.chars().count() + next.chars().count() > 80 {
                // Flush the buffer.
                writeln!(f, " {}", output)?;
                output.truncate(0);
            }
            output.push_str(&next);
        }
    }
    if !output.is_empty() {
        writeln!(f, " {}", output)?;
    }
    Ok(())
}

fn json_registers(ctx: &MinidumpContext) -> serde_json::Value {
    let registers: Cow<HashSet<&str>> = match ctx.valid {
        MinidumpContextValidity::All => {
            let gpr = ctx.general_purpose_registers();
            let set: HashSet<&str> = gpr.iter().cloned().collect();
            Cow::Owned(set)
        }
        MinidumpContextValidity::Some(ref which) => Cow::Borrowed(which),
    };

    let mut output = serde_json::Map::new();
    for &reg in ctx.general_purpose_registers() {
        if registers.contains(reg) {
            let reg_val = ctx.format_register(reg);
            output.insert(String::from(reg), json!(reg_val));
        }
    }
    json!(output)
}

impl CallStack {
    /// Create a `CallStack` with `info` and no frames.
    pub fn with_info(info: CallStackInfo) -> CallStack {
        CallStack {
            info,
            frames: vec![],
            thread_name: None,
        }
    }

    /// Write a human-readable description of the call stack to `f`.
    ///
    /// This is very verbose, it implements the output format used by
    /// minidump_stackwalk.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        if self.frames.is_empty() {
            writeln!(f, "<no frames>")?;
        }
        for (i, frame) in self.frames.iter().enumerate() {
            let addr = frame.instruction;
            write!(f, "{:2}  ", i)?;
            if let Some(ref module) = frame.module {
                write!(f, "{}", basename(&module.code_file()))?;
                if let (&Some(ref function), &Some(ref function_base)) =
                    (&frame.function_name, &frame.function_base)
                {
                    write!(f, "!{}", function)?;
                    if let (
                        &Some(ref source_file),
                        &Some(ref source_line),
                        &Some(ref source_line_base),
                    ) = (
                        &frame.source_file_name,
                        &frame.source_line,
                        &frame.source_line_base,
                    ) {
                        write!(
                            f,
                            " [{} : {} + {:#x}]",
                            basename(&source_file),
                            source_line,
                            addr - source_line_base
                        )?;
                    } else {
                        write!(f, " + {:#x}", addr - function_base)?;
                    }
                } else {
                    write!(f, " + {:#x}", addr - module.base_address())?;
                }
            } else {
                writeln!(f, "{:#x}", addr)?;
            }
            writeln!(f)?;
            print_registers(f, &frame.context)?;
            writeln!(f, "    Found by: {}", frame.trust.description())?;
        }
        Ok(())
    }
}

fn eq_some<T: PartialEq>(opt: Option<T>, val: T) -> bool {
    match opt {
        Some(v) => v == val,
        None => false,
    }
}

impl ProcessState {
    /// `true` if the minidump was written in response to a process crash.
    pub fn crashed(&self) -> bool {
        self.crash_reason.is_some() && self.crash_address.is_some()
    }
    /// Write a human-readable description of the process state to `f`.
    ///
    /// This is very verbose, it implements the output format used by
    /// minidump_stackwalk.
    pub fn print<T: Write>(&self, f: &mut T) -> io::Result<()> {
        writeln!(f, "Operating system: {}", self.system_info.os.long_name())?;
        if let Some(ref ver) = self.system_info.os_version {
            writeln!(f, "                  {}", ver)?;
        }
        writeln!(f, "CPU: {}", self.system_info.cpu)?;
        if let Some(ref info) = self.system_info.cpu_info {
            writeln!(f, "     {}", info)?;
        }
        writeln!(
            f,
            "     {} CPU{}",
            self.system_info.cpu_count,
            if self.system_info.cpu_count > 1 {
                "s"
            } else {
                ""
            }
        )?;
        if let Some(ref lsb) = self.linux_standard_base {
            writeln!(
                f,
                "Linux {} {} - {} ({})",
                lsb.id, lsb.release, lsb.codename, lsb.description
            )?;
        }
        writeln!(f)?;

        if let (&Some(ref reason), &Some(ref address)) = (&self.crash_reason, &self.crash_address) {
            write!(
                f,
                "Crash reason:  {}
Crash address: {:#x}
",
                reason, address
            )?;
        } else {
            writeln!(f, "No crash")?;
        }
        if let Some(ref assertion) = self.assertion {
            writeln!(f, "Assertion: {}", assertion)?;
        }
        if let Some(ref info) = self.mac_crash_info {
            writeln!(f, "Mac Crash Info:")?;
            for (idx, record) in info.iter().enumerate() {
                writeln!(f, "  Record {}", idx)?;
                if let Some(val) = record.thread() {
                    writeln!(f, "    thread: 0x{}", val)?;
                }
                if let Some(val) = record.dialog_mode() {
                    writeln!(f, "    dialog mode: 0x{}", val)?;
                }
                if let Some(val) = record.abort_cause() {
                    writeln!(f, "    abort_cause: 0x{}", val)?;
                }

                if let Some(val) = record.module_path() {
                    writeln!(f, "    module: {}", val)?;
                }
                if let Some(val) = record.message() {
                    writeln!(f, "    message: {}", val)?;
                }
                if let Some(val) = record.signature_string() {
                    writeln!(f, "    signature string: {}", val)?;
                }
                if let Some(val) = record.backtrace() {
                    writeln!(f, "    backtrace: {}", val)?;
                }
                if let Some(val) = record.message2() {
                    writeln!(f, "    message2: {}", val)?;
                }
            }
            writeln!(f)?;
        }
        if let Some(ref exploitability) = self.exploitability {
            writeln!(f, "Estimated exploitability: {}", exploitability.to_str())?;
        }
        if let Some(ref time) = self.process_create_time {
            let uptime = self.time - *time;
            writeln!(f, "Process uptime: {} seconds", uptime.num_seconds())?;
        } else {
            writeln!(f, "Process uptime: not available")?;
        }
        writeln!(f)?;

        if let Some(requesting_thread) = self.requesting_thread {
            let stack = &self.threads[requesting_thread];
            writeln!(
                f,
                "Thread {} {} ({})",
                requesting_thread,
                stack.thread_name.as_deref().unwrap_or(""),
                if self.crashed() {
                    "crashed"
                } else {
                    "requested dump, did not crash"
                }
            )?;
            stack.print(f)?;
            writeln!(f)?;
        }
        for (i, stack) in self.threads.iter().enumerate() {
            if eq_some(self.requesting_thread, i) {
                // Don't print the requesting thread again,
                continue;
            }
            if stack.info == CallStackInfo::DumpThreadSkipped {
                continue;
            }
            writeln!(
                f,
                "Thread {} {}",
                i,
                stack.thread_name.as_deref().unwrap_or("")
            )?;
            stack.print(f)?;
        }
        write!(
            f,
            "
Loaded modules:
"
        )?;
        let main_address = self.modules.main_module().map(|m| m.base_address());
        for module in self.modules.by_addr() {
            // TODO: missing symbols, corrupt symbols
            write!(
                f,
                "{:#010x} - {:#010x}  {}  {}",
                module.base_address(),
                module.base_address() + module.size() - 1,
                basename(&module.code_file()),
                module.version().unwrap_or(Cow::Borrowed("???"))
            )?;
            if eq_some(main_address, module.base_address()) {
                write!(f, "  (main)")?;
            }
            writeln!(f)?;
        }
        write!(
            f,
            "
Unloaded modules:
"
        )?;
        for module in self.unloaded_modules.by_addr() {
            writeln!(
                f,
                "{:#010x} - {:#010x}  {}",
                module.base_address(),
                module.base_address() + module.size() - 1,
                basename(&module.code_file()),
            )?;
        }
        if !self.unimplemented_streams.is_empty() {
            write!(
                f,
                "
Unimplemented streams encountered:
"
            )?;
            for stream in &self.unimplemented_streams {
                writeln!(
                    f,
                    "Stream 0x{:08x} {:?} ({}) @ 0x{:08x}",
                    stream.stream_type as u32,
                    stream.stream_type,
                    stream.vendor,
                    stream.location.rva,
                )?;
            }
        }
        if !self.unknown_streams.is_empty() {
            write!(
                f,
                "
Unknown streams encountered:
"
            )?;
            for stream in &self.unknown_streams {
                writeln!(
                    f,
                    "Stream 0x{:08x} ({}) @ 0x{:08x}",
                    stream.stream_type, stream.vendor, stream.location.rva,
                )?;
            }
        }
        Ok(())
    }

    /// Outputs json in a schema compatible with mozilla's Socorro crash reporting servers.
    pub fn print_json<T: Write>(&self, f: &mut T, pretty: bool) -> Result<(), serde_json::Error> {
        let sys = &self.system_info;

        // Curry self for use in `map`
        let json_hex = |val: u64| -> String { self.json_hex(val) };

        let mut output = json!({
            // TODO: I guess we should still produce some JSON in some failure modes?
            // OK | ERROR_* | SYMBOL_SUPPLIER_INTERRUPTED
            "status": "OK",
            "system_info": {
                // Linux | Windows NT | Mac OS X
                "os": sys.os.long_name(),
                "os_ver": sys.os_version,
                // x86 | amd64 | arm | ppc | sparc
                "cpu_arch": sys.cpu.to_string(),
                "cpu_info": sys.cpu_info,
                "cpu_count": sys.cpu_count,
                // TODO: Issue #19
                // optional
                "cpu_microcode_version": null,
            },
            "crash_info": {
                // TODO: Issue #22
                "type": self.crash_reason.map(|reason| reason.to_string()),
                "address": self.crash_address.map(json_hex),
                // thread index | null
                "crashing_thread": self.requesting_thread,
                "assertion": self.assertion,
            },
            // optional
            "lsb_release": self.linux_standard_base.as_ref().map(|lsb| json!({
                "id": lsb.id,
                "release": lsb.release,
                "codename": lsb.codename,
                "description": lsb.description,
            })),
            // optional
            "mac_crash_info": self.mac_crash_info.as_ref().map(|info| json!({
                "num_records": info.len(),
                // All of these fields are optional
                "records": info.iter().map(|record| json!({
                    "thread": record.thread().copied().map(json_hex),
                    "dialog_mode": record.dialog_mode().copied().map(json_hex),
                    "abort_cause": record.abort_cause().copied().map(json_hex),

                    "module": record.module_path(),
                    "message": record.message(),
                    "signature_string": record.signature_string(),
                    "backtrace": record.backtrace(),
                    "message2": record.message2(),
                })).collect::<Vec<_>>()
            })),

            // the first module is always the main one
            "main_module": 0,
            // TODO: Issue #171
            "modules_contains_cert_info": false,
            "modules": self.modules.iter().map(|module| json!({
                "base_addr": json_hex(module.raw.base_of_image),
                // filename | empty string
                "debug_file": basename(module.debug_file().unwrap_or(Cow::Borrowed("")).borrow()),
                // [[:xdigit:]]{33} | empty string
                "debug_id": module.debug_identifier().unwrap_or(Cow::Borrowed("")),
                "end_addr": json_hex(module.raw.base_of_image + module.raw.size_of_image as u64),
                "filename": module.name,
                "code_id": module.code_identifier(),
                "version": module.version(),

                // These are all just metrics for debugging minidump-processor's execution

                // optional, if mdsw looked for the file and it does exist
                // "loaded_symbols": true,
                // optional, if mdsw looked for the file and it doesn't exist
                // "missing_symbols": true,
                // optional, if mdsw found a file that has parse errors
                // "corrupt_symbols": true,
                // optional, whether or not the SYM file was fetched from disk cache
                // "symbol_disk_cache_hit": <bool>,
                // optional, time in ms it took to fetch symbol file from url; omitted
                // if the symbol file was in disk cache
                // "symbols_fetch_time": <float>,
                // optional, url of symbol file
                // "symbol_url": <string>

                // TODO: Issue #171
                // optional
                // "cert_subject": <string>

            })).collect::<Vec<_>>(),
            "pid": self.process_id,
            "thread_count": self.threads.len(),
            "threads": self.threads.iter().map(|thread| json!({
                "frame_count": thread.frames.len(),
                // TODO: I think this is legacy gunk that we don't ever do?
                "frames_truncated": false,
                // optional, if truncated, this is the original total
                "total_frames": thread.frames.len(),
                // TODO: Issue #156
                // optional
                "last_error_value": null,
                // optional
                "thread_name": thread.thread_name,
                "frames": thread.frames.iter().enumerate().map(|(idx, frame)| json!({
                    "frame": idx,
                    // optional
                    "module": frame.module.as_ref().map(|module| basename(&module.name)),
                    // optional
                    "function": frame.function_name,
                    // optional
                    "file": frame.source_file_name,
                    // optional
                    "line": frame.source_line,
                    "offset": json_hex(frame.instruction),
                    // optional
                    "module_offset": frame
                        .module
                        .as_ref()
                        .map(|module| frame.instruction - module.raw.base_of_image)
                        .map(json_hex),
                    // optional
                    "function_offset": frame
                        .function_base
                        .map(|func_base| frame.instruction - func_base)
                        .map(json_hex),
                    "missing_symbols": frame.function_name.is_none(),
                    // none | scan | cfi_scan | frame_pointer | cfi | context | prewalked
                    "trust": frame.trust.json_name(),
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),

            // TODO: Issue #169
            // "largest_free_vm_block": 0x000000
            // "tiny_block_size": <int>,
            // "write_combine_size": <int>,

            "unloaded_modules": self.unloaded_modules.iter().map(|module| json!({
                "base_addr": json_hex(module.raw.base_of_image),
                "code_id": module.code_identifier(),
                "end_addr": json_hex(module.raw.base_of_image + module.raw.size_of_image as u64),
                "filename": module.name,
            })).collect::<Vec<_>>(),

            "sensitive": {
                // TODO: Issue #25
                // low | medium | high | interesting | none | ERROR: *
                "exploitability": self.exploitability.as_ref().map(|e| e.to_str()),
            }
        });

        if let Some(requesting_thread) = self.requesting_thread {
            // Copy the crashing thread into a top-level "crashing_thread" field and:
            // * Add a "thread_index" field to indicate which thread it was
            // * Add a "registers" field to its first frame
            //
            // Note that we currently make crashing_thread a strict superset
            // of a normal "threads" entry, while the original schema strips
            // many of the fields here. We don't to keep things more uniform.

            let registers = json_registers(&self.threads[requesting_thread].frames[0].context);

            // Yuck, spidering through json...
            let mut thread =
                output.get_mut("threads").unwrap().as_array().unwrap()[requesting_thread].clone();
            let thread_obj = thread.as_object_mut().unwrap();
            let frames = thread_obj
                .get_mut("frames")
                .unwrap()
                .as_array_mut()
                .unwrap();
            let frame = frames[0].as_object_mut().unwrap();

            frame.insert(String::from("registers"), registers);
            thread_obj.insert(String::from("thread_index"), json!(requesting_thread));

            output
                .as_object_mut()
                .unwrap()
                .insert(String::from("crashing_thread"), thread);
        }

        if pretty {
            serde_json::to_writer_pretty(f, &output)
        } else {
            serde_json::to_writer(f, &output)
        }
    }

    // Convert an integer to a hex string, with leading 0's for uniform width.
    fn json_hex(&self, val: u64) -> String {
        match self.system_info.cpu {
            Cpu::X86 | Cpu::Ppc | Cpu::Sparc | Cpu::Arm => {
                format!("0x{:08x}", val)
            }
            Cpu::X86_64 | Cpu::Ppc64 | Cpu::Arm64 | Cpu::Unknown(_) => {
                format!("0x{:016x}", val)
            }
        }
    }
}
