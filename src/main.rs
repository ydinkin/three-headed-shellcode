use std::env;
use std::fs::File;
use std::io::Read;
use std::num::Wrapping;
use rand::random;
use unicorn::{Error, Cpu, CpuX86, CpuARM, CpuMIPS};

const MAX_EMU_TIME_MS : u64 = 60 * 1000;
 
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("usage: {} <file>", args[0]);
        return;
    }

    let mut file = File::open(&args[1]).expect("file could not be opened");
    let size = file.metadata().expect("file metadata unavailable").len() as usize;
    println!("opened `{}` ({} bytes)", args[1], size);

    let mut shellcode = vec![0; size];
    file.read_exact(&mut shellcode).expect("file could not be opened"); 
    
    let mut points = 0;
    
    for i in 0..100 {
        let (a, b) = (random::<i32>(), random::<i32>());
        println!("round {}: A={}, B={}", i, a, b);
        println!("------------");
        for emulate in &[emulate_x86, emulate_arm, emulate_mips] {
            let (sum, mul) = emulate(&shellcode, a, b).expect("emulation failed");
            let sum_correct = sum == (Wrapping(a) + Wrapping(b)).0;
            println!("{} + {} {} {}", a, b, if sum_correct { "==" } else { "!=" }, sum);
            let mul_correct = mul == (Wrapping(a) * Wrapping(b)).0;
            println!("{} * {} {} {}", a, b, if mul_correct { "==" } else { "!=" }, mul);
            if sum_correct && mul_correct {
                points += 1;
                println!("points: {}", points);
            }
            println!("------------");
        }
    }

    println!("total points: {}", points);
}

fn emulate_x86(shellcode: &[u8], a: i32, b: i32) -> Result<(i32, i32), Error> {
    let emu = CpuX86::new(unicorn::Mode::MODE_32)?;
    println!("starting x86 emulation");

    let memsize = shellcode.len();
    let memsize = if memsize % 0x1000 == 0 { memsize } else { memsize + (0x1000 - memsize % 0x1000) };
    
    emu.mem_map(0, memsize, unicorn::Protection::ALL)?;
    emu.mem_write(0, &shellcode)?;
    emu.reg_write_i32(unicorn::RegisterX86::EAX, a)?;
    emu.reg_write_i32(unicorn::RegisterX86::EBX, b)?;

    match emu.emu_start(0, shellcode.len() as u64, MAX_EMU_TIME_MS, 0) {
        Ok(()) => println!("emulation success"),
        Err(e) => println!("emulation error: {}", e),
    }

    let eip = emu.reg_read_i32(unicorn::RegisterX86::EIP).expect("failed to get EIP");
    let eax = emu.reg_read_i32(unicorn::RegisterX86::EAX).expect("failed to get EAX");
    let ebx = emu.reg_read_i32(unicorn::RegisterX86::EBX).expect("failed to get EBX");
    println!("end of emulation state: EIP=0x{:X}, EAX=0x{:X}, EBX=0x{:X}", eip, eax, ebx);

    Ok((eax, ebx))
}

fn emulate_arm(shellcode: &[u8], a: i32, b: i32) -> Result<(i32, i32), Error> {
    let emu = CpuARM::new(unicorn::Mode::LITTLE_ENDIAN)?;
    println!("starting ARM emulation");

    let memsize = shellcode.len();
    let memsize = if memsize % 0x1000 == 0 { memsize } else { memsize + (0x1000 - memsize % 0x1000) };
    
    emu.mem_map(0, memsize, unicorn::Protection::ALL)?;
    emu.mem_write(0, &shellcode)?;
    emu.reg_write_i32(unicorn::RegisterARM::R0, a)?;
    emu.reg_write_i32(unicorn::RegisterARM::R1, b)?;

    match emu.emu_start(0, shellcode.len() as u64, MAX_EMU_TIME_MS, 0) {
        Ok(()) => println!("emulation success"),
        Err(e) => println!("emulation error: {}", e),
    }

    let pc = emu.reg_read_i32(unicorn::RegisterARM::PC).expect("failed to get PC");
    let r0 = emu.reg_read_i32(unicorn::RegisterARM::R0).expect("failed to get R0");
    let r1 = emu.reg_read_i32(unicorn::RegisterARM::R1).expect("failed to get R1");
    println!("end of emulation state: PC=0x{:X}, R0=0x{:X}, R1=0x{:X}", pc, r0, r1);

    Ok((r0, r1))
}

fn emulate_mips(shellcode: &[u8], a: i32, b: i32) -> Result<(i32, i32), Error> {
    let emu = CpuMIPS::new(unicorn::Mode::MODE_32)?;
    println!("starting MIPS emulation");

    let memsize = shellcode.len();
    let memsize = if memsize % 0x1000 == 0 { memsize } else { memsize + (0x1000 - memsize % 0x1000) };
    
    emu.mem_map(0, memsize, unicorn::Protection::ALL)?;
    emu.mem_write(0, &shellcode)?;
    emu.reg_write_i32(unicorn::RegisterMIPS::A0, a)?;
    emu.reg_write_i32(unicorn::RegisterMIPS::A1, b)?;

    match emu.emu_start(0, shellcode.len() as u64, MAX_EMU_TIME_MS, 0) {
        Ok(()) => println!("emulation success"),
        Err(e) => println!("emulation error: {}", e),
    }

    let pc = emu.reg_read_i32(unicorn::RegisterMIPS::PC).expect("failed to get PC");
    let a0 = emu.reg_read_i32(unicorn::RegisterMIPS::A0).expect("failed to get A0");
    let a1 = emu.reg_read_i32(unicorn::RegisterMIPS::A1).expect("failed to get A1");
    println!("end of emulation state: PC=0x{:X}, A0=0x{:X}, A1=0x{:X}", pc, a0, a1);

    Ok((a0, a1))
}
