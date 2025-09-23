// Simple user mode QEMU emulation example
use libafl_qemu::{config, config::QemuConfig, Emulator, Regs, QemuExitReason, QemuExitError, QemuShutdownCause};
use std::{path::PathBuf};
use log::info;
use clap::Parser;
use libafl_bolts::tuples::tuple_list;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to the binary file
    #[clap(short, long, value_parser)]
    firmware: PathBuf,

    /// Entry point address (hex, default: 0x0)
    #[clap(short, long, value_parser = parse_hex, default_value_t = 0x0)]
    entry: u64,

    /// QEMU architecture (mips, mipsel, arm, armeb, armel, x86_64, i386)
    #[clap(short, long, default_value_t = String::from("x86_64"))]
    arch: String,
    
    /// Enable QEMU debug flags (e.g., in_asm)
    #[clap(long)]
    debug: Option<String>,
    
    /// Firmware load address (hex, default: 0x40205000)
    #[clap(long, value_parser = parse_hex, default_value_t = 0x40205000)]
    load_addr: u64,
}

fn parse_hex(s: &str) -> Result<u64, std::num::ParseIntError> {
    u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    println!("Debug: Logging initialized, should see INFO messages now");
    
    // 配置env_logger以显示INFO级别的日志
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // 验证架构是否支持
    match args.arch.as_str() {
        "arm" | "armel" => {},
        _ => panic!("Unsupported architecture for system mode: {}", args.arch),
    }

    info!("Creating QEMU SYSTEM MODE emulator for architecture: {}", args.arch);
    info!("Binary path: {:?}", args.firmware);
    info!("Firmware load address: 0x{:x}", args.load_addr);
    info!("Entry point: 0x{:x}", args.entry);

    // 创建QEMU配置
    let mut raw_options = String::new();
    
    // 添加debug参数
    if let Some(debug_flags) = &args.debug {
        raw_options.push_str(&format!("-d {} ", debug_flags));
    }
    
    // 添加额外参数以禁用默认存储设备和音频设备
    raw_options.push_str("-nographic -no-reboot -nodefaults -audio none ");
    
    // 配置内存大小为512MB
    raw_options.push_str("-m 512 ");
    
    // 添加device loader参数来指定固件加载地址
    raw_options.push_str(&format!(
        "-device loader,file={},addr=0x{:x},force-raw=on,cpu-num=0 ",
        args.firmware.to_str().unwrap(), args.load_addr
    ));
    
    // 使用不同的机器类型，可能不会默认包含需要介质的存储设备
    let qemu_config = QemuConfig::builder()
        .machine("vexpress-a9")  // 尝试使用vexpress-a9
        .cpu("cortex-a9")        // 使用对应的CPU类型
        .monitor(config::Monitor::Null)
        // 不使用kernel参数，而是通过raw_options中的device loader指定加载地址
        .serial(config::Serial::Null)  // 使用Null串行端口
        .no_graphic(true)
        .snapshot(true)
        .start_cpu(false)
        .raw_options(raw_options)
        .build();

    // 创建没有特殊模块的Emulator
    let emulator = Emulator::<u32, _, _, _, (), (), _>::empty()
        .qemu_parameters(qemu_config)
        .modules(tuple_list!())
        .build()?;

    let qemu = emulator.qemu();

    info!("QEMU system mode emulator initialized successfully for architecture: {}", args.arch);
    info!("Binary loaded: {:?}", args.firmware);
    
    // 获取第一个CPU (在访问寄存器前必须有CPU上下文)
    if let Some(cpu) = qemu.cpu_from_index(0) {
        info!("Got CPU with index 0");
        
        // 如果指定了入口点，则设置
        if args.entry != 0 {
            info!("Setting entry point to 0x{:x}", args.entry);
            // 对于ARM架构，GuestReg是u32类型，需要显式转换
            match args.entry.try_into() {
                Ok(entry_u32) => {
                    match cpu.write_reg::<Regs, u32>(Regs::Pc, entry_u32) {
                        Ok(_) => info!("Entry point set successfully"),
                        Err(e) => info!("Failed to set entry point: {:?}", e),
                    }
                },
                Err(e) => info!("Failed to convert entry point to u32: {:?}", e),
            }
        } else {
            // 如果没有指定入口点，则设置为加载地址
            let load_addr_u32: u32 = match args.load_addr.try_into() {
                Ok(addr) => addr,
                Err(e) => {
                    info!("Failed to convert load address to u32: {:?}", e);
                    return Err(Box::new(e));
                }
            };
            
            info!("Setting PC to load address: 0x{:x}", load_addr_u32);
            if let Err(e) = cpu.write_reg::<Regs, u32>(Regs::Pc, load_addr_u32) {
                info!("Failed to set PC to load address: {:?}", e);
            }
        }
        
        // 读取寄存器
        if let Ok(pc) = cpu.read_reg(Regs::Pc) {
            info!("Current PC: 0x{:x}", pc);
        } else {
            info!("Failed to read PC register");
        }
        
        if let Ok(sp) = cpu.read_reg(Regs::Sp) {
            info!("Current SP: 0x{:x}", sp);
        } else {
            info!("Failed to read SP register");
        }
        
        // 新添加: 检查并设置CPSR寄存器的T位（ARM/Thumb模式切换）
        if let Ok(cpsr) = cpu.read_reg(Regs::Cpsr) {
            info!("Current CPSR: 0x{:x}", cpsr);
            
            // 检查T位 (第5位) 确定当前模式
            let thumb_mode = (cpsr & (1 << 5)) != 0;
            info!("Current CPU mode: {}", if thumb_mode { "Thumb" } else { "ARM" });
            
            // 可选: 根据需要切换模式
            // 例如，如果需要强制使用ARM模式:
            // if thumb_mode {
            //     let new_cpsr = cpsr & !(1 << 5); // 清除T位
            //     if let Err(e) = cpu.write_reg::<Regs, u32>(Regs::Cpsr, new_cpsr) {
            //         info!("Failed to set CPSR to ARM mode: {:?}", e);
            //     } else {
            //         info!("Switched to ARM mode");
            //     }
            // }
            
            // 可选: 根据需要切换到Thumb模式:
            // let new_cpsr = cpsr | (1 << 5); // 设置T位
            // if let Err(e) = cpu.write_reg::<Regs, u32>(Regs::Cpsr, new_cpsr) {
            //     info!("Failed to set CPSR to Thumb mode: {:?}", e);
            // } else {
            //     info!("Switched to Thumb mode");
            // }
        } else {
            info!("Failed to read CPSR register");
        }
    } else {
        info!("Failed to get CPU with index 0");
    }

    // 运行仿真（注意：run是unsafe函数）
    info!("Starting emulation...");
    unsafe {
        match qemu.run() {
            Ok(QemuExitReason::Timeout) => info!("Emulation timed out"),
            Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(signal))) => {
                info!("Emulation terminated by host signal: {:?}", signal);
                signal.handle()
            },
            Ok(reason) => info!("Emulation exited with reason: {:?}", reason),
            Err(QemuExitError::UnexpectedExit) => info!("Emulation crashed with unexpected exit"),
            Err(e) => info!("Emulation error: {:?}", e),
        }
    }

    info!("QEMU system mode emulation completed");
    Ok(())
}