// Simple user mode QEMU emulation example
use libafl_qemu::{config, config::QemuConfig, Emulator, Regs, QemuExitReason, QemuExitError, QemuShutdownCause};
use libafl_qemu::command::NopCommandManager;
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
    
    /// Disassemble output.txt after emulation
    #[clap(long, default_value_t = true)]
    disassemble: bool,
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
        raw_options.push_str(&format!("{} ", debug_flags));
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
        // 设置要hook的函数
        let function_hooks = vec![
            FunctionHookConfig {
                address: 0x405A3ED4, // BL __fixup_smp指令地址
                action: FunctionHookAction::Skip,
                instruction_size: 4, // ARM指令是4字节
            },
            // 可以添加更多的函数hook配置
            // FunctionHookConfig {
            //     address: 0x12345678, // 另一个函数地址
            //     action: FunctionHookAction::ModifyReturnValue(0x0), // 修改返回值为0
            //     instruction_size: 4,
            // },
        ];

        // 运行带函数hook的仿真
        run_with_function_hooks(&emulator, qemu, function_hooks)?;
        
        Ok(())
}



// 定义函数跳过策略枚举
#[derive(Clone)]
enum FunctionHookAction {
    Skip,
    ModifyReturnValue(u32),
    // 可以添加更多类型的干预策略
}

// 定义函数hook配置结构体
#[derive(Clone)]
struct FunctionHookConfig {
    address: u64,
    action: FunctionHookAction,
    instruction_size: u32, // 指令大小，ARM为4字节，Thumb为2字节
}

// 通用的函数hook处理函数
fn setup_function_hook<C: Clone>(
    emulator: &libafl_qemu::Emulator<C, NopCommandManager, libafl_qemu::NopEmulatorDriver, (), (), (), libafl_qemu::NopSnapshotManager>,
    qemu: libafl_qemu::Qemu,
    config: FunctionHookConfig
) -> Result<(), Box<dyn std::error::Error>> 
{
    let FunctionHookConfig { address, action, instruction_size } = config;
    
    info!("Adding function hook at address: 0x{:x}", address);
    
    // 创建断点
    let breakpoint = libafl_qemu::breakpoint::Breakpoint::without_command(address as libafl_qemu::GuestAddr, false);
    let breakpoint_id = emulator.add_breakpoint(breakpoint, true);
    info!("Breakpoint added with ID: {:?}", breakpoint_id);
    
    // 返回Ok，让调用者控制执行循环
    Ok(())
}

// 运行带断点处理的仿真函数
fn run_with_function_hooks<C: Clone>(
    emulator: &libafl_qemu::Emulator<C, NopCommandManager, libafl_qemu::NopEmulatorDriver, (), (), (), libafl_qemu::NopSnapshotManager>,
    qemu: libafl_qemu::Qemu,
    hooks: Vec<FunctionHookConfig>
) -> Result<(), Box<dyn std::error::Error>> 
{
    info!("Starting emulation with function hooks...");
    let mut running = true;
    
    // 创建断点地址到hook配置的映射
        let mut hook_map = std::collections::HashMap::new();
        for hook in hooks {
            hook_map.insert(hook.address, hook.clone());
            setup_function_hook(emulator, qemu, hook)?;
        }
        
        // 运行仿真循环
        while running {
            unsafe {
                match qemu.run() {
                    Ok(QemuExitReason::Breakpoint(addr)) => {
                        let addr_u64 = addr as u64;
                        info!("Breakpoint hit at address: 0x{:x}", addr_u64);
                        
                        // 检查是否是我们设置的断点
                        if let Some(hook_config) = hook_map.get(&addr_u64) {
                            info!("Processing function hook at 0x{:x}", addr_u64);
                            
                            // 获取CPU以修改寄存器
                            if let Some(cpu) = qemu.cpu_from_index(0) {
                                // 读取当前PC
                                if let Ok(pc) = cpu.read_reg(Regs::Pc) {
                                    info!("Current PC before modification: 0x{:x}", pc);
                                    
                                    // 根据hook类型执行不同的操作
                                    match hook_config.action {
                                        FunctionHookAction::Skip => {
                                            // 跳过指令
                                            let new_pc = pc + hook_config.instruction_size;
                                            info!("Setting PC to 0x{:x} to skip instruction", new_pc);
                                            
                                            if let Err(e) = cpu.write_reg::<Regs, u32>(Regs::Pc, new_pc) {
                                                info!("Failed to set PC: {:?}", e);
                                            } else {
                                                info!("Successfully skipped instruction at 0x{:x}", addr_u64);
                                            }
                                            // if let Err(e) = cpu.write_reg::<Regs, u32>(Regs::Lr, new_pc) {
                                            //     info!("Failed to set LR: {:?}", e);
                                            // }
                                        },
                                        FunctionHookAction::ModifyReturnValue(value) => {
                                            // 修改返回值（通常是R0寄存器）
                                            info!("Setting return value to 0x{:x}", value);
                                            if let Err(e) = cpu.write_reg::<Regs, u32>(Regs::R0, value) {
                                                info!("Failed to set return value: {:?}", e);
                                            } else {
                                                // 同时跳过指令
                                                let new_pc = pc + hook_config.instruction_size;
                                                info!("Setting PC to 0x{:x} to skip instruction", new_pc);
                                                if let Err(e) = cpu.write_reg::<Regs, u32>(Regs::Pc, new_pc) {
                                                    info!("Failed to set PC: {:?}", e);
                                                } else {
                                                    info!("Successfully modified return value and skipped instruction at 0x{:x}", addr_u64);
                                                }
                                            }
                                        },
                                    }
                                }
                            }
                        }
                    },
                Ok(QemuExitReason::Timeout) => {
                    info!("Emulation timed out");
                    running = false;
                },
                Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(signal))) => {
                    info!("Emulation terminated by host signal: {:?}", signal);
                    signal.handle();
                    running = false;
                },
                Ok(reason) => {
                    info!("Emulation exited with reason: {:?}", reason);
                    running = false;
                },
                Err(QemuExitError::UnexpectedExit) => {
                    info!("Emulation crashed with unexpected exit");
                    running = false;
                },
                Err(e) => {
                    info!("Emulation error: {:?}", e);
                    running = false;
                },
            }
        }
    }
    
    info!("QEMU system mode emulation completed");
    Ok(())
}