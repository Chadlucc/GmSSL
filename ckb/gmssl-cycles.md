
# GmSSL编译安装

## Docker 环境安装


```
mkdir /home/data/ckb
docker run -it -d -v /home/data/ckb:/ckb nervos/ckb-riscv-gnu-toolchain:bionic-20191209  /bin/bash
```

## GmSSL安装


进入docker程序

```
docker exec -it XXX /bin/bash
```

在docker中执行以下命令

```
cd /ckb
git clone https://github.com/cryptape/GmSSL.git
cd GmSSL
./Configure linux-generic64 no-threads no-sock no-shared no-dso no-stdio no-ui no-afalgeng -DNO_SYSLOG
make include/openssl/opensslconf.h crypto/include/internal/bn_conf.h  crypto/include/internal/dso_conf.h
make CC=riscv64-unknown-elf-gcc libcrypto.a 
```

# 测试程序编译安装

在docker中执行以下命令

```
riscv64-unknown-elf-gcc test/sms4test.c libcrypto.a -I include  -o sms4test
```
# Cycle数量测试

## 环境准备

### ckb-vm编译

在宿主机上执行

```
cd /home/data/ckb
git clone https://github.com/nervosnetwork/ckb-vm-test-suite
```

修改vm配置文件
```
vim /home/data/ckb/ckb-vm-test-suite/binary/src/asm64.rs
```
将文件内容替换为如下内容：
```
use bytes::Bytes;
use std::env;
use std::fs::File;
use std::io::Read;
use std::process::exit;
use ckb_vm::{
    instructions::{extract_opcode, insts},
    Instruction,
};
// 0.25 cycles per byte
pub const BYTES_PER_CYCLE: u64 = 4;

pub fn transferred_byte_cycles(bytes: u64) -> u64 {
    // Compiler will optimize the divisin here to shifts.
    (bytes + BYTES_PER_CYCLE - 1) / BYTES_PER_CYCLE
}
pub fn instruction_cycles(i: Instruction) -> u64 {
    match extract_opcode(i) {
        insts::OP_JALR => 3,
        insts::OP_LD => 2,
        insts::OP_LW => 3,
        insts::OP_LH => 3,
        insts::OP_LB => 3,
        insts::OP_LWU => 3,
        insts::OP_LHU => 3,
        insts::OP_LBU => 3,
        insts::OP_SB => 3,
        insts::OP_SH => 3,
        insts::OP_SW => 3,
        insts::OP_SD => 2,
        insts::OP_BEQ => 3,
        insts::OP_BGE => 3,
        insts::OP_BGEU => 3,
        insts::OP_BLT => 3,
        insts::OP_BLTU => 3,
        insts::OP_BNE => 3,
        insts::OP_EBREAK => 500,
        insts::OP_ECALL => 500,
        insts::OP_JAL => 3,
        insts::OP_RVC_LW => 3,
        insts::OP_RVC_LD => 2,
        insts::OP_RVC_SW => 3,
        insts::OP_RVC_SD => 2,
        insts::OP_RVC_LWSP => 3,
        insts::OP_RVC_LDSP => 2,
        insts::OP_RVC_SWSP => 3,
        insts::OP_RVC_SDSP => 2,
        insts::OP_RVC_BEQZ => 3,
        insts::OP_RVC_BNEZ => 3,
        insts::OP_RVC_JAL => 3,
        insts::OP_RVC_J => 3,
        insts::OP_RVC_JR => 3,
        insts::OP_RVC_JALR => 3,
        insts::OP_RVC_EBREAK => 500,
        insts::OP_MUL => 5,
        insts::OP_MULW => 5,
        insts::OP_MULH => 5,
        insts::OP_MULHU => 5,
        insts::OP_MULHSU => 5,
        insts::OP_DIV => 32,
        insts::OP_DIVW => 32,
        insts::OP_DIVU => 32,
        insts::OP_DIVUW => 32,
        insts::OP_REM => 32,
        insts::OP_REMW => 32,
        insts::OP_REMU => 32,
        insts::OP_REMUW => 32,
        _ => 1,
    }
}
use ckb_vm::{
    decoder::build_imac_decoder,
    machine::asm::{AsmCoreMachine, AsmMachine},
    DefaultMachineBuilder, SupportMachine,
};
fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    let mut file = File::open(args[0].clone()).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    let buffer: Bytes = buffer.into();
	
	
	
    let args: Vec<Bytes> = args.into_iter().map(|a| a.into()).collect();
	
	
		let max_cycle = 0xffffffff;
	
        let core_machine = AsmCoreMachine::new_with_max_cycles(max_cycle);
        let mut builder = DefaultMachineBuilder::new(core_machine)
            .instruction_cycle_func( Box::new(instruction_cycles));
	
        let mut machine = AsmMachine::new(builder.build(), None);
		let bytes = machine.load_program(&buffer, &args).unwrap();
		let transferred_cycles = transferred_byte_cycles(bytes);
		machine.machine.add_cycles(transferred_cycles).expect("load program cycles");
		let result = machine.run();
        println!(
            "Run result: {:?}\nTotal cycles consumed: {}\nTransfer cycles: {}, running cycles: {}\n",
            result,
            machine.machine.cycles(),
            transferred_cycles,
            machine.machine.cycles() - transferred_cycles,
        );
		if result != Ok(0) {
		println!("Error result: {:?}", result);
		exit(i32::from(result.unwrap_or(-1)));
		}
}

```

构建虚拟机

```
cd /home/data/ckb/ckb-vm-test-suite/
./test.sh
cd /home/data/ckb/ckb-vm-test-suite/binary
cargo build --release
```

### 下载ckb-glibc

在宿主机上执行如下命令：

```
cd /home//data/ckb/
git clone https://github.com/nervosnetwork/ckb-c-stdlib.git
```

### 测试Cycle数量

```
cd /home/data/ckb/GmSSL/ckb
make run 
```




