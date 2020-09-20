

## Preparation

### Install Cargo
```
root@gmssl:~# apt-get install cargo
```

### Install ckb riscv toolchain

First we need to run the ckb-riscv-gnu-toolchain docker and enter the container.

Run those code below on host machine

```
root@gmssl:~# mkdir /home/data/ckb
root@gmssl:~# docker run -it -d -v /home/gmssl/ckb:/ckb nervos/ckb-riscv-gnu-toolchain:bionic-20191209  /bin/bash    
root@gmssl:~# docker exec -it 3ed22e64a76b /bin/b
```

Copy those riscv compiler files to /ckb

```
root@3ed22e64a76b:/# cp -r /riscv/ /ckb/
```

Set enviroment variable

```
root@gmssl:~# export RISCV=/home/gmssl/ckb/riscv/
root@gmssl:~# export PATH=$PATH:$RISCV/bin
```
### Install ckb-c-std-lib

```
root@gmssl:~# cd /home/gmssl/ckb/
root@gmssl:~/ckb# git clone https://github.com/nervosnetwork/ckb-c-stdlib.git
```

### Install ckb-vm-test-suite

First we need to get ckb-vm-test-suite source code
```
root@gmssl:~/ckb# cd /home/data/ckb
root@gmssl:~/ckb# git clone https://github.com/nervosnetwork/ckb-vm-test-suite
```

In order to  add cycle count to ckb-vm, we need to configure the template file.Replace /home/gmssl/ckb/ckb-vm-test-suite/binary/src/asm64.rs with code below.

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

### Generate CKB-VM (Configured with cycle caculation)

We need to generate ckb-vm first. 
```
root@gmssl:~/ckb/GmSSL# cd /home/gmssl/ckb/ckb-vm-test-suite/
root@gmssl:~/ckb/ckb-vm-test-suite# ./test.sh 
```

After generated the ckb-vm, we can use it to caculate the running cycles of sm2\sm3\sm9.



```
root@gmssl:~# cd /home/gmssl/ckb/GmSSL/ckb/
root@gmssl:~/ckb/GmSSL/ckb# make run
```
We can get something like these below

```
running /home/gmssl/ckb/ckb-vm-test-suite/binary/target/release/asm64 sm3
Run result: Ok(0)
Total cycles consumed: 104581
Transfer cycles: 1475, running cycles: 103106

Done. There should be no output(return 0).
```
