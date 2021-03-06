## 代码介绍


代码地址
https://github.com/cryptape/GmSSL/tree/master/ckb

```
root@k8s-master:~/GmSSL/ckb# tree
.
├── gmssl-cycles.md
├── build.md   本说明文档
├── Makefile   编译运行文档
├── sm2
│   └── sm2.c  SM2代码
├── sm3
│   ├── sm3.c  SM3代码
│   ├── sm3.h  SM3头文件
│   └── sm3.md SM3说明文档
└── standalone-cycle.md

```

## 环境准备


### GmSSL 编译

git clone https://github.com/cryptape/GmSSL.git
cd GmSSL
./Configure linux-generic64 no-threads no-sock no-shared no-dso no-stdio no-ui no-afalgeng -DNO_SYSLOG
make include/openssl/opensslconf.h crypto/include/internal/bn_conf.h  crypto/include/internal/dso_conf.h
make CC=riscv64-unknown-elf-gcc libcrypto.a 

## 代码测试

可以直接在ckb目录下运行如下代码进行测试

make

make run

也可以使用如下命令

### SM2测试

cd ckb/sm2/

#### SM2编译
root@localhost:~/GmSSL/ckb/sm2# riscv64-unknown-elf-gcc sm2.c ../../libcrypto.a -I../../include  -o sm2


#### SM2运行

root@localhost:~/GmSSL/ckb/sm2# PATH_TO_CKB_VM/asm64 sm2
Run result: Ok(4)
Total cycles consumed: 44804302
Transfer cycles: 398143, running cycles: 44406159

Error result: Ok(4)

### SM3测试

cd ckb/sm3/

#### SM3编译

root@localhost:~/GmSSL/ckb/sm3# riscv64-unknown-elf-gcc sm3.c -o sm3

#### SM3运行

root@localhost:~/GmSSL/ckb/sm3# PATH_TO_CKB_VM/asm64 sm3
Run result: Ok(1)
Total cycles consumed: 35332
Transfer cycles: 7155, running cycles: 28177

Error result: Ok(1)
