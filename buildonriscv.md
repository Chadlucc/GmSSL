# 编译GmSSL

```
https://github.com/cryptape/GmSSL.git
cd GmSSL
./Configure linux-generic64 no-threads no-sock no-shared no-dso no-stdio no-ui no-afalgeng -DNO_SYSLOG
make include/openssl/opensslconf.h crypto/include/internal/bn_conf.h  crypto/include/internal/dso_conf.h
make CC=riscv64-unknown-elf-gcc libcrypto.a 
```
# 编译测试代码

```
riscv64-unknown-elf-gcc test/sms4test.c libcrypto.a -I include  -o sms4test

```
