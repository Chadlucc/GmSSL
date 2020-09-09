#include "openssl/sm3.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#define GETCH() getchar()

int main() {
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    unsigned char mess1[] = "12345678abcderty";

    unsigned char md_value[EVP_MAX_MD_SIZE] = { 0 };
    int md_len, i;

    md = EVP_get_digestbyname("sm3");

    if (!md) {
        return -1;
    }

    mdctx = EVP_MD_CTX_new(); //分配、初始化并返回摘要上下文.
    EVP_DigestInit_ex(mdctx, md, NULL);  //设置摘要上下文ctx以使用ENGINE impl中的摘要类型. 
    EVP_DigestUpdate(mdctx, mess1, 64); //将d处的cnt字节数据散列到摘要上下文ctx中.
    EVP_DigestFinal_ex(mdctx, md_value, (unsigned int*)&md_len);//从ctx检索摘要值并将其存入md中. 
    EVP_MD_CTX_free(mdctx);


    return 0;
}
 
