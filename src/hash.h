#ifndef HASH_H
#define HASH_H

#include <openssl/evp.h>

typedef struct CRACK_CTX {
    FILE* wordlist;
    char algorithm[7];
} CRACK_CTX;

void get_hash(const char* plain_txt, const char* algo, unsigned char* digest);
int crack_passwd(const char* passwd, const CRACK_CTX* ctx);
int crack_passwds(const FILE* passwds, const CRACK_CTX* ctx);

#endif