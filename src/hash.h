#ifndef HASH_H
#define HASH_H

#include <openssl/evp.h>
#define BUF_SIZE 65536

typedef struct CRACK_CTX {
    char fname[20];
    pthread_t t_id;
    int id;
    int* found;
    int threads;

    char passwd[65];
    char algorithm[7];
} CRACK_CTX;

void get_hash(const char* plain_txt, const char* algo, unsigned char* digest);
int crack_passwd(const char* passwd, CRACK_CTX* ctx);
void *cracker(CRACK_CTX* ctx);

#endif