#ifndef HASH_H
#define HASH_H

#include <openssl/evp.h>

void get_hash(const char* plain_txt, const char* algo, unsigned char* digest);

#endif