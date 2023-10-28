#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

#include "hash.h"


void get_hash(const char* plain_txt, const char* algo, unsigned char* digest) {
    /*
    https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestInit_ex.html
    */
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    char chunk[3];
    chunk[2] = '\0';

    md = EVP_get_digestbyname(algo);  // "SHA256"

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, plain_txt, strlen(plain_txt));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    for (int i = 0; i < md_len; i++) {
        sprintf(chunk, "%02x", md_value[i]);
        strncat(digest, chunk, 2);
    }
}