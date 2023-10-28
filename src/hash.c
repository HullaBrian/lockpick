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
    int i = 0;
    chunk[2] = '\0';

    memset(digest, '\0', EVP_MAX_MD_SIZE);

    md = EVP_get_digestbyname(algo);  // "SHA256"

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, plain_txt, strlen(plain_txt));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    for (; i < md_len; i++) {
        sprintf(chunk, "%02x", md_value[i]);
        strncat(digest, chunk, 2);
    }
}

int crack_passwd(const char* passwd, const CRACK_CTX* ctx) {
    if (ctx->wordlist == NULL) {
        return -1;
    }
    printf("\n[+] Attempting to crack hash...\n");

    unsigned char line[65];
    unsigned char digest[65];
    int found = 0;
    line[64] = '\0';
    digest[64] = '\0';

    while (!feof(ctx->wordlist)) {
        fgets(line, 64, ctx->wordlist);
        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = '\0';  // remove newline character

        get_hash(line, ctx->algorithm, digest);

        found = 0;
        for (int i = 0; i < strlen(passwd); i++) {
            if (passwd[i] != digest[i]) {
                found = 1;
                break;
            }
        }
        if (found == 0) {
            printf("Found password: '%s'\n\n", line);
            return 0;
        }
    }
    printf("Could not find password!\n\n");
    return 1;
}

int crack_passwds(const FILE* passwds, const CRACK_CTX* ctx) {
    return -1;
}