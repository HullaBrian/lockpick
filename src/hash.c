#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "hash.h"


void get_hash(const char* plain_txt, const char* algo, unsigned char* digest) {
    /*
    https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestInit_ex.html
    */
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    unsigned char chunk[3];
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

void *cracker(CRACK_CTX* ctx) {
    unsigned char line[65];
    unsigned char digest[65];
    int found = 0;
    int i = 0;
    line[64] = '\0';
    digest[64] = '\0';
    FILE* file = fopen(ctx->fname, "r");

    if (ctx->id != 0) {
        for (i = 0; i < ctx->threads - 1; i++) {
                fgets(line, 64, file);  // skip threads to allow other threads to work
        }
    }

    while (fgets(line, 64, file) != NULL && *(ctx->found) == 0) {
        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = '\0';  // remove newline character

        get_hash(line, ctx->algorithm, digest);

        found = 0;
        for (int i = 0; i < strlen(ctx->passwd); i++) {
            if (ctx->passwd[i] != digest[i]) {
                found = 1;
                break;
            }
        }
        if (found == 0) {
            printf("[%d] Found password: '%s'\n", ctx->id, line);
            *(ctx->found) = 1;
            fclose(file);
            return;
        }

        for (i = 0; i < ctx->threads - 1; i++) {
            fgets(line, 64, file);  // skip threads to allow other threads to work
        }
    }

    fclose(file);
}

int crack_passwd(const char* passwd, CRACK_CTX* ctx) {
    printf("[+] Attempting to crack hash...\n");
    printf("Creating threads...");

    CRACK_CTX threads[ctx->threads];
    struct timespec start, finish;
    double elapsed;

    for (int i = 0; i < ctx->threads; i++) {
        threads[i] = *ctx;
        threads[i].id = i;
        pthread_create(&(threads[i].t_id), NULL, cracker, &threads[i]);
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    printf("Done!\nWaiting for threads to finish...\n");
    for (int i = ctx->threads - 1; i >= 0; i--)
        pthread_join(threads[ctx->threads - 1].t_id, NULL);

    clock_gettime(CLOCK_MONOTONIC, &finish);
    elapsed = finish.tv_sec - start.tv_sec;
    elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;

    printf("Total time: %lf seconds\n\n", elapsed);

    if (*(ctx->found) != 1)
        printf("Could not find password!\n\n");

    return 1;
}