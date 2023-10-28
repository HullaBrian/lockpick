#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"

#define INVALID_USAGE "Invalid usage. Use 'pick --help' for a usages options.\n"
#define MAX_HASH_LENGTH 32
#define MAX_HASH_ALGO_LENGTH 6

#define NUM_SUPPORTED_HASH_ALGOS 2
const char* SUPPORTED_HASH_ALGS[] = {"SHA256", "MD5"};

int verify_valid_call (int argc, char* argv[]) {
    int h = 0;
    int total = 3;  // ensure that all required parameters are given. each required paramter detected decreases count by 1
    
    /*
    Required paramters:
        - (-h/-H) input method of the password hash (literal or file)
        - (-w) wordlist
    */
    
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {  // detect if current argv is a parameter
            switch(argv[i][1]) {
                case 'h':
                    if (h == 2) {
                        printf("You may not give both a literal hash and an input file!\n");
                        return 0;
                    }
                    h = 1;
                    total--;
                    break;
                case 'H':
                    if (h == 1) {
                        printf("You may not give both a literal hash and an input file!\n");
                        return 0;
                    }
                    h = 2;
                    total--;
                    break;
                case 'w':
                    total--;
                    break;
                case 'a':
                    total--;
                    break;
                case 't':
                    break;
                default:
                    return 0;
            }
        }
    }
    if (total != 0) {
        return -1;
    }

    return 1;
}

int main (int argc, char* argv[]) {
    char hash[MAX_HASH_LENGTH + 1];
    FILE* WORDLIST;
    FILE* PASSWORD_LIST;
    char hash_alg[MAX_HASH_ALGO_LENGTH + 1] = "|";
    int threads = 1;

    unsigned char digest[65];
    digest[64] = '\0';

    if (argc == 1) {
        printf(INVALID_USAGE);
        return 2;
    }

    if (strcmp(argv[1], "--help") == 0) {
        printf("Usage: pick [options]...\n");
        printf("\nRequired Parameters:\n");

        printf("  -h             pass the literal hash of the password\n");
        printf("  -H             pass a file containing 1 or more hashed passwords\n");
        printf("  -w             wordlist to check against the password(s)\n");
        printf("  -a             supported hashing algorithm to use:\n");
        printf("                   sha256, md5\n");
        printf("\nYou must provide either -h or -H, along with -a and -w\n");
        
        printf("\nOptional Parameters:\n");
        printf("  -t             number of threads to use\n");
        
        printf("\nExample usage:\n");
        printf("$./pick -h 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 -a SHA256 -w rockyou.txt\n\n");
        return 1;
    }

    int verify_status = verify_valid_call(argc, argv);

    if (verify_status == 0) {
        printf(INVALID_USAGE);
        return 2;
    } else if (verify_status == -1) {
        printf("Missing required parameter(s). See 'pick --help' for details\n");
        return 2;
    }

    printf("[+] Building data to begin cracking...\n");
    
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {  // detect if current argv is a parameter
            switch(argv[i][1]) {
                case 'h':
                    strncpy(hash, argv[i + 1], MAX_HASH_LENGTH);
                    hash[MAX_HASH_LENGTH] = '\0';
                    printf("[+] Assigned literal hash\n");
                    i++;
                    break;
                case 'H':
                    PASSWORD_LIST = fopen(argv[i + 1], "r");
                    if (PASSWORD_LIST != NULL) {
                        printf("[+] Opened hash list at '%s'\n", argv[i + 1]);
                        i++;
                        break;
                    }
                    printf("[CRITICAL] COULD NOT OPEN FILE\n");
                    return 3;
                case 'w':
                    WORDLIST = fopen(argv[i + 1], "r");
                    if (WORDLIST != NULL) {
                        printf("[+] Opened hash list at '%s'\n", argv[i + 1]);
                        i++;
                        break;
                    }
                    printf("[CRITICAL] COULD NOT OPEN FILE\n");
                    return 3;
                case 'a':
                    for (int j = 0; j < NUM_SUPPORTED_HASH_ALGOS; j++) {
                        if (strcmp(argv[i + 1], SUPPORTED_HASH_ALGS[j]) == 0) {
                            strncpy(hash_alg, argv[i + 1], MAX_HASH_ALGO_LENGTH);
                            hash_alg[MAX_HASH_ALGO_LENGTH] = '\0';
                            printf("[+] Assigned hash algorithm\n");
                            break;
                        }
                    }

                    if (hash_alg[0] == '|') {
                        printf("Invalid option '%s' for hash algorithm\n", argv[i + 1]);
                        return 5;
                    }

                    i++;
                    break;
                case 't':
                    if (atoi(argv[i + 1]) == 0) {
                        printf("Invalid option '%s' for number of threads!\n", argv[i + 1]);
                        return 4;
                    }
                    threads = atoi(argv[i + 1]);
                    printf("[+] Assigned the number of threads to use\n");
                    i++;
                    break;
            }
        }
    }

    get_hash(hash, hash_alg, digest);
    printf("Digest: %s\n", digest);

    printf("[+] Cleaning up...");
    if (PASSWORD_LIST != NULL)
        fclose(PASSWORD_LIST);
    if (WORDLIST != NULL)
        fclose(WORDLIST);
    printf("done!\n");

    printf("Exiting...\n");

    return 1;
}