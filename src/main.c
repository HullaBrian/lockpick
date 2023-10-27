#include <stdio.h>
#include <string.h>

#define INVALID_USAGE "Invalid usage. Use 'pick --help' for a usages options.\n"

int verify_valid_call (int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {  // detect if current argv is a parameter
            switch(argv[i][1]) {
                case 'h':
                case 'H':
                case 'w':
                case 'a':
                case 't':
                    break;
                default:
                    return 0;
            }
        }
    }
    return 1;
}

int main (int argc, char* argv[]) {
    if (argc == 1) {
        printf(INVALID_USAGE);
        return 2;
    }

    if (strcmp(argv[0], "--help") == 0) {
        printf("Usage: pick [options]...\n");
        printf("\nOptions:\n");

        printf("  -h             pass the literal hash of the password\n");
        printf("  -H             pass a file containing 1 or more hashed passwords\n");
        printf("  -w             wordlist to check against the password(s)\n");
        printf("  -a             supported hashing algorithm to use:\n");
        printf("                   sha256, md5\n");
        printf("  -t             number of threads to use\n");
        return 1;
    }

    if (verify_valid_call(argc, argv) == 0) {
        printf(INVALID_USAGE);
        return 2;
    }
    printf("Success!\n");

    return 1;
}