#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "libbcrypt/bcrypt.h"

const int WORKFORCE = 1;

void zor(char dst[BCRYPT_HASHSIZE], char a[BCRYPT_HASHSIZE], char b[BCRYPT_HASHSIZE]) {
    for (size_t i = 0; i < BCRYPT_HASHSIZE; i++) {
        dst[i] = a[i] ^ b[i];
    }
}

int main(int argc, char** argv) {
    char salt[BCRYPT_HASHSIZE] = {0};
    char hash[BCRYPT_HASHSIZE] = {0};
    char filebuf[BCRYPT_HASHSIZE] = {0};
    char zortbuf[BCRYPT_HASHSIZE] = {0};
    int ret = 0;

    if (argc < 2) {
        printf("USAGE: zort <password> <file>\n");
        return -1;
    }
    char* password = argv[1];
    char* filepath = argv[2];

    bool reverse = strcmp(filepath+strlen(filepath)-5, ".zort") == 0;

    FILE* file = fopen(filepath, "r");
    if (file == NULL) {return -1;}
    
    if (!reverse) {
        if (bcrypt_gensalt(WORKFORCE, salt) != 0) {
            printf("Couldn't generate salt.\n");
            ret = -1; goto closefile;
        }
    } else {
        if (fread(salt, sizeof(char), BCRYPT_HASHSIZE, file) != BCRYPT_HASHSIZE) {
            printf("Couldn't read salt.\n");
            ret = -1; goto closefile;
        }
    }
    if (bcrypt_hashpw(password, salt, hash) != 0) {
        printf("Couldn't hash the password.\n");
        ret = -1; goto closefile;
    }
    printf("hash: %s\n", hash);
    if (access(filepath, R_OK) != 0) {
        printf("Couldn't read the file: %s\n", filepath);
        ret = -1; goto closefile;
    }

    char* output_filename = (char*)malloc(strlen(filepath)*sizeof(char)+6);
    if (output_filename == NULL) {
        printf("Not enough memory for filename?!\n");
        ret = -1;
        goto closefile;
    }
    strcpy(output_filename, filepath);
    strcat(output_filename, ".zort");
    printf("Output filename: %s\n", output_filename);

    FILE* output_file = fopen(output_filename, "w+");
    
    if (!reverse) {
        // Write the salt
        fwrite(salt, sizeof(char), BCRYPT_HASHSIZE, output_file);
    }

    while (fread(filebuf, sizeof(char), BCRYPT_HASHSIZE, file) == BCRYPT_HASHSIZE) {
        zor(zortbuf, filebuf, hash);
        if (fwrite(zortbuf, sizeof(char), BCRYPT_HASHSIZE, output_file) != BCRYPT_HASHSIZE) {
            printf("Didn't write fully\n");
        }
        memset(filebuf, 0, BCRYPT_HASHSIZE);
    }
    // write the remainder
    fwrite(filebuf, sizeof(char), strlen(filebuf), output_file);

    free(output_filename);
    fclose(output_file);
closefile:
    fclose(file);
    return ret;
}
