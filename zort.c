#define _POSIX_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_BCRYPT
#include "libbcrypt/bcrypt.h"
#define HASHSIZE BCRYPT_HASHSIZE
#endif
#ifdef USE_MEOW_HASH
#include "meow_hash/meow_hash_x64_aesni.h"
#define HASHSIZE 16
#endif

const int WORKFORCE = 1;

void zor(char dst[HASHSIZE], char a[HASHSIZE], char b[HASHSIZE]) {
    for (size_t i = 0; i < HASHSIZE; i++) {
        dst[i] = a[i] ^ b[i];
    }
}

void small_ram(FILE* file, FILE* output_file, char hash[HASHSIZE]) {
    char filebuf[HASHSIZE] = {0};
    char zortbuf[HASHSIZE] = {0};
    while (fread(filebuf, sizeof(char), HASHSIZE, file) == HASHSIZE) {
#ifdef USE_BCRYPT
        zor(zortbuf, filebuf, hash);
#endif
#ifdef USE_MEOW_HASH
        zor(zortbuf, filebuf, (char*)&hash);
#endif
        if (fwrite(zortbuf, sizeof(char), HASHSIZE, output_file) != HASHSIZE) {
            printf("Didn't write fully\n");
        }
        memset(filebuf, 0, HASHSIZE);
    }
    // write the remainder
    fwrite(filebuf, sizeof(char), strlen(filebuf), output_file);
}

int read_entire_file(FILE* file, char** ptr, long *filesize) {
    // get file size
    if (fseek(file, 0, SEEK_END) != 0)
        return -1;
    *filesize = ftell(file);
    if (*filesize == -1)
        return -1;
    rewind(file);

    *ptr = (char*)malloc(sizeof(char)*(*filesize) + 1);
    if (*ptr == NULL)
        return -1;
    memset(*ptr, 0, sizeof(char)*(*filesize) + 1);

    if (fread(*ptr, sizeof(char), *filesize, file) == 0) return -1;
    return 0;
}

void all_ram(FILE* file, FILE* output_file, char hash[HASHSIZE]) {
    char *content;
    long fsize;
    if (read_entire_file(file, &content, &fsize) != 0) {
        printf("Error while reading content of the file\n");
        return;
    }
    printf("Read the file into memory...\n");

    for (size_t i = 0; i < fsize; i++) {
        content[i] = content[i] ^ hash[i%HASHSIZE];
    }
    printf("XORed all of the contents...\n");
    //fwrite(content, sizeof(char)*fsize, 1, output_file);
    int fd = fileno(output_file);
    write(fd, content, fsize);
    free(content);
    printf("Wrote to file...\n");
}

int main(int argc, char** argv) {
    char salt[HASHSIZE] = {0};
    char hash[HASHSIZE] = {0};
    int ret = 0;

    if (argc < 2) {
        printf("USAGE: zort <password> <file> [-f|-t]\n");
        return -1;
    }
    char* password = argv[1];
    char* filepath = argv[2];
    bool fast = false;
    bool tmp = false;
    if (argc >= 4) {
        for (size_t a = 3; a < argc; a++) {
            if (!fast)
                fast = strcmp(argv[a], "-f") == 0;
            if (!tmp)
                tmp = strcmp(argv[a], "-t") == 0;
        }
    }

    bool reverse = strcmp(filepath+strlen(filepath)-5, ".zort") == 0;

    FILE* file = fopen(filepath, "r");
    if (file == NULL) {return -1;}
    

    char* output_filename = (char*)malloc(strlen(filepath)*sizeof(char)+6);
    if (output_filename == NULL) {
        printf("Not enough memory for filename?!\n");
        ret = -1;
        goto closefile;
    }
    strcpy(output_filename, filepath);
    strcat(output_filename, ".zort");
    if (tmp) {
        size_t last_slash = 0;
        for (size_t i = 0; i < strlen(output_filename); i++) {
            if (output_filename[i] == '/')
                last_slash = i;
        }
        char *tmppath = (char*)malloc(strlen(output_filename)-last_slash+1);
        memset(tmppath, 0, strlen(output_filename)-last_slash+1);
        strcat(tmppath, "/tmp/");
        strcat(tmppath, output_filename+last_slash+ (last_slash == 0 ? 0 : 1));
        output_filename = tmppath;
    }
    printf("Output filename: %s\n", output_filename);

    FILE* output_file = fopen(output_filename, "w+");
    
#ifdef USE_BCRYPT
    if (!reverse) {
        if (bcrypt_gensalt(WORKFORCE, salt) != 0) {
            printf("Couldn't generate salt.\n");
            ret = -1; goto closefile;
        }
    } else {
        if (fread(salt, sizeof(char), HASHSIZE, file) != HASHSIZE) {
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
    if (!reverse) {
        // Write the salt
        fwrite(salt, sizeof(char), HASHSIZE, output_file);
    }
    if (fast) {
        all_ram(file, output_file, hash);
    } else {
        small_ram(file, output_file, hash);
    }
#endif
#ifdef USE_MEOW_HASH
    meow_u128 mhash = MeowHash(MeowDefaultSeed, strlen(password), password);
    if (fast) {
        all_ram(file, output_file, (char*)&mhash);
    } else {
        small_ram(file, output_file, (char*)&mhash);
    }
#endif

    free(output_filename);
    fclose(output_file);
closefile:
    fclose(file);
    return ret;
}
