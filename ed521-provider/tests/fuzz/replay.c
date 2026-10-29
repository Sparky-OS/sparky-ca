/* SPDX-License-Identifier: ISC
 * Copyright (c) 2026 Daniel Campos Ramos
 *
 * Runs a harness over files and directories without libFuzzer, so that the
 * kept corpus and every crash found are regression tests in the normal build.
 */
#include "common.h"
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static int replay(const char *path, int *count)
{
    struct stat info;
    if (stat(path, &info) != 0)
        return 1;
    if (S_ISDIR(info.st_mode)) {
        DIR *directory = opendir(path);
        struct dirent *entry;
        int failed = directory == NULL;
        while (!failed && (entry = readdir(directory)) != NULL) {
            char child[4096];
            if (entry->d_name[0] == '.')
                continue;
            snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
            failed = replay(child, count);
        }
        if (directory != NULL)
            closedir(directory);
        return failed;
    }
    FILE *file = fopen(path, "rb");
    unsigned char *data = malloc(info.st_size ? (size_t)info.st_size : 1);
    if (file == NULL || data == NULL || fread(data, 1, (size_t)info.st_size, file) != (size_t)info.st_size) {
        if (file != NULL)
            fclose(file);
        free(data);
        return 1;
    }
    fclose(file);
    LLVMFuzzerTestOneInput(data, (size_t)info.st_size);
    free(data);
    ++*count;
    return 0;
}

int main(int argc, char **argv)
{
    int count = 0;
    LLVMFuzzerInitialize(&argc, &argv);
    for (int i = 1; i < argc; ++i) {
        if (replay(argv[i], &count)) {
            fprintf(stderr, "cannot read %s\n", argv[i]);
            return 1;
        }
    }
    printf("%d inputs replayed\n", count);
    return 0;
}
