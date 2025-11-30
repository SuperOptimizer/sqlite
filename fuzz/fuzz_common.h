/*
** Common utilities for SQLite fuzz harnesses
**
** This header provides:
** - Temp directory setup to prevent junk files in working directory
** - Common includes and macros
*/

#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/*
** Set up a temporary directory for this fuzzer instance.
** This prevents SQLite from creating junk files in the working directory
** when fuzzed SQL contains ATTACH statements with corrupted filenames.
**
** Call this once at the start of main(), before any SQLite operations.
** Returns 0 on success, -1 on failure.
*/
static int fuzz_setup_tmpdir(void) {
    static char tmpdir[128];
    pid_t pid = getpid();

    /* Create a unique temp directory for this process */
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/sqlite-fuzz-%d", (int)pid);

    /* Try to create the directory (ignore if exists) */
    if (mkdir(tmpdir, 0700) != 0 && errno != EEXIST) {
        /* Fall back to /tmp if we can't create our own dir */
        snprintf(tmpdir, sizeof(tmpdir), "/tmp");
    }

    /* Change to the temp directory */
    if (chdir(tmpdir) != 0) {
        perror("chdir to tmpdir");
        return -1;
    }

    return 0;
}

/*
** Clean up temp files created during fuzzing.
** Call this periodically (e.g., every N iterations) to prevent
** accumulation of temp files.
*/
static void fuzz_cleanup_tmpdir(void) {
    /* Simple cleanup: remove common SQLite temp file patterns */
    system("rm -f *.db *.db-journal *.db-wal *.db-shm 2>/dev/null");
    system("rm -f *memory* 2>/dev/null");
}

#endif /* FUZZ_COMMON_H */
