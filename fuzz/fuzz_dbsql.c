/*
** SQLite Database + SQL Combined Fuzzer
**
** This fuzzer combines a fuzzed database file with fuzzed SQL statements.
** The input format is: [4-byte DB size][database bytes][SQL bytes]
**
** This is more powerful than fuzzing either alone because it can discover
** bugs that only manifest with specific database states + SQL combinations.
** Uses AFL++ persistent mode for high performance fuzzing.
*/

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "sqlite3.h"
#include "fuzz_common.h"

/* AFL++ persistent mode macros */
#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();
#endif

/* Progress handler to prevent infinite loops */
static int nProgressCalls = 0;
static const int MAX_PROGRESS_CALLS = 100000;

static int progress_handler(void *pUnused) {
    (void)pUnused;
    nProgressCalls++;
    return nProgressCalls >= MAX_PROGRESS_CALLS;
}

/* Maximum sizes */
static const size_t MAX_DB_SIZE = 10 * 1024 * 1024;   /* 10 MB */
static const size_t MAX_SQL_LEN = 100000;
static const sqlite3_int64 DB_SIZE_LIMIT = 50 * 1024 * 1024;

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    unsigned char *dbCopy = NULL;
    char *sql = NULL;
    char *zErr = NULL;
    uint32_t dbSize;
    size_t sqlSize;
    int rc;
    sqlite3_int64 szLimit;

    /*
     * Input format:
     * - First 4 bytes: little-endian database size
     * - Next dbSize bytes: database content
     * - Remaining bytes: SQL statement
     */

    /* Need at least 4 bytes for size + some minimal content */
    if (size < 8) {
        return 0;
    }

    /* Read database size (little-endian) */
    dbSize = (uint32_t)data[0]
           | ((uint32_t)data[1] << 8)
           | ((uint32_t)data[2] << 16)
           | ((uint32_t)data[3] << 24);

    /* Validate sizes */
    if (dbSize > MAX_DB_SIZE || dbSize > size - 4) {
        /* Invalid size, just use remaining as SQL against empty DB */
        dbSize = 0;
    }

    sqlSize = size - 4 - dbSize;
    if (sqlSize > MAX_SQL_LEN) {
        sqlSize = MAX_SQL_LEN;
    }

    /* Open in-memory database */
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    /* Set progress handler */
    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Set limits */
    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 1000000);
    sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 100000);
    sqlite3_limit(db, SQLITE_LIMIT_VDBE_OP, 100000);

    /* Load the database if we have one */
    if (dbSize >= 100) {
        dbCopy = sqlite3_malloc64(dbSize + 1);
        if (dbCopy != NULL) {
            memcpy(dbCopy, data + 4, dbSize);

            rc = sqlite3_deserialize(db, "main", dbCopy, dbSize, dbSize,
                    SQLITE_DESERIALIZE_FREEONCLOSE | SQLITE_DESERIALIZE_RESIZEABLE);
            if (rc != SQLITE_OK) {
                sqlite3_free(dbCopy);
                /* Continue with empty database */
            } else {
                /* Set size limit */
                szLimit = DB_SIZE_LIMIT;
                sqlite3_file_control(db, "main", SQLITE_FCNTL_SIZE_LIMIT, &szLimit);
            }
        }
    }

    /* Execute the SQL if we have any */
    if (sqlSize > 0) {
        sql = malloc(sqlSize + 1);
        if (sql != NULL) {
            memcpy(sql, data + 4 + dbSize, sqlSize);
            sql[sqlSize] = '\0';

            nProgressCalls = 0;
            sqlite3_exec(db, sql, NULL, NULL, &zErr);
            sqlite3_free(zErr);

            free(sql);
        }
    }

    /* Also run some standard checks */
    nProgressCalls = 0;
    sqlite3_exec(db, "PRAGMA integrity_check;", NULL, NULL, NULL);

    sqlite3_close(db);

    return 0;
}

#ifdef __AFL_FUZZ_TESTCASE_LEN
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    /* Initialize SQLite once */
    fuzz_setup_tmpdir();
    sqlite3_initialize();
    sqlite3_config(SQLITE_CONFIG_LOOKASIDE, 0, 0);

    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(100000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        fuzz_one_input(buf, len);
    }

    return 0;
}
#else
/* Standalone mode - read from file or stdin */
int main(int argc, char **argv) {
    uint8_t *data = NULL;
    size_t size = 0;
    size_t capacity = 0;

    fuzz_setup_tmpdir();
    sqlite3_initialize();
    sqlite3_config(SQLITE_CONFIG_LOOKASIDE, 0, 0);

    FILE *f = (argc > 1) ? fopen(argv[1], "rb") : stdin;
    if (!f) {
        perror("fopen");
        return 1;
    }

    /* Read entire input */
    while (1) {
        if (size >= capacity) {
            capacity = capacity ? capacity * 2 : 4096;
            data = realloc(data, capacity);
            if (!data) {
                perror("realloc");
                if (argc > 1) fclose(f);
                return 1;
            }
        }
        size_t n = fread(data + size, 1, capacity - size, f);
        if (n == 0)
            break;
        size += n;
    }

    if (argc > 1)
        fclose(f);

    fuzz_one_input(data, size);

    free(data);
    return 0;
}
#endif
