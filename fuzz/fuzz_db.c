/*
** SQLite Database File Fuzzer
**
** This fuzzer tests SQLite's ability to safely handle malformed database files.
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

/*
** SQL statements to run against fuzzed databases.
** These exercise various SQLite functionality to find bugs.
*/
static const char *azSql[] = {
    /* Integrity and structure checks */
    "PRAGMA integrity_check;",
    "PRAGMA quick_check;",
    "PRAGMA foreign_key_check;",
    "PRAGMA page_count;",
    "PRAGMA freelist_count;",
    "PRAGMA page_size;",
    "PRAGMA journal_mode;",
    "PRAGMA encoding;",
    "PRAGMA auto_vacuum;",
    "PRAGMA schema_version;",
    "PRAGMA user_version;",
    "PRAGMA application_id;",
    "PRAGMA data_version;",
    "PRAGMA table_list;",
    "PRAGMA index_list(sqlite_schema);",
    "PRAGMA compile_options;",

    /* Schema queries */
    "SELECT * FROM sqlite_schema;",
    "SELECT count(*) FROM sqlite_schema;",
    "SELECT type, name, tbl_name, rootpage FROM sqlite_schema;",
    "SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL;",
    "SELECT * FROM sqlite_schema WHERE type='table';",
    "SELECT * FROM sqlite_schema WHERE type='index';",
    "SELECT * FROM sqlite_schema WHERE type='trigger';",
    "SELECT * FROM sqlite_schema WHERE type='view';",

    /* DBSTAT virtual table queries */
    "SELECT * FROM dbstat;",
    "SELECT sum(length(name)) FROM dbstat;",
    "SELECT pageno, pagetype, ncell, payload, unused FROM dbstat LIMIT 100;",
    "SELECT name, path, pageno FROM dbstat WHERE pagetype='leaf' LIMIT 50;",
    "SELECT aggregate_npage FROM dbstat ORDER BY 1 DESC LIMIT 10;",

    /* Try to read actual table data if tables exist */
    "SELECT * FROM (SELECT name FROM sqlite_schema WHERE type='table' LIMIT 1);",
    "SELECT count(*) FROM (SELECT name FROM sqlite_schema WHERE type='table' LIMIT 1);",

    /* Maintenance operations */
    "REINDEX;",
    "VACUUM;",
    "ANALYZE;",
    "PRAGMA optimize;",
    "PRAGMA wal_checkpoint;",
    "PRAGMA incremental_vacuum(10);",

    /* Try to modify (tests write paths on corrupted DB) */
    "BEGIN;",
    "CREATE TABLE IF NOT EXISTS _fuzz_test_(x);",
    "INSERT OR IGNORE INTO _fuzz_test_ VALUES(1);",
    "ROLLBACK;",

    /* FTS/RTRee if present */
    "SELECT * FROM sqlite_schema WHERE sql LIKE '%fts%';",
    "SELECT * FROM sqlite_schema WHERE sql LIKE '%rtree%';",
};

/* Progress handler to prevent infinite loops */
static int nProgressCalls = 0;
static const int MAX_PROGRESS_CALLS = 100000;

static int progress_handler(void *pUnused) {
    (void)pUnused;
    nProgressCalls++;
    return nProgressCalls >= MAX_PROGRESS_CALLS;
}

/* Maximum database size */
static const sqlite3_int64 MAX_DB_SIZE = 50 * 1024 * 1024;  /* 50 MB */

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    unsigned char *dbCopy = NULL;
    int rc;
    size_t i;
    sqlite3_int64 szLimit;

    /* Skip empty or tiny inputs */
    if (size < 100 || size > MAX_DB_SIZE) {
        return 0;
    }

    /* Open an in-memory database */
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    /* Copy the fuzz data so we can pass ownership to deserialize */
    dbCopy = sqlite3_malloc64(size + 1);
    if (dbCopy == NULL) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(dbCopy, data, size);

    /* Load the fuzzed data as a database using deserialize */
    rc = sqlite3_deserialize(db, "main", dbCopy, size, size,
            SQLITE_DESERIALIZE_FREEONCLOSE | SQLITE_DESERIALIZE_RESIZEABLE);
    if (rc != SQLITE_OK) {
        /* deserialize failed, dbCopy was not taken ownership of */
        sqlite3_free(dbCopy);
        sqlite3_close(db);
        return 0;
    }
    /* Note: dbCopy is now owned by SQLite and will be freed on close */

    /* Set a size limit */
    szLimit = MAX_DB_SIZE;
    sqlite3_file_control(db, "main", SQLITE_FCNTL_SIZE_LIMIT, &szLimit);

    /* Set progress handler to prevent infinite loops */
    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Run test SQL statements */
    for (i = 0; i < sizeof(azSql) / sizeof(azSql[0]); i++) {
        char *zErr = NULL;
        nProgressCalls = 0;
        sqlite3_exec(db, azSql[i], NULL, NULL, &zErr);
        sqlite3_free(zErr);
    }

    /* Clean up */
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
