/*
** SQLite Deserialize Fuzzer
**
** Tests sqlite3_deserialize() which allows loading a database from
** a memory buffer - exercises database format parsing code.
*/

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "sqlite3.h"
#include "fuzz_common.h"

#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();
#endif

static int nProgressCalls = 0;
static const int MAX_PROGRESS_CALLS = 50000;

static int progress_handler(void *pUnused) {
    (void)pUnused;
    return ++nProgressCalls >= MAX_PROGRESS_CALLS;
}

static const size_t MAX_INPUT_LEN = 100000;
static const size_t MIN_DB_SIZE = 512;  /* Minimum SQLite database size */

/* Queries to run against deserialized database */
static const char *azTestSql[] = {
    "SELECT * FROM sqlite_schema;",
    "SELECT sql FROM sqlite_schema WHERE type='table';",
    "PRAGMA integrity_check;",
    "PRAGMA quick_check;",
    "PRAGMA page_count;",
    "PRAGMA freelist_count;",
    "PRAGMA schema_version;",
    "PRAGMA page_size;",
    "PRAGMA journal_mode;",
    "PRAGMA encoding;",
    "SELECT count(*) FROM sqlite_schema;",
    "SELECT name FROM sqlite_schema WHERE type='table';",
    "SELECT name FROM sqlite_schema WHERE type='index';",
    "SELECT name FROM sqlite_schema WHERE type='trigger';",
    "SELECT name FROM sqlite_schema WHERE type='view';",
    "PRAGMA table_list;",
    "PRAGMA database_list;",
    "ANALYZE;",
    "PRAGMA optimize;",
    "REINDEX;",
};

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    unsigned char *dbData = NULL;

    if (size < MIN_DB_SIZE || size > MAX_INPUT_LEN) return 0;

    /* Allocate writable buffer for database */
    dbData = sqlite3_malloc64(size);
    if (!dbData) return 0;
    memcpy(dbData, data, size);

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        sqlite3_free(dbData);
        return 0;
    }

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Set limits to prevent DoS */
    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 100000);
    sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 50000);
    sqlite3_limit(db, SQLITE_LIMIT_COLUMN, 100);
    sqlite3_limit(db, SQLITE_LIMIT_EXPR_DEPTH, 100);
    sqlite3_limit(db, SQLITE_LIMIT_COMPOUND_SELECT, 10);
    sqlite3_limit(db, SQLITE_LIMIT_VDBE_OP, 50000);
    sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 2);

    /* Try to deserialize the fuzzed data as a database */
    rc = sqlite3_deserialize(db, "main", dbData, size, size,
                             SQLITE_DESERIALIZE_FREEONCLOSE |
                             SQLITE_DESERIALIZE_RESIZEABLE);

    if (rc == SQLITE_OK) {
        /* Database was deserialized - run queries */
        size_t nQueries = sizeof(azTestSql) / sizeof(azTestSql[0]);
        for (size_t i = 0; i < nQueries; i++) {
            nProgressCalls = 0;
            sqlite3_exec(db, azTestSql[i], NULL, NULL, NULL);
        }

        /* Try to read from any tables found */
        sqlite3_stmt *stmt = NULL;
        rc = sqlite3_prepare_v2(db,
            "SELECT name FROM sqlite_schema WHERE type='table' LIMIT 5",
            -1, &stmt, NULL);
        if (rc == SQLITE_OK && stmt) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char *tblName = (const char *)sqlite3_column_text(stmt, 0);
                if (tblName && strlen(tblName) < 100) {
                    char sql[200];
                    snprintf(sql, sizeof(sql), "SELECT * FROM \"%s\" LIMIT 10;", tblName);
                    nProgressCalls = 0;
                    sqlite3_exec(db, sql, NULL, NULL, NULL);

                    snprintf(sql, sizeof(sql), "PRAGMA table_info(\"%s\");", tblName);
                    sqlite3_exec(db, sql, NULL, NULL, NULL);
                }
            }
            sqlite3_finalize(stmt);
        }

        /* Try some modifications */
        sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL);
        sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS fuzz_test(id INTEGER);", NULL, NULL, NULL);
        sqlite3_exec(db, "INSERT INTO fuzz_test VALUES(1);", NULL, NULL, NULL);
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);

        /* Vacuum and checkpoint */
        sqlite3_exec(db, "VACUUM;", NULL, NULL, NULL);
    }

    /* Close will free dbData due to SQLITE_DESERIALIZE_FREEONCLOSE */
    sqlite3_close(db);

    return 0;
}

#ifdef __AFL_FUZZ_TESTCASE_LEN
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    fuzz_setup_tmpdir();
    sqlite3_initialize();
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(100000)) {
        fuzz_one_input(buf, __AFL_FUZZ_TESTCASE_LEN);
    }
    return 0;
}
#else
int main(int argc, char **argv) {
    uint8_t *data = NULL;
    size_t size = 0, capacity = 0;
    fuzz_setup_tmpdir();
    sqlite3_initialize();
    FILE *f = (argc > 1) ? fopen(argv[1], "rb") : stdin;
    if (!f) return 1;
    while (1) {
        if (size >= capacity) {
            capacity = capacity ? capacity * 2 : 4096;
            data = realloc(data, capacity);
            if (!data) return 1;
        }
        size_t n = fread(data + size, 1, capacity - size, f);
        if (n == 0) break;
        size += n;
    }
    if (argc > 1) fclose(f);
    fuzz_one_input(data, size);
    free(data);
    return 0;
}
#endif
