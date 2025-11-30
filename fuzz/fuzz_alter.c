/*
** SQLite ALTER TABLE / Schema Modification Fuzzer
**
** Tests schema modification operations which exercise complex
** code paths in SQLite's schema management.
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

static const size_t MAX_INPUT_LEN = 50000;

/* Schema modification templates */
static const char *azAlterSql[] = {
    /* ALTER TABLE operations */
    "ALTER TABLE t1 RENAME TO %s;",
    "ALTER TABLE t1 RENAME COLUMN a TO %s;",
    "ALTER TABLE t1 ADD COLUMN %s INTEGER;",
    "ALTER TABLE t1 ADD COLUMN %s TEXT DEFAULT '';",
    "ALTER TABLE t1 ADD COLUMN %s REAL DEFAULT 0.0;",
    "ALTER TABLE t1 ADD COLUMN %s BLOB;",
    "ALTER TABLE t1 DROP COLUMN e;",

    /* CREATE operations with fuzzed names */
    "CREATE TABLE %s (id INTEGER PRIMARY KEY, val TEXT);",
    "CREATE TABLE IF NOT EXISTS %s (x, y, z);",
    "CREATE INDEX %s ON t1(b);",
    "CREATE UNIQUE INDEX %s ON t1(a, b);",
    "CREATE INDEX IF NOT EXISTS %s ON t2(x);",
    "CREATE VIEW %s AS SELECT * FROM t1;",
    "CREATE VIEW IF NOT EXISTS %s AS SELECT a, b FROM t1 WHERE c > 0;",
    "CREATE TRIGGER %s AFTER INSERT ON t1 BEGIN SELECT 1; END;",
    "CREATE TRIGGER IF NOT EXISTS %s BEFORE UPDATE ON t1 BEGIN SELECT 1; END;",
    "CREATE TEMP TABLE %s (a, b);",
    "CREATE TEMPORARY VIEW %s AS SELECT 1;",

    /* DROP operations */
    "DROP TABLE IF EXISTS %s;",
    "DROP INDEX IF EXISTS %s;",
    "DROP VIEW IF EXISTS %s;",
    "DROP TRIGGER IF EXISTS %s;",

    /* Virtual tables */
    "CREATE VIRTUAL TABLE %s USING fts5(content);",
    "CREATE VIRTUAL TABLE IF NOT EXISTS %s USING rtree(id, x1, x2, y1, y2);",

    /* Complex ALTER sequences */
    "BEGIN; ALTER TABLE t1 ADD COLUMN %s; COMMIT;",
    "BEGIN; ALTER TABLE t1 RENAME COLUMN b TO %s; ROLLBACK;",
    "SAVEPOINT sp1; ALTER TABLE t1 ADD COLUMN %s TEXT; RELEASE sp1;",
};

static char *escape_identifier(const uint8_t *data, size_t size) {
    /* Make a valid SQL identifier from fuzz data */
    char *result = malloc(size + 3);
    if (!result) return NULL;

    result[0] = '"';
    size_t j = 1;
    for (size_t i = 0; i < size && j < size + 1; i++) {
        char c = data[i];
        if (c == '"') {
            result[j++] = '"';
            result[j++] = '"';
        } else if (c == '\0') {
            continue;
        } else {
            result[j++] = c;
        }
    }
    result[j++] = '"';
    result[j] = '\0';
    return result;
}

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    char *escaped = NULL;
    char *sql = NULL;

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 500000);
    sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 100000);
    sqlite3_limit(db, SQLITE_LIMIT_COLUMN, 100);

    /* Create base schema */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL, d BLOB, e);"
        "CREATE TABLE t2(x INTEGER, y TEXT, z);"
        "CREATE INDEX t1_idx ON t1(b);"
        "CREATE VIEW v1 AS SELECT * FROM t1;"
        "INSERT INTO t1 VALUES(1,'a',1.0,X'00',NULL);"
        "INSERT INTO t1 VALUES(2,'b',2.0,X'FF','x');"
        "INSERT INTO t2 VALUES(1,'y',100);",
        NULL, NULL, NULL);

    escaped = escape_identifier(data, size);
    if (!escaped) {
        sqlite3_close(db);
        return 0;
    }

    sql = malloc(strlen(escaped) + 500);
    if (!sql) {
        free(escaped);
        sqlite3_close(db);
        return 0;
    }

    size_t nTemplates = sizeof(azAlterSql) / sizeof(azAlterSql[0]);
    for (size_t i = 0; i < nTemplates; i++) {
        char *zErr = NULL;
        sprintf(sql, azAlterSql[i], escaped);
        nProgressCalls = 0;
        sqlite3_exec(db, sql, NULL, NULL, &zErr);
        sqlite3_free(zErr);
    }

    /* Also test raw ALTER with binding won't work, but test schema queries */
    sqlite3_exec(db, "SELECT * FROM sqlite_schema;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA table_info(t1);", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA index_list(t1);", NULL, NULL, NULL);
    sqlite3_exec(db, "SELECT sql FROM sqlite_schema WHERE type='table';", NULL, NULL, NULL);

    free(sql);
    free(escaped);
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
