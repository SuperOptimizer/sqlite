/*
** SQLite UPSERT/Conflict Resolution Fuzzer
**
** Tests INSERT OR REPLACE, ON CONFLICT clauses, UPSERT syntax.
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

static const size_t MAX_INPUT_LEN = 10000;

static const char *azUpsertSql[] = {
    /* INSERT OR REPLACE */
    "INSERT OR REPLACE INTO t1 VALUES(%d, 'replace%d', %d.0);",
    "INSERT OR REPLACE INTO t2 VALUES(%d, 'rep', X'%02X%02X');",

    /* INSERT OR IGNORE */
    "INSERT OR IGNORE INTO t1 VALUES(%d, 'ignore%d', %d.0);",
    "INSERT OR IGNORE INTO t2 VALUES(%d, 'ign', NULL);",

    /* INSERT OR ABORT */
    "INSERT OR ABORT INTO t1 VALUES(%d, 'abort%d', %d.0);",

    /* INSERT OR ROLLBACK */
    "INSERT OR ROLLBACK INTO t1 VALUES(%d, 'rollback%d', %d.0);",

    /* INSERT OR FAIL */
    "INSERT OR FAIL INTO t1 VALUES(%d, 'fail%d', %d.0);",

    /* UPSERT with ON CONFLICT DO NOTHING */
    "INSERT INTO t1 VALUES(%d, 'upsert%d', %d.0) ON CONFLICT DO NOTHING;",
    "INSERT INTO t2 VALUES(%d, 'up', NULL) ON CONFLICT DO NOTHING;",

    /* UPSERT with ON CONFLICT DO UPDATE */
    "INSERT INTO t1 VALUES(%d, 'val', 0.0) ON CONFLICT(a) DO UPDATE SET b = 'updated%d';",
    "INSERT INTO t1 VALUES(%d, 'val', 0.0) ON CONFLICT(a) DO UPDATE SET c = c + 1;",
    "INSERT INTO t1 VALUES(%d, 'val', 0.0) ON CONFLICT(a) DO UPDATE SET b = excluded.b;",

    /* UPSERT with WHERE clause */
    "INSERT INTO t1 VALUES(%d, 'cond', 0.0) ON CONFLICT(a) DO UPDATE SET b = 'cond%d' WHERE c < 100;",

    /* UPSERT on UNIQUE constraint */
    "INSERT INTO t3 VALUES(%d, 'unique%d') ON CONFLICT(name) DO NOTHING;",
    "INSERT INTO t3 VALUES(%d, 'unique%d') ON CONFLICT(name) DO UPDATE SET id = id + 1000;",

    /* Multi-column conflict */
    "INSERT INTO t4 VALUES(%d, %d, 'multi') ON CONFLICT(x, y) DO NOTHING;",
    "INSERT INTO t4 VALUES(%d, %d, 'multi') ON CONFLICT(x, y) DO UPDATE SET z = 'resolved';",

    /* UPDATE OR REPLACE */
    "UPDATE OR REPLACE t1 SET a = %d WHERE a = 1;",
    "UPDATE OR IGNORE t1 SET b = 'upd%d' WHERE a = %d;",
    "UPDATE OR ABORT t1 SET c = %d.0 WHERE a > 0;",

    /* DELETE and reinsert patterns */
    "DELETE FROM t1 WHERE a = %d;",
    "INSERT INTO t1 SELECT * FROM t1 WHERE a = %d ON CONFLICT DO NOTHING;",

    /* Batch inserts with conflict */
    "INSERT OR REPLACE INTO t1 SELECT %d, 'batch', 0.0 UNION ALL SELECT %d+1, 'batch', 1.0;",
};

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    char sql[512];

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Create tables with various constraints */
    sqlite3_exec(db,
        /* Primary key constraint */
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL);"

        /* Primary key + NOT NULL */
        "CREATE TABLE t2(id INTEGER PRIMARY KEY, name TEXT NOT NULL, data BLOB);"

        /* UNIQUE constraint */
        "CREATE TABLE t3(id INTEGER, name TEXT UNIQUE);"

        /* Multi-column UNIQUE */
        "CREATE TABLE t4(x INTEGER, y INTEGER, z TEXT, UNIQUE(x, y));"

        /* Composite primary key */
        "CREATE TABLE t5(a INTEGER, b INTEGER, c TEXT, PRIMARY KEY(a, b));"

        /* Check constraint */
        "CREATE TABLE t6(id INTEGER PRIMARY KEY, val INTEGER CHECK(val >= 0));"

        /* Initial data */
        "INSERT INTO t1 VALUES(1, 'one', 1.0);"
        "INSERT INTO t1 VALUES(2, 'two', 2.0);"
        "INSERT INTO t1 VALUES(3, 'three', 3.0);"
        "INSERT INTO t2 VALUES(1, 'first', X'01');"
        "INSERT INTO t2 VALUES(2, 'second', X'02');"
        "INSERT INTO t3 VALUES(1, 'unique1');"
        "INSERT INTO t3 VALUES(2, 'unique2');"
        "INSERT INTO t4 VALUES(1, 1, 'a');"
        "INSERT INTO t4 VALUES(1, 2, 'b');"
        "INSERT INTO t5 VALUES(1, 1, 'comp1');"
        "INSERT INTO t6 VALUES(1, 10);",
        NULL, NULL, NULL);

    /* Execute UPSERT operations based on fuzz input */
    size_t nOps = sizeof(azUpsertSql) / sizeof(azUpsertSql[0]);
    for (size_t i = 0; i < size && i < 50; i++) {
        int opIdx = data[i] % nOps;
        int v1 = (i + 1 < size) ? data[i + 1] % 20 : 1;
        int v2 = (i + 2 < size) ? data[i + 2] % 10 : 1;
        int v3 = (i + 3 < size) ? data[i + 3] % 100 : 1;

        snprintf(sql, sizeof(sql), azUpsertSql[opIdx], v1, v2, v3, v1);
        nProgressCalls = 0;
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Test transaction + conflict behavior */
    sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL);
    for (size_t i = 0; i < 5; i++) {
        int val = (i < size) ? data[i] % 10 : (int)i;
        snprintf(sql, sizeof(sql), "INSERT OR REPLACE INTO t1 VALUES(%d, 'txn', 0.0);", val);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }
    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);

    /* Verify integrity */
    sqlite3_exec(db, "PRAGMA integrity_check;", NULL, NULL, NULL);
    sqlite3_exec(db, "SELECT count(*) FROM t1;", NULL, NULL, NULL);

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
