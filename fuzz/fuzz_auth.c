/*
** SQLite Authorization Fuzzer
**
** Tests sqlite3_set_authorizer callback for access control decisions.
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

/* Fuzz-controlled authorizer */
static const uint8_t *g_fuzz_data = NULL;
static size_t g_fuzz_size = 0;
static size_t g_fuzz_idx = 0;

static int auth_callback(void *pUserData, int action, const char *z1,
                         const char *z2, const char *z3, const char *z4) {
    (void)pUserData;
    (void)z1; (void)z2; (void)z3; (void)z4;

    /* Get next fuzz byte to decide authorization */
    if (g_fuzz_idx < g_fuzz_size) {
        int decision = g_fuzz_data[g_fuzz_idx++] % 4;
        switch (decision) {
            case 0: return SQLITE_OK;      /* Allow */
            case 1: return SQLITE_DENY;    /* Deny with error */
            case 2: return SQLITE_IGNORE;  /* Silently ignore (NULL result) */
            default: return SQLITE_OK;
        }
    }
    return SQLITE_OK;
}

static const char *azAuthSql[] = {
    /* SELECT operations */
    "SELECT * FROM t1;",
    "SELECT a, b FROM t1 WHERE c > 0;",
    "SELECT count(*) FROM t1;",
    "SELECT * FROM t1, t2 WHERE t1.a = t2.x;",

    /* INSERT operations */
    "INSERT INTO t1 VALUES(100, 'auth', 0.0);",
    "INSERT INTO t2 VALUES(100, 'test');",
    "INSERT INTO t1 SELECT * FROM t1 WHERE a < 5;",

    /* UPDATE operations */
    "UPDATE t1 SET b = 'modified' WHERE a = 1;",
    "UPDATE t1 SET c = c + 1;",
    "UPDATE t2 SET y = 'changed' WHERE x > 5;",

    /* DELETE operations */
    "DELETE FROM t1 WHERE a = 1;",
    "DELETE FROM t2 WHERE x > 10;",

    /* CREATE operations */
    "CREATE TABLE t3(id INTEGER PRIMARY KEY, val TEXT);",
    "CREATE INDEX idx_t1_b ON t1(b);",
    "CREATE VIEW v1 AS SELECT * FROM t1;",
    "CREATE TRIGGER tr1 AFTER INSERT ON t1 BEGIN SELECT 1; END;",

    /* DROP operations */
    "DROP TABLE IF EXISTS t3;",
    "DROP INDEX IF EXISTS idx_t1_b;",
    "DROP VIEW IF EXISTS v1;",
    "DROP TRIGGER IF EXISTS tr1;",

    /* ALTER operations */
    "ALTER TABLE t1 ADD COLUMN d INTEGER;",
    "ALTER TABLE t1 RENAME TO t1_renamed;",
    "ALTER TABLE t1_renamed RENAME TO t1;",

    /* PRAGMA operations */
    "PRAGMA table_info(t1);",
    "PRAGMA index_list(t1);",
    "PRAGMA foreign_key_list(t1);",
    "PRAGMA integrity_check;",

    /* Transaction operations */
    "BEGIN;",
    "COMMIT;",
    "ROLLBACK;",
    "SAVEPOINT sp1;",
    "RELEASE sp1;",

    /* Function calls */
    "SELECT abs(-5);",
    "SELECT length('test');",
    "SELECT substr('hello', 1, 3);",
    "SELECT printf('%d', 42);",

    /* Attach/Detach */
    "ATTACH ':memory:' AS aux;",
    "DETACH aux;",

    /* Aggregate functions */
    "SELECT sum(a), avg(a), max(a), min(a) FROM t1;",
    "SELECT group_concat(b) FROM t1;",

    /* Subqueries */
    "SELECT * FROM t1 WHERE a IN (SELECT x FROM t2);",
    "SELECT (SELECT max(a) FROM t1) AS max_a;",
};

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    char sql[256];

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    /* Set up global fuzz state for authorizer */
    g_fuzz_data = data;
    g_fuzz_size = size;
    g_fuzz_idx = 0;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Create initial schema before setting authorizer */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL);"
        "CREATE TABLE t2(x INTEGER PRIMARY KEY, y TEXT);"
        "INSERT INTO t1 VALUES(1, 'one', 1.0);"
        "INSERT INTO t1 VALUES(2, 'two', 2.0);"
        "INSERT INTO t1 VALUES(3, 'three', 3.0);"
        "INSERT INTO t2 VALUES(1, 'x');"
        "INSERT INTO t2 VALUES(2, 'y');",
        NULL, NULL, NULL);

    /* Set authorizer */
    sqlite3_set_authorizer(db, auth_callback, NULL);

    /* Execute SQL with authorization checks */
    size_t nOps = sizeof(azAuthSql) / sizeof(azAuthSql[0]);
    for (size_t i = 0; i < size && i < 30; i++) {
        int opIdx = data[i] % nOps;
        nProgressCalls = 0;
        sqlite3_exec(db, azAuthSql[opIdx], NULL, NULL, NULL);
    }

    /* Clear authorizer and verify state */
    sqlite3_set_authorizer(db, NULL, NULL);
    sqlite3_exec(db, "SELECT count(*) FROM t1;", NULL, NULL, NULL);

    /* Re-enable authorizer with different pattern */
    g_fuzz_idx = size / 2;  /* Start from middle of fuzz data */
    sqlite3_set_authorizer(db, auth_callback, NULL);

    /* Try more operations */
    for (size_t i = 0; i < 10 && i < size; i++) {
        int v = data[i] % 20;
        snprintf(sql, sizeof(sql), "INSERT INTO t1 VALUES(%d, 'test%zu', 0.0);", 200 + v, i);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    sqlite3_set_authorizer(db, NULL, NULL);
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
