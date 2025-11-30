/*
** SQLite Index/Constraint Fuzzer
**
** Tests index creation, partial indexes, expression indexes, unique constraints.
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

static const char *azIndexSql[] = {
    /* Basic indexes */
    "CREATE INDEX idx_a ON t1(a);",
    "CREATE INDEX idx_b ON t1(b);",
    "CREATE INDEX idx_c ON t1(c);",
    "CREATE INDEX idx_ab ON t1(a, b);",
    "CREATE INDEX idx_abc ON t1(a, b, c);",

    /* Unique indexes */
    "CREATE UNIQUE INDEX idx_uniq_b ON t2(b);",
    "CREATE UNIQUE INDEX idx_uniq_bc ON t2(b, c);",

    /* Partial indexes */
    "CREATE INDEX idx_partial_pos ON t1(a) WHERE a > 0;",
    "CREATE INDEX idx_partial_notnull ON t1(b) WHERE b IS NOT NULL;",
    "CREATE INDEX idx_partial_range ON t1(c) WHERE c BETWEEN 0 AND 100;",
    "CREATE INDEX idx_partial_like ON t1(b) WHERE b LIKE 'prefix%';",

    /* Expression indexes */
    "CREATE INDEX idx_expr_lower ON t1(lower(b));",
    "CREATE INDEX idx_expr_abs ON t1(abs(a));",
    "CREATE INDEX idx_expr_len ON t1(length(b));",
    "CREATE INDEX idx_expr_substr ON t1(substr(b, 1, 3));",
    "CREATE INDEX idx_expr_coalesce ON t1(coalesce(b, 'default'));",
    "CREATE INDEX idx_expr_math ON t1(a * 2 + 1);",

    /* Descending indexes */
    "CREATE INDEX idx_desc_a ON t1(a DESC);",
    "CREATE INDEX idx_mixed ON t1(a ASC, b DESC);",

    /* Collation indexes */
    "CREATE INDEX idx_nocase ON t1(b COLLATE NOCASE);",
    "CREATE INDEX idx_binary ON t1(b COLLATE BINARY);",

    /* Drop indexes */
    "DROP INDEX IF EXISTS idx_a;",
    "DROP INDEX IF EXISTS idx_b;",
    "DROP INDEX IF EXISTS idx_ab;",

    /* Reindex */
    "REINDEX idx_c;",
    "REINDEX t1;",
    "REINDEX;",

    /* Query using indexes */
    "SELECT * FROM t1 WHERE a = %d;",
    "SELECT * FROM t1 WHERE a > %d AND a < %d;",
    "SELECT * FROM t1 WHERE b = 'row%d';",
    "SELECT * FROM t1 WHERE a = %d AND b = 'row%d';",
    "SELECT * FROM t1 WHERE lower(b) = 'row%d';",
    "SELECT * FROM t1 ORDER BY a;",
    "SELECT * FROM t1 ORDER BY a DESC;",
    "SELECT * FROM t1 ORDER BY b COLLATE NOCASE;",

    /* Analyze for statistics */
    "ANALYZE t1;",
    "ANALYZE;",

    /* Insert/update/delete with indexed columns */
    "INSERT INTO t1 VALUES(%d, 'new%d', %d.0);",
    "UPDATE t1 SET a = %d WHERE a = 1;",
    "UPDATE t1 SET b = 'modified' WHERE a = %d;",
    "DELETE FROM t1 WHERE a = %d;",

    /* Unique constraint violations */
    "INSERT OR REPLACE INTO t2 VALUES(%d, 'dup', 0.0);",
    "INSERT OR IGNORE INTO t2 VALUES(%d, 'dup', 0.0);",

    /* Covering index queries */
    "SELECT a, b FROM t1 WHERE a > 0;",
    "SELECT count(*) FROM t1 WHERE a > 0;",
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

    /* Create tables */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER, b TEXT, c REAL);"
        "CREATE TABLE t2(a INTEGER PRIMARY KEY, b TEXT UNIQUE, c REAL);"
        "CREATE TABLE t3(x INTEGER, y INTEGER, z TEXT, UNIQUE(x, y));",
        NULL, NULL, NULL);

    /* Insert initial data */
    for (int i = 1; i <= 30; i++) {
        snprintf(sql, sizeof(sql), "INSERT INTO t1 VALUES(%d, 'row%d', %d.%d);",
                 i, i, i, i % 10);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }
    for (int i = 1; i <= 20; i++) {
        snprintf(sql, sizeof(sql), "INSERT INTO t2 VALUES(%d, 'unique%d', %d.0);",
                 i, i, i);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Execute index operations based on fuzz input */
    size_t nOps = sizeof(azIndexSql) / sizeof(azIndexSql[0]);
    for (size_t i = 0; i < size && i < 50; i++) {
        int opIdx = data[i] % nOps;
        int v1 = (i + 1 < size) ? data[i + 1] % 50 : 1;
        int v2 = (i + 2 < size) ? data[i + 2] % 50 + 1 : 10;

        snprintf(sql, sizeof(sql), azIndexSql[opIdx], v1, v2, v1);
        nProgressCalls = 0;
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Query plan analysis */
    sqlite3_exec(db, "EXPLAIN QUERY PLAN SELECT * FROM t1 WHERE a = 5;", NULL, NULL, NULL);
    sqlite3_exec(db, "EXPLAIN QUERY PLAN SELECT * FROM t1 WHERE b = 'row5';", NULL, NULL, NULL);

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
