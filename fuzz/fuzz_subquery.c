/*
** SQLite Subquery Fuzzer
**
** Tests correlated subqueries, scalar subqueries, EXISTS, IN subqueries.
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

static const char *azSubquerySql[] = {
    /* Scalar subqueries */
    "SELECT a, (SELECT max(x) FROM t2) FROM t1;",
    "SELECT a, (SELECT count(*) FROM t2 WHERE x = t1.a) FROM t1;",
    "SELECT (SELECT b FROM t1 WHERE a = 1) AS first_b;",
    "SELECT a, b, (SELECT sum(x) FROM t2) / (SELECT count(*) FROM t2) FROM t1;",

    /* Correlated subqueries */
    "SELECT * FROM t1 WHERE a = (SELECT max(x) FROM t2 WHERE y LIKE t1.b);",
    "SELECT a, (SELECT y FROM t2 WHERE x = t1.a LIMIT 1) FROM t1;",
    "SELECT * FROM t1 outer_t WHERE c > (SELECT avg(c) FROM t1 WHERE b = outer_t.b);",

    /* EXISTS subqueries */
    "SELECT * FROM t1 WHERE EXISTS (SELECT 1 FROM t2 WHERE x = t1.a);",
    "SELECT * FROM t1 WHERE NOT EXISTS (SELECT 1 FROM t2 WHERE x = t1.a);",
    "SELECT a FROM t1 WHERE EXISTS (SELECT 1 FROM t2 WHERE y = 'data' AND x > t1.a);",

    /* IN subqueries */
    "SELECT * FROM t1 WHERE a IN (SELECT x FROM t2);",
    "SELECT * FROM t1 WHERE a NOT IN (SELECT x FROM t2 WHERE y IS NOT NULL);",
    "SELECT * FROM t1 WHERE b IN (SELECT y FROM t2);",
    "SELECT * FROM t2 WHERE x IN (SELECT a FROM t1 WHERE c > 0);",

    /* Subquery in FROM clause (derived table) */
    "SELECT * FROM (SELECT a, b FROM t1 WHERE c > 0) AS derived;",
    "SELECT d.a, t2.y FROM (SELECT * FROM t1) AS d JOIN t2 ON d.a = t2.x;",
    "SELECT * FROM (SELECT a, count(*) as cnt FROM t1 GROUP BY a) WHERE cnt > 0;",

    /* Subquery with aggregates */
    "SELECT * FROM t1 WHERE a > (SELECT avg(x) FROM t2);",
    "SELECT * FROM t1 WHERE c = (SELECT max(c) FROM t1);",
    "SELECT a, (SELECT group_concat(y) FROM t2 WHERE x <= t1.a) FROM t1;",

    /* Nested subqueries */
    "SELECT * FROM t1 WHERE a IN (SELECT x FROM t2 WHERE y IN (SELECT b FROM t1));",
    "SELECT (SELECT (SELECT max(a) FROM t1)) AS deep;",
    "SELECT * FROM t1 WHERE a = (SELECT x FROM t2 WHERE x = (SELECT min(a) FROM t1));",

    /* Subquery with UNION */
    "SELECT * FROM t1 WHERE a IN (SELECT x FROM t2 UNION SELECT a FROM t1);",
    "SELECT * FROM (SELECT a, b FROM t1 UNION ALL SELECT x, y FROM t2);",

    /* Subquery in CASE */
    "SELECT a, CASE WHEN a IN (SELECT x FROM t2) THEN 'yes' ELSE 'no' END FROM t1;",
    "SELECT CASE (SELECT count(*) FROM t2) WHEN 0 THEN 'empty' ELSE 'has data' END;",

    /* Subquery with ORDER BY/LIMIT */
    "SELECT * FROM t1 WHERE a = (SELECT x FROM t2 ORDER BY x LIMIT 1);",
    "SELECT * FROM t1 WHERE a IN (SELECT x FROM t2 ORDER BY y LIMIT 5);",

    /* Subquery with DISTINCT */
    "SELECT * FROM t1 WHERE b IN (SELECT DISTINCT y FROM t2);",
    "SELECT DISTINCT (SELECT max(x) FROM t2) FROM t1;",

    /* Subquery in UPDATE */
    "UPDATE t1 SET c = (SELECT avg(x) FROM t2) WHERE a > 0;",
    "UPDATE t1 SET b = (SELECT y FROM t2 WHERE x = t1.a LIMIT 1) WHERE a IN (SELECT x FROM t2);",

    /* Subquery in DELETE */
    "DELETE FROM t1 WHERE a IN (SELECT x FROM t2 WHERE y IS NULL);",
    "DELETE FROM t2 WHERE x NOT IN (SELECT a FROM t1);",

    /* Subquery in INSERT */
    "INSERT INTO t1 SELECT x, y, 0.0 FROM t2 WHERE x NOT IN (SELECT a FROM t1);",
    "INSERT INTO t2 SELECT a, b FROM t1 WHERE a > (SELECT avg(x) FROM t2);",

    /* Complex correlated */
    "SELECT * FROM t1 o WHERE a > ALL (SELECT x FROM t2 WHERE y < o.b);",
    "SELECT * FROM t1 WHERE c >= (SELECT max(c) FROM t1 i WHERE i.b = t1.b);",

    /* Lateral-style (using outer reference in derived table - limited support) */
    "SELECT t1.a, sub.cnt FROM t1, (SELECT count(*) as cnt FROM t2 WHERE x = t1.a) AS sub;",
};

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    char sql[256];

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Create schema with indexed tables for subquery optimization testing */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL);"
        "CREATE TABLE t2(x INTEGER PRIMARY KEY, y TEXT);"
        "CREATE TABLE t3(id INTEGER, parent_id INTEGER, name TEXT);"
        "CREATE INDEX idx_t1_b ON t1(b);"
        "CREATE INDEX idx_t1_c ON t1(c);"
        "CREATE INDEX idx_t2_y ON t2(y);"
        "CREATE INDEX idx_t3_parent ON t3(parent_id);",
        NULL, NULL, NULL);

    /* Insert test data */
    for (int i = 1; i <= 20; i++) {
        snprintf(sql, sizeof(sql), "INSERT INTO t1 VALUES(%d, 'row%d', %d.%d);",
                 i, i % 5, i, i % 10);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }
    for (int i = 1; i <= 15; i++) {
        snprintf(sql, sizeof(sql), "INSERT INTO t2 VALUES(%d, '%s');",
                 i, (i % 3 == 0) ? "data" : "other");
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }
    for (int i = 1; i <= 10; i++) {
        snprintf(sql, sizeof(sql), "INSERT INTO t3 VALUES(%d, %d, 'node%d');",
                 i, (i > 1) ? (i / 2) : 0, i);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Execute subquery operations based on fuzz input */
    size_t nOps = sizeof(azSubquerySql) / sizeof(azSubquerySql[0]);
    for (size_t i = 0; i < size && i < 40; i++) {
        int opIdx = data[i] % nOps;
        nProgressCalls = 0;
        sqlite3_exec(db, azSubquerySql[opIdx], NULL, NULL, NULL);
    }

    /* EXPLAIN QUERY PLAN to exercise optimizer */
    for (size_t i = 0; i < 5 && i < size; i++) {
        int opIdx = data[i] % nOps;
        snprintf(sql, sizeof(sql), "EXPLAIN QUERY PLAN %s", azSubquerySql[opIdx]);
        nProgressCalls = 0;
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Verify state */
    sqlite3_exec(db, "SELECT count(*) FROM t1;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA integrity_check;", NULL, NULL, NULL);

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
