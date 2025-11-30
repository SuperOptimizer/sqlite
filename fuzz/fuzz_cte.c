/*
** SQLite Common Table Expression (CTE) Fuzzer
**
** Tests WITH clauses including recursive CTEs which exercise
** complex query planning and execution paths.
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

/* CTE templates */
static const char *azCteSql[] = {
    /* Simple CTEs */
    "WITH cte AS (SELECT %s AS x) SELECT * FROM cte;",
    "WITH cte(a,b) AS (SELECT 1, 2) SELECT a+%s, b FROM cte;",
    "WITH cte AS (SELECT * FROM t1 WHERE a < %s) SELECT * FROM cte;",

    /* Multiple CTEs */
    "WITH c1 AS (SELECT %s), c2 AS (SELECT * FROM c1) SELECT * FROM c2;",
    "WITH c1 AS (SELECT a FROM t1), c2 AS (SELECT b FROM t1) SELECT * FROM c1, c2 LIMIT %s;",
    "WITH c1 AS (SELECT 1 AS x), c2 AS (SELECT 2 AS y), c3 AS (SELECT 3 AS z) SELECT * FROM c1, c2, c3;",

    /* CTE with JOIN */
    "WITH cte AS (SELECT * FROM t1) SELECT cte.*, t2.y FROM cte JOIN t2 ON cte.a = t2.x LIMIT %s;",
    "WITH cte AS (SELECT a, b FROM t1 WHERE a < %s) SELECT * FROM cte LEFT JOIN t2 ON cte.a = t2.x;",

    /* Recursive CTEs */
    "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x < %s) SELECT * FROM cnt;",
    "WITH RECURSIVE cnt(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM cnt WHERE x < %s) SELECT sum(x) FROM cnt;",

    /* Recursive with multiple columns */
    "WITH RECURSIVE r(a,b,c) AS (SELECT 1,1,1 UNION ALL SELECT a+1,b+a,c+b FROM r WHERE a < %s) SELECT * FROM r;",

    /* Recursive tree traversal pattern */
    "WITH RECURSIVE tree(id, path, level) AS ("
    "  SELECT a, CAST(a AS TEXT), 0 FROM t1 WHERE a = 1 "
    "  UNION ALL "
    "  SELECT t1.a, tree.path || '/' || t1.a, tree.level + 1 "
    "  FROM t1, tree WHERE t1.a = tree.id + 1 AND tree.level < %s"
    ") SELECT * FROM tree;",

    /* Recursive with aggregates */
    "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r WHERE n < %s) "
    "SELECT count(*), sum(n), avg(n) FROM r;",

    /* CTE in subquery */
    "SELECT * FROM t1 WHERE a IN (WITH cte AS (SELECT %s) SELECT * FROM cte);",
    "SELECT (WITH cte AS (SELECT count(*) AS c FROM t1) SELECT c FROM cte) AS cnt;",

    /* CTE with UNION/INTERSECT/EXCEPT */
    "WITH cte AS (SELECT a FROM t1 UNION SELECT x FROM t2) SELECT * FROM cte LIMIT %s;",
    "WITH cte AS (SELECT a FROM t1 INTERSECT SELECT x FROM t2) SELECT count(*) FROM cte;",
    "WITH cte AS (SELECT a FROM t1 EXCEPT SELECT x FROM t2) SELECT * FROM cte;",

    /* CTE in INSERT/UPDATE/DELETE */
    "WITH cte AS (SELECT %s AS v) INSERT INTO t1(a, b, c) SELECT v, 'cte', 0.0 FROM cte;",
    "WITH cte AS (SELECT max(a)+1 AS next FROM t1) UPDATE t1 SET c = (SELECT next FROM cte) WHERE a = 1;",

    /* Materialized hint (SQLite 3.35+) */
    "WITH cte AS MATERIALIZED (SELECT * FROM t1 WHERE a < %s) SELECT * FROM cte, cte AS c2;",
    "WITH cte AS NOT MATERIALIZED (SELECT * FROM t1) SELECT * FROM cte WHERE a < %s;",

    /* Complex recursive: Fibonacci */
    "WITH RECURSIVE fib(a, b) AS ("
    "  SELECT 0, 1 UNION ALL SELECT b, a+b FROM fib WHERE b < %s"
    ") SELECT a FROM fib;",

    /* Recursive with ORDER BY */
    "WITH RECURSIVE r(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM r WHERE x < %s) "
    "SELECT * FROM r ORDER BY x DESC;",

    /* CTE referencing another CTE */
    "WITH c1 AS (SELECT a FROM t1 WHERE a < %s), "
    "     c2 AS (SELECT * FROM c1 WHERE a > 0) "
    "SELECT * FROM c2;",

    /* Deeply nested CTE */
    "WITH c1 AS (SELECT 1 AS x), "
    "     c2 AS (SELECT x+1 FROM c1), "
    "     c3 AS (SELECT x+1 FROM c2), "
    "     c4 AS (SELECT x+1 FROM c3) "
    "SELECT * FROM c4 WHERE x < %s;",

    /* CTE with window functions */
    "WITH cte AS (SELECT a, row_number() OVER (ORDER BY a) AS rn FROM t1) "
    "SELECT * FROM cte WHERE rn < %s;",

    /* CTE with GROUP BY */
    "WITH cte AS (SELECT cat, count(*) AS cnt FROM t1 GROUP BY cat) "
    "SELECT * FROM cte WHERE cnt > %s;",
};

static char *make_safe_limit(const uint8_t *data, size_t size) {
    char *result = malloc(16);
    if (!result) return NULL;
    if (size == 0) {
        strcpy(result, "10");
        return result;
    }
    /* Keep limit small to avoid infinite recursion */
    int val = (data[0] % 50) + 1;
    snprintf(result, 16, "%d", val);
    return result;
}

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    char *limit = NULL;
    char *sql = NULL;

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Set strict recursion limit */
    sqlite3_limit(db, SQLITE_LIMIT_COMPOUND_SELECT, 50);

    /* Create test tables */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL, cat TEXT);"
        "INSERT INTO t1 VALUES(1,'one',1.0,'A');"
        "INSERT INTO t1 VALUES(2,'two',2.0,'A');"
        "INSERT INTO t1 VALUES(3,'three',3.0,'B');"
        "INSERT INTO t1 VALUES(4,'four',4.0,'B');"
        "INSERT INTO t1 VALUES(5,'five',5.0,'A');"
        "INSERT INTO t1 VALUES(6,'six',6.0,'C');"
        "INSERT INTO t1 VALUES(7,'seven',7.0,'B');"
        "INSERT INTO t1 VALUES(8,'eight',8.0,'C');"
        "CREATE TABLE t2(x INTEGER PRIMARY KEY, y TEXT);"
        "INSERT INTO t2 VALUES(1,'alpha');"
        "INSERT INTO t2 VALUES(3,'gamma');"
        "INSERT INTO t2 VALUES(5,'epsilon');",
        NULL, NULL, NULL);

    limit = make_safe_limit(data, size);
    if (!limit) {
        sqlite3_close(db);
        return 0;
    }

    sql = malloc(1024);
    if (!sql) {
        free(limit);
        sqlite3_close(db);
        return 0;
    }

    size_t nTemplates = sizeof(azCteSql) / sizeof(azCteSql[0]);
    for (size_t i = 0; i < nTemplates; i++) {
        nProgressCalls = 0;
        snprintf(sql, 1024, azCteSql[i], limit);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    free(sql);
    free(limit);
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
