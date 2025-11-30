/*
** SQLite Aggregate Functions Fuzzer
**
** Tests aggregate functions with various GROUP BY combinations,
** HAVING clauses, and edge cases.
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

/* Aggregate function templates */
static const char *azAggSql[] = {
    /* Basic aggregates */
    "SELECT count(*) FROM t1;",
    "SELECT count(a) FROM t1;",
    "SELECT count(DISTINCT b) FROM t1;",
    "SELECT sum(c) FROM t1;",
    "SELECT total(c) FROM t1;",
    "SELECT avg(c) FROM t1;",
    "SELECT min(c) FROM t1;",
    "SELECT max(c) FROM t1;",
    "SELECT group_concat(b) FROM t1;",
    "SELECT group_concat(b, ', ') FROM t1;",
    "SELECT group_concat(DISTINCT b) FROM t1;",

    /* Aggregates with GROUP BY */
    "SELECT cat, count(*) FROM t1 GROUP BY cat;",
    "SELECT cat, sum(c) FROM t1 GROUP BY cat;",
    "SELECT cat, avg(c), min(c), max(c) FROM t1 GROUP BY cat;",
    "SELECT cat, group_concat(b) FROM t1 GROUP BY cat;",
    "SELECT cat, count(DISTINCT b) FROM t1 GROUP BY cat;",

    /* GROUP BY with multiple columns */
    "SELECT cat, subcat, count(*) FROM t1 GROUP BY cat, subcat;",
    "SELECT cat, subcat, sum(c) FROM t1 GROUP BY 1, 2;",
    "SELECT cat, subcat, avg(c) FROM t1 GROUP BY cat, subcat ORDER BY 3 DESC;",

    /* GROUP BY with expressions */
    "SELECT a %% %s, count(*) FROM t1 GROUP BY a %% %s;",
    "SELECT substr(b, 1, 1), count(*) FROM t1 GROUP BY substr(b, 1, 1);",
    "SELECT cast(c AS INTEGER), count(*) FROM t1 GROUP BY cast(c AS INTEGER);",
    "SELECT c > %s, count(*) FROM t1 GROUP BY c > %s;",

    /* HAVING clause */
    "SELECT cat, count(*) FROM t1 GROUP BY cat HAVING count(*) > %s;",
    "SELECT cat, sum(c) FROM t1 GROUP BY cat HAVING sum(c) > %s;",
    "SELECT cat, avg(c) FROM t1 GROUP BY cat HAVING avg(c) < %s;",
    "SELECT cat, count(*) AS cnt FROM t1 GROUP BY cat HAVING cnt > %s;",
    "SELECT cat, sum(c) FROM t1 GROUP BY cat HAVING sum(c) BETWEEN %s AND 1000;",

    /* Nested aggregates (in subqueries) */
    "SELECT * FROM (SELECT cat, count(*) AS cnt FROM t1 GROUP BY cat) WHERE cnt > %s;",
    "SELECT cat, (SELECT count(*) FROM t1 AS t2 WHERE t2.cat = t1.cat) FROM t1 GROUP BY cat;",
    "SELECT max(sub.cnt) FROM (SELECT cat, count(*) AS cnt FROM t1 GROUP BY cat) AS sub;",

    /* Aggregates with DISTINCT */
    "SELECT count(DISTINCT cat) FROM t1;",
    "SELECT sum(DISTINCT c) FROM t1;",
    "SELECT avg(DISTINCT c) FROM t1;",
    "SELECT group_concat(DISTINCT cat) FROM t1;",

    /* Aggregates with FILTER */
    "SELECT count(*) FILTER (WHERE cat = 'A') FROM t1;",
    "SELECT sum(c) FILTER (WHERE c > %s) FROM t1;",
    "SELECT cat, count(*) FILTER (WHERE c > %s) FROM t1 GROUP BY cat;",
    "SELECT avg(c) FILTER (WHERE b LIKE '%s%%') FROM t1;",

    /* Aggregates with ORDER BY in group_concat */
    "SELECT group_concat(b ORDER BY c) FROM t1;",
    "SELECT group_concat(b ORDER BY c DESC) FROM t1;",
    "SELECT cat, group_concat(b ORDER BY c, ', ') FROM t1 GROUP BY cat;",

    /* Complex aggregate expressions */
    "SELECT sum(c * %s) FROM t1;",
    "SELECT avg(c + %s) FROM t1;",
    "SELECT sum(c) / count(*) FROM t1;",
    "SELECT max(c) - min(c) FROM t1;",
    "SELECT count(*) * avg(c) FROM t1;",

    /* Aggregates with CASE */
    "SELECT sum(CASE WHEN cat='A' THEN c ELSE 0 END) FROM t1;",
    "SELECT count(CASE WHEN c > %s THEN 1 END) FROM t1;",
    "SELECT cat, sum(CASE WHEN c > %s THEN c ELSE 0 END) FROM t1 GROUP BY cat;",

    /* Aggregates with NULL handling */
    "SELECT count(d) FROM t1;",
    "SELECT sum(d) FROM t1;",
    "SELECT coalesce(sum(d), 0) FROM t1;",
    "SELECT count(*), count(d) FROM t1;",

    /* Aggregates with JOIN */
    "SELECT t1.cat, count(*) FROM t1 JOIN t2 ON t1.a = t2.fk GROUP BY t1.cat;",
    "SELECT t1.cat, sum(t2.val) FROM t1 LEFT JOIN t2 ON t1.a = t2.fk GROUP BY t1.cat;",

    /* Aggregates in UNION */
    "SELECT 'A' AS src, count(*) FROM t1 WHERE cat='A' UNION ALL SELECT 'B', count(*) FROM t1 WHERE cat='B';",

    /* GROUP BY ROLLUP simulation */
    "SELECT cat, sum(c) FROM t1 GROUP BY cat UNION ALL SELECT NULL, sum(c) FROM t1;",

    /* Aggregates with LIMIT */
    "SELECT cat, count(*) FROM t1 GROUP BY cat ORDER BY 2 DESC LIMIT %s;",
    "SELECT cat, sum(c) FROM t1 GROUP BY cat HAVING sum(c) > 0 LIMIT %s OFFSET 1;",

    /* Statistical aggregates (if available) */
    "SELECT typeof(avg(c)), typeof(sum(c)), typeof(total(c)) FROM t1;",
    "SELECT min(b), max(b) FROM t1;",

    /* Empty result handling */
    "SELECT count(*) FROM t1 WHERE 0;",
    "SELECT sum(c) FROM t1 WHERE 0;",
    "SELECT avg(c) FROM t1 WHERE cat = 'nonexistent';",
};

static char *make_safe_number(const uint8_t *data, size_t size) {
    char *result = malloc(16);
    if (!result) return NULL;
    if (size == 0) {
        strcpy(result, "5");
        return result;
    }
    int val = (data[0] % 20) + 1;
    snprintf(result, 16, "%d", val);
    return result;
}

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    char *num = NULL;
    char *sql = NULL;

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Create test tables with varied data */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL, d INTEGER, cat TEXT, subcat TEXT);"
        "INSERT INTO t1 VALUES(1,'alpha',10.5,100,'A','x');"
        "INSERT INTO t1 VALUES(2,'beta',20.3,NULL,'A','y');"
        "INSERT INTO t1 VALUES(3,'gamma',15.7,300,'B','x');"
        "INSERT INTO t1 VALUES(4,'delta',25.1,NULL,'B','y');"
        "INSERT INTO t1 VALUES(5,'epsilon',12.9,500,'A','x');"
        "INSERT INTO t1 VALUES(6,'zeta',30.0,600,'C','z');"
        "INSERT INTO t1 VALUES(7,'eta',18.4,NULL,'B','x');"
        "INSERT INTO t1 VALUES(8,'theta',22.6,800,'C','y');"
        "INSERT INTO t1 VALUES(9,'iota',8.2,900,'A','z');"
        "INSERT INTO t1 VALUES(10,'kappa',35.8,NULL,'C','x');"
        "CREATE TABLE t2(id INTEGER PRIMARY KEY, fk INTEGER, val REAL);"
        "INSERT INTO t2 VALUES(1,1,100.0);"
        "INSERT INTO t2 VALUES(2,1,200.0);"
        "INSERT INTO t2 VALUES(3,3,300.0);"
        "INSERT INTO t2 VALUES(4,5,400.0);"
        "INSERT INTO t2 VALUES(5,7,500.0);",
        NULL, NULL, NULL);

    num = make_safe_number(data, size);
    if (!num) {
        sqlite3_close(db);
        return 0;
    }

    sql = malloc(512);
    if (!sql) {
        free(num);
        sqlite3_close(db);
        return 0;
    }

    size_t nTemplates = sizeof(azAggSql) / sizeof(azAggSql[0]);
    for (size_t i = 0; i < nTemplates; i++) {
        nProgressCalls = 0;
        snprintf(sql, 512, azAggSql[i], num, num, num, num);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Fuzz-driven GROUP BY column selection */
    if (size >= 1) {
        const char *cols[] = {"cat", "subcat", "cat, subcat", "a % 3"};
        int idx = data[0] % 4;
        snprintf(sql, 512, "SELECT %s, count(*), sum(c) FROM t1 GROUP BY %s;", cols[idx], cols[idx]);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    free(sql);
    free(num);
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
