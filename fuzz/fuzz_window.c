/*
** SQLite Window Functions Fuzzer
**
** Tests window functions which involve complex query planning
** and execution paths.
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

/* Window function templates */
static const char *azWindowSql[] = {
    /* Basic window functions */
    "SELECT a, row_number() OVER (ORDER BY %s) FROM t1;",
    "SELECT a, rank() OVER (ORDER BY %s) FROM t1;",
    "SELECT a, dense_rank() OVER (ORDER BY %s) FROM t1;",
    "SELECT a, ntile(%s) OVER (ORDER BY a) FROM t1;",
    "SELECT a, percent_rank() OVER (ORDER BY %s) FROM t1;",
    "SELECT a, cume_dist() OVER (ORDER BY %s) FROM t1;",

    /* Aggregate window functions */
    "SELECT a, sum(c) OVER (ORDER BY %s) FROM t1;",
    "SELECT a, avg(c) OVER (ORDER BY %s) FROM t1;",
    "SELECT a, count(*) OVER (ORDER BY %s) FROM t1;",
    "SELECT a, min(c) OVER (ORDER BY %s) FROM t1;",
    "SELECT a, max(c) OVER (ORDER BY %s) FROM t1;",
    "SELECT a, total(c) OVER (ORDER BY %s) FROM t1;",
    "SELECT a, group_concat(b) OVER (ORDER BY %s) FROM t1;",

    /* Window with PARTITION BY */
    "SELECT a, sum(c) OVER (PARTITION BY %s ORDER BY a) FROM t1;",
    "SELECT a, row_number() OVER (PARTITION BY %s) FROM t1;",
    "SELECT a, rank() OVER (PARTITION BY %s ORDER BY c DESC) FROM t1;",
    "SELECT a, avg(c) OVER (PARTITION BY %s ORDER BY a) FROM t1;",

    /* Window with frame specifications */
    "SELECT a, sum(c) OVER (ORDER BY a ROWS BETWEEN %s PRECEDING AND CURRENT ROW) FROM t1;",
    "SELECT a, sum(c) OVER (ORDER BY a ROWS BETWEEN CURRENT ROW AND %s FOLLOWING) FROM t1;",
    "SELECT a, sum(c) OVER (ORDER BY a ROWS BETWEEN UNBOUNDED PRECEDING AND %s FOLLOWING) FROM t1;",
    "SELECT a, sum(c) OVER (ORDER BY a ROWS BETWEEN %s PRECEDING AND UNBOUNDED FOLLOWING) FROM t1;",
    "SELECT a, sum(c) OVER (ORDER BY a ROWS %s PRECEDING) FROM t1;",

    /* RANGE frame */
    "SELECT a, sum(c) OVER (ORDER BY a RANGE BETWEEN %s PRECEDING AND CURRENT ROW) FROM t1;",
    "SELECT a, sum(c) OVER (ORDER BY a RANGE BETWEEN CURRENT ROW AND %s FOLLOWING) FROM t1;",
    "SELECT a, sum(c) OVER (ORDER BY a RANGE UNBOUNDED PRECEDING) FROM t1;",

    /* GROUPS frame */
    "SELECT a, sum(c) OVER (ORDER BY a GROUPS BETWEEN %s PRECEDING AND CURRENT ROW) FROM t1;",
    "SELECT a, sum(c) OVER (ORDER BY a GROUPS %s PRECEDING) FROM t1;",

    /* EXCLUDE clause */
    "SELECT a, sum(c) OVER (ORDER BY a ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING EXCLUDE CURRENT ROW) FROM t1;",
    "SELECT a, sum(c) OVER (ORDER BY a ROWS BETWEEN 2 PRECEDING AND 2 FOLLOWING EXCLUDE GROUP) FROM t1;",
    "SELECT a, sum(c) OVER (ORDER BY a ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING EXCLUDE TIES) FROM t1;",
    "SELECT a, sum(c) OVER (ORDER BY a ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING EXCLUDE NO OTHERS) FROM t1;",

    /* first_value/last_value/nth_value */
    "SELECT a, first_value(b) OVER (ORDER BY %s) FROM t1;",
    "SELECT a, last_value(b) OVER (ORDER BY %s ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) FROM t1;",
    "SELECT a, nth_value(b, %s) OVER (ORDER BY a) FROM t1;",

    /* lead/lag */
    "SELECT a, lag(b, %s) OVER (ORDER BY a) FROM t1;",
    "SELECT a, lead(b, %s) OVER (ORDER BY a) FROM t1;",
    "SELECT a, lag(b, %s, 'default') OVER (ORDER BY a) FROM t1;",
    "SELECT a, lead(b, 1, %s) OVER (ORDER BY a) FROM t1;",

    /* Named windows */
    "SELECT a, sum(c) OVER win FROM t1 WINDOW win AS (ORDER BY %s);",
    "SELECT a, sum(c) OVER win, avg(c) OVER win FROM t1 WINDOW win AS (ORDER BY %s);",
    "SELECT a, sum(c) OVER win1, avg(c) OVER win2 FROM t1 WINDOW win1 AS (ORDER BY a), win2 AS (ORDER BY %s);",

    /* Multiple windows */
    "SELECT a, sum(c) OVER (ORDER BY a), avg(c) OVER (ORDER BY %s DESC) FROM t1;",
    "SELECT a, row_number() OVER (ORDER BY a), rank() OVER (ORDER BY %s) FROM t1;",

    /* Window in subquery */
    "SELECT * FROM (SELECT a, row_number() OVER (ORDER BY %s) AS rn FROM t1) WHERE rn < 5;",
    "SELECT * FROM (SELECT a, sum(c) OVER (ORDER BY a) AS running FROM t1) WHERE running > %s;",

    /* Window with FILTER */
    "SELECT a, sum(c) FILTER (WHERE a > %s) OVER (ORDER BY a) FROM t1;",
    "SELECT a, count(*) FILTER (WHERE b LIKE '%s%%') OVER () FROM t1;",

    /* Complex expressions in window */
    "SELECT a, sum(c * %s) OVER (ORDER BY a) FROM t1;",
    "SELECT a, avg(c + %s) OVER (PARTITION BY a %% 2 ORDER BY a) FROM t1;",
};

static char *make_safe_value(const uint8_t *data, size_t size) {
    char *result = malloc(32);
    if (!result) return NULL;

    if (size == 0) {
        strcpy(result, "1");
        return result;
    }

    /* Create small positive number for frame specs */
    int val = (data[0] % 10) + 1;
    snprintf(result, 32, "%d", val);
    return result;
}

static char *make_column_ref(const uint8_t *data, size_t size) {
    static const char *cols[] = {"a", "b", "c", "d", "a DESC", "c DESC", "b ASC", "a, b"};
    if (size == 0) return strdup("a");
    int idx = data[0] % (sizeof(cols)/sizeof(cols[0]));
    return strdup(cols[idx]);
}

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    char *val = NULL;
    char *col = NULL;
    char *sql = NULL;

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Create test table with data */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL, d BLOB);"
        "INSERT INTO t1 VALUES(1,'alpha',10.5,X'01');"
        "INSERT INTO t1 VALUES(2,'beta',20.3,X'02');"
        "INSERT INTO t1 VALUES(3,'gamma',15.7,X'03');"
        "INSERT INTO t1 VALUES(4,'delta',25.1,X'04');"
        "INSERT INTO t1 VALUES(5,'epsilon',12.9,X'05');"
        "INSERT INTO t1 VALUES(6,'zeta',30.0,X'06');"
        "INSERT INTO t1 VALUES(7,'eta',18.4,X'07');"
        "INSERT INTO t1 VALUES(8,'theta',22.6,X'08');"
        "INSERT INTO t1 VALUES(9,'iota',8.2,X'09');"
        "INSERT INTO t1 VALUES(10,'kappa',35.8,X'0A');",
        NULL, NULL, NULL);

    val = make_safe_value(data, size);
    col = make_column_ref(data + 1, size > 1 ? size - 1 : 0);

    if (!val || !col) {
        free(val);
        free(col);
        sqlite3_close(db);
        return 0;
    }

    sql = malloc(500);
    if (!sql) {
        free(val);
        free(col);
        sqlite3_close(db);
        return 0;
    }

    size_t nTemplates = sizeof(azWindowSql) / sizeof(azWindowSql[0]);
    for (size_t i = 0; i < nTemplates; i++) {
        nProgressCalls = 0;
        snprintf(sql, 500, azWindowSql[i], col, val, col, val);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Also try with raw fuzz data as expressions */
    if (size > 2) {
        char expr[64];
        snprintf(expr, sizeof(expr), "%d", (int8_t)data[0]);
        snprintf(sql, 500, "SELECT a, sum(c) OVER (ORDER BY a ROWS %s PRECEDING) FROM t1;", expr);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    free(sql);
    free(val);
    free(col);
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
