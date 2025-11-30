/*
** SQLite Expression Fuzzer
**
** Tests SQLite's expression parser and evaluation with complex
** nested expressions, type coercion, and edge cases.
**
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

#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();
#endif

static int nProgressCalls = 0;
static const int MAX_PROGRESS_CALLS = 50000;

static int progress_handler(void *pUnused) {
    (void)pUnused;
    nProgressCalls++;
    return nProgressCalls >= MAX_PROGRESS_CALLS;
}

static const size_t MAX_INPUT_LEN = 50000;

/*
** Expression templates - tests various expression types
*/
static const char *azExprPrefix[] = {
    "SELECT ",
    "SELECT DISTINCT ",
    "SELECT ALL ",
};

static const char *azExprSuffix[] = {
    ";",
    " FROM t1;",
    " FROM t1 WHERE a > 0;",
    " FROM t1, t2;",
    " FROM t1 LIMIT 1;",
    " FROM t1 ORDER BY 1;",
    " FROM t1 GROUP BY 1;",
    " UNION SELECT 1;",
    " UNION ALL SELECT NULL;",
};

/* Escape single quotes */
static char *escape_sql(const uint8_t *data, size_t size) {
    size_t quotes = 0;
    for (size_t i = 0; i < size && data[i]; i++) {
        if (data[i] == '\'') quotes++;
    }

    char *result = malloc(size + quotes + 1);
    if (!result) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < size && data[i]; i++) {
        if (data[i] == '\'') {
            result[j++] = '\'';
            result[j++] = '\'';
        } else {
            result[j++] = data[i];
        }
    }
    result[j] = '\0';
    return result;
}

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    char *escaped = NULL;
    char *sql = NULL;

    if (size == 0 || size > MAX_INPUT_LEN) {
        return 0;
    }

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 500000);
    sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 100000);
    sqlite3_limit(db, SQLITE_LIMIT_EXPR_DEPTH, 100);
    sqlite3_limit(db, SQLITE_LIMIT_COMPOUND_SELECT, 20);
    sqlite3_limit(db, SQLITE_LIMIT_FUNCTION_ARG, 20);

    /* Create test schema with various types */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER, b TEXT, c REAL, d BLOB, e);"
        "CREATE TABLE t2(x INTEGER, y TEXT, z NUMERIC);"
        "INSERT INTO t1 VALUES(1, 'hello', 3.14, X'DEADBEEF', NULL);"
        "INSERT INTO t1 VALUES(2, 'world', -2.71, X'00', 'mixed');"
        "INSERT INTO t1 VALUES(3, NULL, 0.0, X'', 123);"
        "INSERT INTO t1 VALUES(4, '', 1e10, NULL, 45.67);"
        "INSERT INTO t1 VALUES(5, 'HELLO', -1e-10, X'FFFFFFFF', 0);"
        "INSERT INTO t2 VALUES(1, 'a', 100);"
        "INSERT INTO t2 VALUES(2, 'b', 200);"
        "INSERT INTO t2 VALUES(NULL, NULL, NULL);",
        NULL, NULL, NULL);

    escaped = escape_sql(data, size);
    if (!escaped) {
        sqlite3_close(db);
        return 0;
    }

    sql = malloc(strlen(escaped) + 200);
    if (!sql) {
        free(escaped);
        sqlite3_close(db);
        return 0;
    }

    /* Test expression with various prefixes/suffixes */
    size_t nPrefixes = sizeof(azExprPrefix) / sizeof(azExprPrefix[0]);
    size_t nSuffixes = sizeof(azExprSuffix) / sizeof(azExprSuffix[0]);

    for (size_t i = 0; i < nPrefixes; i++) {
        for (size_t j = 0; j < nSuffixes; j++) {
            char *zErr = NULL;
            sprintf(sql, "%s%s%s", azExprPrefix[i], escaped, azExprSuffix[j]);
            nProgressCalls = 0;
            sqlite3_exec(db, sql, NULL, NULL, &zErr);
            sqlite3_free(zErr);
        }
    }

    /* Test as WHERE clause */
    sprintf(sql, "SELECT * FROM t1 WHERE %s;", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Test as ORDER BY */
    sprintf(sql, "SELECT * FROM t1 ORDER BY %s;", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Test as GROUP BY */
    sprintf(sql, "SELECT COUNT(*), %s FROM t1 GROUP BY %s;", escaped, escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Test as HAVING */
    sprintf(sql, "SELECT a FROM t1 GROUP BY a HAVING %s;", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Test in CASE expression */
    sprintf(sql, "SELECT CASE WHEN %s THEN 1 ELSE 0 END;", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Test in function call */
    sprintf(sql, "SELECT COALESCE(%s, 0);", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "SELECT NULLIF(%s, 0);", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "SELECT IIF(%s, 'yes', 'no');", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Test in subquery */
    sprintf(sql, "SELECT * FROM t1 WHERE a IN (SELECT %s);", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "SELECT (SELECT %s);", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Test as INSERT value */
    sprintf(sql, "INSERT INTO t1 VALUES(%s, '', 0, NULL, NULL);", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Test in UPDATE SET */
    sprintf(sql, "UPDATE t1 SET e = %s WHERE a = 1;", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Test EXPLAIN */
    sprintf(sql, "EXPLAIN SELECT %s;", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Test EXPLAIN QUERY PLAN */
    sprintf(sql, "EXPLAIN QUERY PLAN SELECT * FROM t1 WHERE %s;", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Test with binding */
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, "SELECT ? + 1, ? || 'x', ? * 2.0", -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt) {
        sqlite3_bind_text(stmt, 1, (const char*)data, size, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, (const char*)data, size, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, (const char*)data, size, SQLITE_TRANSIENT);
        nProgressCalls = 0;
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    free(sql);
    free(escaped);
    sqlite3_close(db);

    return 0;
}

#ifdef __AFL_FUZZ_TESTCASE_LEN
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    fuzz_setup_tmpdir();
    sqlite3_initialize();
    sqlite3_config(SQLITE_CONFIG_LOOKASIDE, 0, 0);

    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(100000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        fuzz_one_input(buf, len);
    }

    return 0;
}
#else
int main(int argc, char **argv) {
    uint8_t *data = NULL;
    size_t size = 0;
    size_t capacity = 0;

    fuzz_setup_tmpdir();
    sqlite3_initialize();
    sqlite3_config(SQLITE_CONFIG_LOOKASIDE, 0, 0);

    FILE *f = (argc > 1) ? fopen(argv[1], "rb") : stdin;
    if (!f) {
        perror("fopen");
        return 1;
    }

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
        if (n == 0) break;
        size += n;
    }

    if (argc > 1) fclose(f);

    fuzz_one_input(data, size);

    free(data);
    return 0;
}
#endif
