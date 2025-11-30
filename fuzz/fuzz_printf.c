/*
** SQLite printf / Format String Fuzzer
**
** Tests SQLite's printf implementation and format string handling
** which has historically been a source of bugs.
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

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 100000);

    /* Create test table */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER, b TEXT, c REAL, d BLOB);"
        "INSERT INTO t1 VALUES(42, 'hello', 3.14159, X'DEADBEEF');"
        "INSERT INTO t1 VALUES(-999, 'world', -2.71828, NULL);"
        "INSERT INTO t1 VALUES(0, '', 0.0, X'');"
        "INSERT INTO t1 VALUES(2147483647, 'max', 1e308, X'FFFFFFFF');",
        NULL, NULL, NULL);

    escaped = escape_sql(data, size);
    if (!escaped) {
        sqlite3_close(db);
        return 0;
    }

    sql = malloc(strlen(escaped) * 2 + 500);
    if (!sql) {
        free(escaped);
        sqlite3_close(db);
        return 0;
    }

    /* Test printf with format string */
    sprintf(sql, "SELECT printf('%s', 42);", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "SELECT printf('%s', 'hello');", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "SELECT printf('%s', 3.14159);", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "SELECT printf('%s', NULL);", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "SELECT printf('%s', X'DEADBEEF');", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Multiple arguments */
    sprintf(sql, "SELECT printf('%s', 1, 2, 3, 4, 5);", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "SELECT printf('%s', 'a', 'b', 'c');", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "SELECT printf('%s', 1, 'two', 3.0, NULL, X'FF');", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* With column values */
    sprintf(sql, "SELECT printf('%s', a) FROM t1;", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "SELECT printf('%s', a, b, c, d) FROM t1;", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Edge case numbers */
    sprintf(sql, "SELECT printf('%s', 9223372036854775807);", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "SELECT printf('%s', -9223372036854775808);", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "SELECT printf('%s', 1e308);", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "SELECT printf('%s', 1e-308);", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Also test format() alias */
    sprintf(sql, "SELECT format('%s', 123);", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Test in expressions */
    sprintf(sql, "SELECT length(printf('%s', 42));", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "SELECT typeof(printf('%s', 42));", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* Test with prepared statement binding */
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, "SELECT printf(?, 42, 'test', 3.14)", -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt) {
        sqlite3_bind_text(stmt, 1, (const char*)data, size, SQLITE_TRANSIENT);
        nProgressCalls = 0;
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    rc = sqlite3_prepare_v2(db, "SELECT printf('%d %s %f', ?, ?, ?)", -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt) {
        sqlite3_bind_int(stmt, 1, 42);
        sqlite3_bind_text(stmt, 2, (const char*)data, size > 100 ? 100 : size, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 3, 3.14);
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
