/*
** SQLite Prepared Statement Fuzzer
**
** This fuzzer tests SQLite's prepared statement API including:
** - sqlite3_prepare_v2/v3
** - sqlite3_bind_* functions with various types
** - sqlite3_step/reset/finalize
** - Parameter binding edge cases
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

/* AFL++ persistent mode macros */
#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();
#endif

/* Progress handler to prevent infinite loops */
static int nProgressCalls = 0;
static const int MAX_PROGRESS_CALLS = 50000;

static int progress_handler(void *pUnused) {
    (void)pUnused;
    nProgressCalls++;
    return nProgressCalls >= MAX_PROGRESS_CALLS;
}

/* Maximum input size */
static const size_t MAX_INPUT_LEN = 50000;

/*
** Input format:
** [2 bytes: SQL length] [SQL string] [bind data...]
**
** Bind data format (repeated):
** [1 byte: type] [data based on type]
**   type 0: NULL
**   type 1: int64 (8 bytes)
**   type 2: double (8 bytes)
**   type 3: text (2 byte length + data)
**   type 4: blob (2 byte length + data)
**   type 5: zeroblob (4 byte length)
*/

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc;
    size_t pos = 0;
    uint16_t sqlLen;
    char *sql = NULL;
    int paramIdx = 1;
    int nParams;

    /* Need at least 2 bytes for SQL length */
    if (size < 2 || size > MAX_INPUT_LEN) {
        return 0;
    }

    /* Read SQL length */
    sqlLen = data[0] | (data[1] << 8);
    pos = 2;

    /* Validate SQL length */
    if (sqlLen == 0 || pos + sqlLen > size) {
        return 0;
    }

    /* Open in-memory database */
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    /* Set progress handler */
    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Set limits */
    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 100000);
    sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 50000);
    sqlite3_limit(db, SQLITE_LIMIT_COLUMN, 50);
    sqlite3_limit(db, SQLITE_LIMIT_EXPR_DEPTH, 30);
    sqlite3_limit(db, SQLITE_LIMIT_COMPOUND_SELECT, 5);
    sqlite3_limit(db, SQLITE_LIMIT_VDBE_OP, 50000);
    sqlite3_limit(db, SQLITE_LIMIT_FUNCTION_ARG, 8);
    sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 2);
    sqlite3_limit(db, SQLITE_LIMIT_VARIABLE_NUMBER, 100);

    /* Create test schema */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL, d BLOB);"
        "CREATE TABLE t2(x, y, z);"
        "INSERT INTO t1 VALUES(1, 'hello', 3.14, X'DEADBEEF');"
        "INSERT INTO t1 VALUES(2, 'world', 2.71, X'CAFEBABE');"
        "INSERT INTO t2 VALUES(1, 2, 3);"
        "INSERT INTO t2 VALUES(4, 5, 6);",
        NULL, NULL, NULL);

    /* Copy and null-terminate SQL */
    sql = malloc(sqlLen + 1);
    if (!sql) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(sql, data + pos, sqlLen);
    sql[sqlLen] = '\0';
    pos += sqlLen;

    /* Prepare statement */
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK || stmt == NULL) {
        free(sql);
        sqlite3_close(db);
        return 0;
    }

    /* Get number of parameters */
    nParams = sqlite3_bind_parameter_count(stmt);

    /* Bind parameters from remaining fuzz data */
    while (pos < size && paramIdx <= nParams) {
        uint8_t bindType;

        if (pos >= size) break;
        bindType = data[pos++];

        switch (bindType % 6) {
            case 0: /* NULL */
                sqlite3_bind_null(stmt, paramIdx);
                break;

            case 1: /* int64 */
                if (pos + 8 <= size) {
                    sqlite3_int64 val = 0;
                    for (int i = 0; i < 8; i++) {
                        val |= ((sqlite3_int64)data[pos + i]) << (i * 8);
                    }
                    sqlite3_bind_int64(stmt, paramIdx, val);
                    pos += 8;
                }
                break;

            case 2: /* double */
                if (pos + 8 <= size) {
                    double val;
                    memcpy(&val, data + pos, 8);
                    sqlite3_bind_double(stmt, paramIdx, val);
                    pos += 8;
                }
                break;

            case 3: /* text */
                if (pos + 2 <= size) {
                    uint16_t len = data[pos] | (data[pos + 1] << 8);
                    pos += 2;
                    if (len > 10000) len = 10000;
                    if (pos + len <= size) {
                        sqlite3_bind_text(stmt, paramIdx, (const char*)(data + pos), len, SQLITE_TRANSIENT);
                        pos += len;
                    }
                }
                break;

            case 4: /* blob */
                if (pos + 2 <= size) {
                    uint16_t len = data[pos] | (data[pos + 1] << 8);
                    pos += 2;
                    if (len > 10000) len = 10000;
                    if (pos + len <= size) {
                        sqlite3_bind_blob(stmt, paramIdx, data + pos, len, SQLITE_TRANSIENT);
                        pos += len;
                    }
                }
                break;

            case 5: /* zeroblob */
                if (pos + 4 <= size) {
                    uint32_t len = data[pos] | (data[pos + 1] << 8) |
                                   (data[pos + 2] << 16) | (data[pos + 3] << 24);
                    pos += 4;
                    if (len > 100000) len = 100000;
                    sqlite3_bind_zeroblob(stmt, paramIdx, len);
                }
                break;
        }
        paramIdx++;
    }

    /* Execute statement (limit steps) */
    nProgressCalls = 0;
    for (int i = 0; i < 1000; i++) {
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) break;
    }

    /* Reset and run again with different bindings */
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);

    /* Rebind with NULLs and run again */
    for (int i = 1; i <= nParams; i++) {
        sqlite3_bind_null(stmt, i);
    }
    nProgressCalls = 0;
    for (int i = 0; i < 100; i++) {
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) break;
    }

    /* Clean up */
    sqlite3_finalize(stmt);
    free(sql);
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
/* Standalone mode */
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
