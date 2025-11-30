/*
** SQLite Savepoint/Transaction Fuzzer
**
** Tests nested transactions, savepoints, rollback behavior.
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

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    char sql[256];
    int savepoint_depth = 0;
    int in_transaction = 0;

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Create schema */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL);"
        "CREATE TABLE t2(x INTEGER, y TEXT);"
        "CREATE TABLE log(ts INTEGER, msg TEXT);"
        "INSERT INTO t1 VALUES(1, 'initial1', 1.0);"
        "INSERT INTO t1 VALUES(2, 'initial2', 2.0);"
        "INSERT INTO t2 VALUES(1, 'x1');"
        "INSERT INTO t2 VALUES(2, 'x2');",
        NULL, NULL, NULL);

    /* Process fuzz input as transaction commands */
    for (size_t i = 0; i < size; i++) {
        int op = data[i] % 16;
        int val = (i + 1 < size) ? data[i + 1] % 100 : (int)i;

        nProgressCalls = 0;

        switch (op) {
            case 0: /* BEGIN */
                if (!in_transaction) {
                    sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL);
                    in_transaction = 1;
                }
                break;

            case 1: /* BEGIN DEFERRED */
                if (!in_transaction) {
                    sqlite3_exec(db, "BEGIN DEFERRED;", NULL, NULL, NULL);
                    in_transaction = 1;
                }
                break;

            case 2: /* BEGIN IMMEDIATE */
                if (!in_transaction) {
                    sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
                    in_transaction = 1;
                }
                break;

            case 3: /* BEGIN EXCLUSIVE */
                if (!in_transaction) {
                    sqlite3_exec(db, "BEGIN EXCLUSIVE;", NULL, NULL, NULL);
                    in_transaction = 1;
                }
                break;

            case 4: /* COMMIT */
                if (savepoint_depth == 0 && in_transaction) {
                    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
                    in_transaction = 0;
                }
                break;

            case 5: /* ROLLBACK */
                if (savepoint_depth == 0 && in_transaction) {
                    sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
                    in_transaction = 0;
                }
                break;

            case 6: /* SAVEPOINT */
                if (savepoint_depth < 10) {
                    snprintf(sql, sizeof(sql), "SAVEPOINT sp%d;", savepoint_depth);
                    if (sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK) {
                        savepoint_depth++;
                    }
                }
                break;

            case 7: /* RELEASE SAVEPOINT */
                if (savepoint_depth > 0) {
                    snprintf(sql, sizeof(sql), "RELEASE sp%d;", savepoint_depth - 1);
                    if (sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK) {
                        savepoint_depth--;
                    }
                }
                break;

            case 8: /* ROLLBACK TO SAVEPOINT */
                if (savepoint_depth > 0) {
                    int target = val % savepoint_depth;
                    snprintf(sql, sizeof(sql), "ROLLBACK TO sp%d;", target);
                    sqlite3_exec(db, sql, NULL, NULL, NULL);
                }
                break;

            case 9: /* INSERT */
                snprintf(sql, sizeof(sql), "INSERT INTO t1 VALUES(%d, 'sp%d', %d.0);",
                         100 + val, savepoint_depth, val);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                break;

            case 10: /* UPDATE */
                snprintf(sql, sizeof(sql), "UPDATE t1 SET b = 'mod%d' WHERE a = %d;",
                         val, (val % 5) + 1);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                break;

            case 11: /* DELETE */
                snprintf(sql, sizeof(sql), "DELETE FROM t1 WHERE a = %d;", (val % 10) + 100);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                break;

            case 12: /* INSERT t2 */
                snprintf(sql, sizeof(sql), "INSERT INTO t2 VALUES(%d, 'y%d');", val, val);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                break;

            case 13: /* Log action */
                snprintf(sql, sizeof(sql), "INSERT INTO log VALUES(%zu, 'op%d');", i, op);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                break;

            case 14: /* SELECT (to trigger read) */
                sqlite3_exec(db, "SELECT count(*) FROM t1;", NULL, NULL, NULL);
                break;

            case 15: /* END (alias for COMMIT) */
                if (savepoint_depth == 0 && in_transaction) {
                    sqlite3_exec(db, "END;", NULL, NULL, NULL);
                    in_transaction = 0;
                }
                break;
        }
    }

    /* Clean up any open transactions */
    while (savepoint_depth > 0) {
        snprintf(sql, sizeof(sql), "RELEASE sp%d;", savepoint_depth - 1);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
        savepoint_depth--;
    }
    if (in_transaction) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
    }

    /* Verify state */
    sqlite3_exec(db, "SELECT * FROM t1;", NULL, NULL, NULL);
    sqlite3_exec(db, "SELECT * FROM log;", NULL, NULL, NULL);
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
