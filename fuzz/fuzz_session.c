/*
** SQLite Session Extension Fuzzer
**
** Tests the session extension for change tracking and
** changeset/patchset generation.
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

/* Conflict handler for applying changesets */
static int conflict_handler(void *pCtx, int eConflict, sqlite3_changeset_iter *pIter) {
    (void)pCtx;
    (void)pIter;

    /* Return different actions based on conflict type */
    switch (eConflict) {
        case SQLITE_CHANGESET_DATA:
            return SQLITE_CHANGESET_REPLACE;
        case SQLITE_CHANGESET_NOTFOUND:
            return SQLITE_CHANGESET_OMIT;
        case SQLITE_CHANGESET_CONFLICT:
            return SQLITE_CHANGESET_REPLACE;
        case SQLITE_CHANGESET_CONSTRAINT:
            return SQLITE_CHANGESET_ABORT;
        case SQLITE_CHANGESET_FOREIGN_KEY:
            return SQLITE_CHANGESET_OMIT;
        default:
            return SQLITE_CHANGESET_ABORT;
    }
}

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3 *db2 = NULL;
    sqlite3_session *pSession = NULL;
    int rc;
    int nChangeset = 0;
    void *pChangeset = NULL;
    int nPatchset = 0;
    void *pPatchset = NULL;

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    /* Open two databases */
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;

    rc = sqlite3_open(":memory:", &db2);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);
    sqlite3_progress_handler(db2, 100, progress_handler, NULL);

    /* Create identical schemas */
    const char *schema =
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL);"
        "CREATE TABLE t2(x INTEGER PRIMARY KEY, y BLOB);"
        "CREATE TABLE t3(id INTEGER PRIMARY KEY, name TEXT, value INTEGER);"
        "INSERT INTO t1 VALUES(1, 'one', 1.0);"
        "INSERT INTO t1 VALUES(2, 'two', 2.0);"
        "INSERT INTO t1 VALUES(3, 'three', 3.0);"
        "INSERT INTO t2 VALUES(1, X'AABB');"
        "INSERT INTO t2 VALUES(2, X'CCDD');"
        "INSERT INTO t3 VALUES(1, 'first', 100);"
        "INSERT INTO t3 VALUES(2, 'second', 200);";

    sqlite3_exec(db, schema, NULL, NULL, NULL);
    sqlite3_exec(db2, schema, NULL, NULL, NULL);

    /* Create session for db */
    rc = sqlite3session_create(db, "main", &pSession);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        sqlite3_close(db2);
        return 0;
    }

    /* Attach tables to session */
    sqlite3session_attach(pSession, "t1");
    sqlite3session_attach(pSession, "t2");
    sqlite3session_attach(pSession, "t3");
    sqlite3session_attach(pSession, NULL);  /* All tables */

    /* Make changes based on fuzz input */
    for (size_t i = 0; i < size && i < 20; i++) {
        char sql[256];
        int op = data[i] % 6;
        int val = data[(i + 1) % size];

        switch (op) {
            case 0:  /* INSERT */
                snprintf(sql, sizeof(sql),
                    "INSERT OR IGNORE INTO t1 VALUES(%d, 'fuzz%d', %d.%d);",
                    100 + (int)i, val, val, (int)i);
                break;
            case 1:  /* UPDATE */
                snprintf(sql, sizeof(sql),
                    "UPDATE t1 SET b = 'updated%d', c = %d.0 WHERE a = %d;",
                    val, val, (val % 3) + 1);
                break;
            case 2:  /* DELETE */
                snprintf(sql, sizeof(sql),
                    "DELETE FROM t1 WHERE a = %d;", (val % 3) + 1);
                break;
            case 3:  /* INSERT t2 */
                snprintf(sql, sizeof(sql),
                    "INSERT OR IGNORE INTO t2 VALUES(%d, X'%02X%02X');",
                    100 + (int)i, (unsigned)val, (unsigned)(val ^ 0xFF));
                break;
            case 4:  /* UPDATE t2 */
                snprintf(sql, sizeof(sql),
                    "UPDATE t2 SET y = X'%02X' WHERE x = %d;",
                    (unsigned)val, (val % 2) + 1);
                break;
            case 5:  /* INSERT t3 */
                snprintf(sql, sizeof(sql),
                    "INSERT OR IGNORE INTO t3 VALUES(%d, 'name%d', %d);",
                    100 + (int)i, val, val * 10);
                break;
        }

        nProgressCalls = 0;
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Check session state */
    int bEmpty = sqlite3session_isempty(pSession);

    /* Generate changeset */
    rc = sqlite3session_changeset(pSession, &nChangeset, &pChangeset);
    if (rc == SQLITE_OK && nChangeset > 0 && pChangeset) {
        /* Apply changeset to db2 */
        rc = sqlite3changeset_apply(db2, nChangeset, pChangeset,
                                    NULL, conflict_handler, NULL);

        /* Invert the changeset */
        int nInverted = 0;
        void *pInverted = NULL;
        rc = sqlite3changeset_invert(nChangeset, pChangeset, &nInverted, &pInverted);
        if (rc == SQLITE_OK && pInverted) {
            /* Apply inverted changeset */
            sqlite3changeset_apply(db2, nInverted, pInverted,
                                   NULL, conflict_handler, NULL);
            sqlite3_free(pInverted);
        }

        /* Iterate through changeset */
        sqlite3_changeset_iter *pIter = NULL;
        rc = sqlite3changeset_start(&pIter, nChangeset, pChangeset);
        if (rc == SQLITE_OK) {
            while (sqlite3changeset_next(pIter) == SQLITE_ROW) {
                const char *zTab;
                int nCol;
                int op;
                int bIndirect;

                sqlite3changeset_op(pIter, &zTab, &nCol, &op, &bIndirect);

                /* Get old/new values */
                for (int j = 0; j < nCol && j < 10; j++) {
                    sqlite3_value *pOld = NULL;
                    sqlite3_value *pNew = NULL;

                    if (op == SQLITE_UPDATE || op == SQLITE_DELETE) {
                        sqlite3changeset_old(pIter, j, &pOld);
                    }
                    if (op == SQLITE_UPDATE || op == SQLITE_INSERT) {
                        sqlite3changeset_new(pIter, j, &pNew);
                    }
                }
            }
            sqlite3changeset_finalize(pIter);
        }

        sqlite3_free(pChangeset);
    }

    /* Generate patchset */
    rc = sqlite3session_patchset(pSession, &nPatchset, &pPatchset);
    if (rc == SQLITE_OK && nPatchset > 0 && pPatchset) {
        sqlite3_free(pPatchset);
    }

    /* Diff between databases */
    int nDiff = 0;
    void *pDiff = NULL;
    rc = sqlite3session_diff(pSession, "main", "t1", NULL);

    /* Clean up */
    sqlite3session_delete(pSession);
    sqlite3_close(db);
    sqlite3_close(db2);

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
