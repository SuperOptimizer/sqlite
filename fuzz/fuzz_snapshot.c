/*
** SQLite Snapshot API Fuzzer
**
** Tests the snapshot API for reading historical database states
** in WAL mode.
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
    sqlite3 *db2 = NULL;
    sqlite3_snapshot *pSnapshot = NULL;
    sqlite3_snapshot *pSnapshot2 = NULL;
    int rc;
    char *dbPath = NULL;

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    /* Need a file-based database for WAL mode snapshots */
    dbPath = sqlite3_mprintf("/tmp/fuzz_snapshot_%p.db", (void*)data);
    if (!dbPath) return 0;

    /* Clean up any existing file */
    unlink(dbPath);

    rc = sqlite3_open(dbPath, &db);
    if (rc != SQLITE_OK) {
        sqlite3_free(dbPath);
        return 0;
    }

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Enable WAL mode (required for snapshots) */
    sqlite3_exec(db, "PRAGMA journal_mode = WAL;", NULL, NULL, NULL);

    /* Create schema and initial data */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL);"
        "CREATE TABLE t2(x INTEGER, y BLOB);"
        "INSERT INTO t1 VALUES(1, 'initial', 1.0);"
        "INSERT INTO t1 VALUES(2, 'data', 2.0);"
        "INSERT INTO t2 VALUES(1, X'AABBCC');",
        NULL, NULL, NULL);

    /* Start a read transaction and get snapshot */
    rc = sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_exec(db, "SELECT * FROM t1;", NULL, NULL, NULL);
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3_snapshot_get(db, "main", &pSnapshot);
    }

    /* Commit the read transaction */
    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);

    if (pSnapshot) {
        /* Make some changes based on fuzz input */
        for (size_t i = 0; i < size && i < 10; i++) {
            char sql[256];
            int op = data[i] % 4;
            int val = data[(i + 1) % size];

            switch (op) {
                case 0:
                    snprintf(sql, sizeof(sql),
                        "INSERT OR IGNORE INTO t1 VALUES(%d, 'new%d', %d.0);",
                        10 + (int)i, val, val);
                    break;
                case 1:
                    snprintf(sql, sizeof(sql),
                        "UPDATE t1 SET b = 'modified%d' WHERE a = %d;",
                        val, (val % 2) + 1);
                    break;
                case 2:
                    snprintf(sql, sizeof(sql),
                        "DELETE FROM t1 WHERE a = %d;", (val % 5) + 1);
                    break;
                case 3:
                    snprintf(sql, sizeof(sql),
                        "INSERT OR IGNORE INTO t2 VALUES(%d, X'%02X');",
                        10 + (int)i, (unsigned)val);
                    break;
            }

            nProgressCalls = 0;
            sqlite3_exec(db, sql, NULL, NULL, NULL);
        }

        /* Get another snapshot after changes */
        rc = sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_exec(db, "SELECT * FROM t1;", NULL, NULL, NULL);
            sqlite3_snapshot_get(db, "main", &pSnapshot2);
        }
        sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);

        /* Compare snapshots */
        if (pSnapshot2) {
            int cmp = sqlite3_snapshot_cmp(pSnapshot, pSnapshot2);
            (void)cmp;  /* Just exercise the comparison */

            sqlite3_snapshot_free(pSnapshot2);
            pSnapshot2 = NULL;
        }

        /* Open second connection to read from snapshot */
        rc = sqlite3_open(dbPath, &db2);
        if (rc == SQLITE_OK) {
            sqlite3_progress_handler(db2, 100, progress_handler, NULL);

            /* Try to open snapshot */
            rc = sqlite3_exec(db2, "BEGIN;", NULL, NULL, NULL);
            if (rc == SQLITE_OK) {
                rc = sqlite3_snapshot_open(db2, "main", pSnapshot);
                if (rc == SQLITE_OK) {
                    /* Read data from historical snapshot */
                    nProgressCalls = 0;
                    sqlite3_exec(db2, "SELECT * FROM t1;", NULL, NULL, NULL);
                    sqlite3_exec(db2, "SELECT count(*) FROM t1;", NULL, NULL, NULL);
                    sqlite3_exec(db2, "SELECT * FROM t2;", NULL, NULL, NULL);
                }
            }
            sqlite3_exec(db2, "END;", NULL, NULL, NULL);

            /* Try snapshot recovery */
            sqlite3_snapshot_recover(db2, "main");

            sqlite3_close(db2);
        }

        sqlite3_snapshot_free(pSnapshot);
    }

    /* WAL checkpoint operations */
    int nLog = 0, nCkpt = 0;
    sqlite3_wal_checkpoint_v2(db, "main", SQLITE_CHECKPOINT_PASSIVE, &nLog, &nCkpt);
    sqlite3_wal_checkpoint_v2(db, "main", SQLITE_CHECKPOINT_FULL, &nLog, &nCkpt);
    sqlite3_wal_checkpoint_v2(db, "main", SQLITE_CHECKPOINT_RESTART, &nLog, &nCkpt);
    sqlite3_wal_checkpoint_v2(db, "main", SQLITE_CHECKPOINT_TRUNCATE, &nLog, &nCkpt);

    /* Auto-checkpoint setting */
    sqlite3_wal_autocheckpoint(db, 100);
    sqlite3_wal_autocheckpoint(db, 0);

    sqlite3_close(db);

    /* Clean up database files */
    unlink(dbPath);
    char walPath[256], shmPath[256];
    snprintf(walPath, sizeof(walPath), "%s-wal", dbPath);
    snprintf(shmPath, sizeof(shmPath), "%s-shm", dbPath);
    unlink(walPath);
    unlink(shmPath);

    sqlite3_free(dbPath);

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
