/*
** SQLite Backup API Fuzzer
**
** Tests sqlite3_backup_init/step/finish/remaining/pagecount.
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
    sqlite3 *dbSrc = NULL;
    sqlite3 *dbDst = NULL;
    sqlite3 *dbDst2 = NULL;
    sqlite3_backup *pBackup = NULL;
    int rc;
    char sql[256];

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    /* Open source database */
    rc = sqlite3_open(":memory:", &dbSrc);
    if (rc != SQLITE_OK) return 0;

    nProgressCalls = 0;
    sqlite3_progress_handler(dbSrc, 100, progress_handler, NULL);

    /* Create source schema and data */
    sqlite3_exec(dbSrc,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c BLOB);"
        "CREATE TABLE t2(x REAL, y INTEGER, z TEXT);"
        "CREATE INDEX idx1 ON t1(b);"
        "CREATE INDEX idx2 ON t2(y);",
        NULL, NULL, NULL);

    /* Insert data based on fuzz input */
    for (size_t i = 0; i < size && i < 50; i++) {
        int val = data[i];
        snprintf(sql, sizeof(sql),
            "INSERT INTO t1 VALUES(%zu, 'row%d', X'%02X%02X');",
            i, val, val, (val * 2) % 256);
        sqlite3_exec(dbSrc, sql, NULL, NULL, NULL);

        snprintf(sql, sizeof(sql),
            "INSERT INTO t2 VALUES(%d.%d, %d, 'data%zu');",
            val, val % 10, val * 3, i);
        sqlite3_exec(dbSrc, sql, NULL, NULL, NULL);
    }

    /* Open destination databases */
    rc = sqlite3_open(":memory:", &dbDst);
    if (rc != SQLITE_OK) {
        sqlite3_close(dbSrc);
        return 0;
    }

    rc = sqlite3_open(":memory:", &dbDst2);
    if (rc != SQLITE_OK) {
        sqlite3_close(dbSrc);
        sqlite3_close(dbDst);
        return 0;
    }

    /* Process fuzz input for backup operations */
    for (size_t i = 0; i < size; i++) {
        int op = data[i] % 10;
        int pages = (i + 1 < size) ? (data[i + 1] % 20) + 1 : 5;

        nProgressCalls = 0;

        switch (op) {
            case 0: /* Start backup to first destination */
                if (pBackup) sqlite3_backup_finish(pBackup);
                pBackup = sqlite3_backup_init(dbDst, "main", dbSrc, "main");
                break;

            case 1: /* Start backup to second destination */
                if (pBackup) sqlite3_backup_finish(pBackup);
                pBackup = sqlite3_backup_init(dbDst2, "main", dbSrc, "main");
                break;

            case 2: /* Step backup */
                if (pBackup) {
                    rc = sqlite3_backup_step(pBackup, pages);
                    if (rc == SQLITE_DONE) {
                        sqlite3_backup_finish(pBackup);
                        pBackup = NULL;
                    }
                }
                break;

            case 3: /* Step backup with -1 (all pages) */
                if (pBackup) {
                    rc = sqlite3_backup_step(pBackup, -1);
                    sqlite3_backup_finish(pBackup);
                    pBackup = NULL;
                }
                break;

            case 4: /* Check remaining pages */
                if (pBackup) {
                    (void)sqlite3_backup_remaining(pBackup);
                    (void)sqlite3_backup_pagecount(pBackup);
                }
                break;

            case 5: /* Modify source during backup */
                if (pBackup) {
                    int val = data[i];
                    snprintf(sql, sizeof(sql),
                        "INSERT INTO t1 VALUES(%d, 'during', X'FF');", 1000 + val);
                    sqlite3_exec(dbSrc, sql, NULL, NULL, NULL);
                }
                break;

            case 6: /* Delete from source during backup */
                if (pBackup) {
                    snprintf(sql, sizeof(sql), "DELETE FROM t1 WHERE a = %d;", pages);
                    sqlite3_exec(dbSrc, sql, NULL, NULL, NULL);
                }
                break;

            case 7: /* Full backup cycle */
                if (pBackup) sqlite3_backup_finish(pBackup);
                pBackup = sqlite3_backup_init(dbDst, "main", dbSrc, "main");
                if (pBackup) {
                    while ((rc = sqlite3_backup_step(pBackup, 5)) == SQLITE_OK) {
                        nProgressCalls++;
                        if (nProgressCalls > 1000) break;
                    }
                    sqlite3_backup_finish(pBackup);
                    pBackup = NULL;
                }
                break;

            case 8: /* Verify destination */
                sqlite3_exec(dbDst, "SELECT count(*) FROM t1;", NULL, NULL, NULL);
                sqlite3_exec(dbDst, "PRAGMA integrity_check;", NULL, NULL, NULL);
                break;

            case 9: /* Backup from destination back to new memory db */
                {
                    sqlite3 *dbTemp = NULL;
                    if (sqlite3_open(":memory:", &dbTemp) == SQLITE_OK) {
                        sqlite3_backup *pRev = sqlite3_backup_init(dbTemp, "main", dbDst, "main");
                        if (pRev) {
                            sqlite3_backup_step(pRev, -1);
                            sqlite3_backup_finish(pRev);
                        }
                        sqlite3_exec(dbTemp, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL);
                        sqlite3_close(dbTemp);
                    }
                }
                break;
        }
    }

    /* Cleanup any active backup */
    if (pBackup) {
        sqlite3_backup_finish(pBackup);
    }

    /* Final verification */
    sqlite3_exec(dbDst, "PRAGMA integrity_check;", NULL, NULL, NULL);
    sqlite3_exec(dbDst2, "PRAGMA integrity_check;", NULL, NULL, NULL);

    sqlite3_close(dbDst2);
    sqlite3_close(dbDst);
    sqlite3_close(dbSrc);
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
