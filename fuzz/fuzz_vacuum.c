/*
** SQLite VACUUM/REINDEX Fuzzer
**
** Tests database maintenance operations which reorganize
** database structure and can expose issues in B-tree handling.
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

/* Maintenance operation templates */
static const char *azVacuumSql[] = {
    /* Basic VACUUM */
    "VACUUM;",
    "VACUUM main;",

    /* REINDEX operations */
    "REINDEX;",
    "REINDEX t1;",
    "REINDEX t1_idx;",
    "REINDEX t2_idx;",
    "REINDEX main.t1;",

    /* Incremental vacuum */
    "PRAGMA auto_vacuum = INCREMENTAL;",
    "PRAGMA incremental_vacuum(10);",
    "PRAGMA incremental_vacuum(100);",
    "PRAGMA incremental_vacuum;",

    /* Page manipulation */
    "PRAGMA page_size = 1024;",
    "PRAGMA page_size = 4096;",
    "PRAGMA page_size = 8192;",
    "PRAGMA page_size = 16384;",
    "PRAGMA page_size = 32768;",
    "PRAGMA page_size = 65536;",

    /* Cache operations */
    "PRAGMA cache_size = 100;",
    "PRAGMA cache_size = -2000;",
    "PRAGMA cache_spill = 0;",
    "PRAGMA cache_spill = 1;",

    /* Free list operations */
    "PRAGMA freelist_count;",
    "PRAGMA max_page_count;",
    "PRAGMA max_page_count = 1000;",

    /* Integrity after operations */
    "PRAGMA integrity_check;",
    "PRAGMA quick_check;",

    /* Schema manipulation before vacuum */
    "DROP INDEX IF EXISTS temp_idx;",
    "CREATE INDEX temp_idx ON t1(b);",
    "DROP INDEX temp_idx;",

    /* Auto-vacuum modes */
    "PRAGMA auto_vacuum = NONE;",
    "PRAGMA auto_vacuum = FULL;",
    "PRAGMA auto_vacuum = INCREMENTAL;",
    "PRAGMA auto_vacuum;",

    /* WAL operations */
    "PRAGMA journal_mode = WAL;",
    "PRAGMA wal_checkpoint;",
    "PRAGMA wal_checkpoint(PASSIVE);",
    "PRAGMA wal_checkpoint(FULL);",
    "PRAGMA wal_checkpoint(RESTART);",
    "PRAGMA wal_checkpoint(TRUNCATE);",
    "PRAGMA journal_mode = DELETE;",
    "PRAGMA journal_mode = TRUNCATE;",
    "PRAGMA journal_mode = PERSIST;",
    "PRAGMA journal_mode = MEMORY;",
    "PRAGMA journal_mode = OFF;",

    /* Synchronous modes */
    "PRAGMA synchronous = OFF;",
    "PRAGMA synchronous = NORMAL;",
    "PRAGMA synchronous = FULL;",
    "PRAGMA synchronous = EXTRA;",

    /* Analyze for optimizer stats */
    "ANALYZE;",
    "ANALYZE t1;",
    "ANALYZE t2;",
    "ANALYZE main;",

    /* Optimize */
    "PRAGMA optimize;",
    "PRAGMA optimize(0x02);",
    "PRAGMA optimize(0x04);",
    "PRAGMA optimize(0xfffe);",
};

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    int i;

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Create schema with multiple tables and indexes */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL, d BLOB);"
        "CREATE TABLE t2(x INTEGER, y TEXT, z BLOB);"
        "CREATE TABLE t3(id INTEGER PRIMARY KEY AUTOINCREMENT, val TEXT);"
        "CREATE INDEX t1_idx ON t1(b);"
        "CREATE INDEX t1_idx2 ON t1(c, b);"
        "CREATE INDEX t2_idx ON t2(y);"
        "CREATE UNIQUE INDEX t2_uidx ON t2(x);",
        NULL, NULL, NULL);

    /* Insert data to create some pages */
    sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL);
    for (i = 0; i < 100; i++) {
        char sql[256];
        snprintf(sql, sizeof(sql),
            "INSERT INTO t1 VALUES(%d, 'text%d', %d.%d, X'%02X%02X');"
            "INSERT INTO t2 VALUES(%d, 'val%d', X'%02X');"
            "INSERT INTO t3(val) VALUES('auto%d');",
            i, i, i, i % 100,
            (unsigned)(data[i % size]), (unsigned)(data[(i+1) % size]),
            i, i, (unsigned)(data[(i+2) % size]),
            i);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }
    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);

    /* Delete some rows to create fragmentation */
    sqlite3_exec(db, "DELETE FROM t1 WHERE a % 3 = 0;", NULL, NULL, NULL);
    sqlite3_exec(db, "DELETE FROM t2 WHERE x % 5 = 0;", NULL, NULL, NULL);
    sqlite3_exec(db, "DELETE FROM t3 WHERE id % 7 = 0;", NULL, NULL, NULL);

    /* Run maintenance operations based on fuzz input */
    size_t nOps = sizeof(azVacuumSql) / sizeof(azVacuumSql[0]);

    /* Use fuzz data to select which operations to run */
    for (size_t j = 0; j < size && j < 50; j++) {
        size_t opIdx = data[j] % nOps;
        nProgressCalls = 0;
        sqlite3_exec(db, azVacuumSql[opIdx], NULL, NULL, NULL);
    }

    /* Always run full set at least once */
    for (size_t k = 0; k < nOps; k++) {
        nProgressCalls = 0;
        sqlite3_exec(db, azVacuumSql[k], NULL, NULL, NULL);
    }

    /* Verify data still accessible */
    sqlite3_exec(db, "SELECT count(*) FROM t1;", NULL, NULL, NULL);
    sqlite3_exec(db, "SELECT count(*) FROM t2;", NULL, NULL, NULL);
    sqlite3_exec(db, "SELECT count(*) FROM t3;", NULL, NULL, NULL);

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
