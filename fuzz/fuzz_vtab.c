/*
** SQLite Virtual Table Fuzzer
**
** Tests built-in virtual tables: dbstat, stmt, bytecode, pragma, etc.
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

static const char *azVtabSql[] = {
    /* DBSTAT virtual table */
    "SELECT * FROM dbstat;",
    "SELECT name, path, pageno, pagetype, ncell, payload, unused, mx_payload FROM dbstat;",
    "SELECT pagetype, count(*), sum(ncell) FROM dbstat GROUP BY pagetype;",
    "SELECT * FROM dbstat WHERE name = 't1';",
    "SELECT * FROM dbstat WHERE pagetype = 'leaf';",
    "SELECT * FROM dbstat ORDER BY pageno;",
    "SELECT sum(payload), sum(unused) FROM dbstat;",
    "SELECT * FROM dbstat('main');",

    /* PRAGMA virtual table */
    "SELECT * FROM pragma_table_info('t1');",
    "SELECT * FROM pragma_table_xinfo('t1');",
    "SELECT * FROM pragma_index_info('idx1');",
    "SELECT * FROM pragma_index_list('t1');",
    "SELECT * FROM pragma_index_xinfo('idx1');",
    "SELECT * FROM pragma_foreign_key_list('t1');",
    "SELECT * FROM pragma_database_list;",
    "SELECT * FROM pragma_collation_list;",
    "SELECT * FROM pragma_function_list;",
    "SELECT * FROM pragma_module_list;",
    "SELECT * FROM pragma_pragma_list;",
    "SELECT * FROM pragma_compile_options;",
    "SELECT * FROM pragma_table_list;",

    /* STMT virtual table */
    "SELECT * FROM sqlite_stmt;",
    "SELECT sql, busy, nscan, nsort, naidx, nstep, reprep, run, mem FROM sqlite_stmt;",
    "SELECT sql FROM sqlite_stmt WHERE busy = 1;",
    "SELECT count(*) FROM sqlite_stmt;",

    /* BYTECODE virtual table */
    "SELECT * FROM bytecode('SELECT 1');",
    "SELECT * FROM bytecode('SELECT * FROM t1 WHERE a > 5');",
    "SELECT * FROM bytecode('INSERT INTO t1 VALUES(1,2,3)');",
    "SELECT opcode, p1, p2, p3, p4, p5, comment FROM bytecode('SELECT * FROM t1');",
    "SELECT addr, opcode FROM bytecode('UPDATE t1 SET b = 1');",
    "SELECT * FROM bytecode('SELECT * FROM t1 JOIN t2 ON t1.a = t2.x');",
    "SELECT * FROM bytecode('SELECT sum(a) FROM t1 GROUP BY b');",

    /* Tables function */
    "SELECT * FROM pragma_table_list WHERE type = 'table';",
    "SELECT * FROM pragma_table_list WHERE schema = 'main';",

    /* Joining virtual tables */
    "SELECT p.name, d.pagetype, d.ncell FROM pragma_table_info('t1') p, dbstat d WHERE d.name = 't1';",
    "SELECT * FROM pragma_index_list('t1') il JOIN pragma_index_info(il.name) ii;",

    /* Virtual table with WHERE clause */
    "SELECT * FROM pragma_function_list WHERE builtin = 1;",
    "SELECT * FROM pragma_function_list WHERE narg = 1;",
    "SELECT * FROM pragma_function_list WHERE enc = 'utf8';",

    /* Aggregate on virtual tables */
    "SELECT count(*) FROM pragma_function_list;",
    "SELECT type, count(*) FROM pragma_function_list GROUP BY type;",
    "SELECT pagetype, avg(ncell) FROM dbstat GROUP BY pagetype;",

    /* Complex queries on virtual tables */
    "SELECT name FROM pragma_table_list WHERE name IN (SELECT name FROM dbstat);",
    "SELECT DISTINCT pagetype FROM dbstat ORDER BY pagetype;",

    /* Generate_series if available */
    "SELECT * FROM generate_series(1, 10);",
    "SELECT * FROM generate_series(1, 100, 5);",
    "SELECT value, value * value FROM generate_series(1, 10);",
};

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    char sql[512];

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Create regular tables to query via virtual tables */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL);"
        "CREATE TABLE t2(x INTEGER, y BLOB, z TEXT);"
        "CREATE INDEX idx1 ON t1(b);"
        "CREATE INDEX idx2 ON t1(c, b);"
        "CREATE INDEX idx3 ON t2(y);",
        NULL, NULL, NULL);

    /* Insert data */
    for (int i = 0; i < 50; i++) {
        snprintf(sql, sizeof(sql),
            "INSERT INTO t1 VALUES(%d, 'row%d', %d.%d);",
            i, i, i, i % 10);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }
    for (int i = 0; i < 30; i++) {
        snprintf(sql, sizeof(sql),
            "INSERT INTO t2 VALUES(%d, X'%02X%02X', 'data%d');",
            i, i * 2, i * 3, i);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Run virtual table queries */
    size_t nQueries = sizeof(azVtabSql) / sizeof(azVtabSql[0]);
    for (size_t i = 0; i < nQueries; i++) {
        nProgressCalls = 0;
        sqlite3_exec(db, azVtabSql[i], NULL, NULL, NULL);
    }

    /* Fuzz-driven queries */
    for (size_t i = 0; i < size && i < 20; i++) {
        int queryIdx = data[i] % nQueries;
        nProgressCalls = 0;
        sqlite3_exec(db, azVtabSql[queryIdx], NULL, NULL, NULL);
    }

    /* Prepare statements to populate sqlite_stmt */
    sqlite3_stmt *stmts[5];
    sqlite3_prepare_v2(db, "SELECT * FROM t1 WHERE a > ?", -1, &stmts[0], NULL);
    sqlite3_prepare_v2(db, "INSERT INTO t1 VALUES(?, ?, ?)", -1, &stmts[1], NULL);
    sqlite3_prepare_v2(db, "UPDATE t1 SET b = ? WHERE a = ?", -1, &stmts[2], NULL);
    sqlite3_prepare_v2(db, "DELETE FROM t1 WHERE a = ?", -1, &stmts[3], NULL);
    sqlite3_prepare_v2(db, "SELECT * FROM t1 JOIN t2 ON t1.a = t2.x", -1, &stmts[4], NULL);

    /* Query sqlite_stmt with prepared statements active */
    sqlite3_exec(db, "SELECT sql, busy FROM sqlite_stmt;", NULL, NULL, NULL);

    /* Clean up prepared statements */
    for (int i = 0; i < 5; i++) {
        if (stmts[i]) sqlite3_finalize(stmts[i]);
    }

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
