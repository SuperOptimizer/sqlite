/*
** SQLite ATTACH/DETACH Database Fuzzer
**
** Tests multi-database operations, schema copying, and
** cross-database queries.
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

/* Cross-database SQL templates */
static const char *azAttachSql[] = {
    /* Cross-database queries */
    "SELECT * FROM main.t1, db2.t2 WHERE main.t1.a = db2.t2.x;",
    "SELECT * FROM t1 JOIN db2.t2 ON t1.a = t2.x;",
    "SELECT main.t1.*, db2.t2.* FROM main.t1, db2.t2;",
    "SELECT * FROM db2.t2 WHERE x IN (SELECT a FROM main.t1);",

    /* INSERT across databases */
    "INSERT INTO db2.t2 SELECT * FROM main.t1;",
    "INSERT INTO main.t1 SELECT x, y, z, NULL FROM db2.t2;",
    "INSERT INTO db2.t2 VALUES((SELECT max(a)+1 FROM main.t1), 'cross', 0);",

    /* UPDATE across databases */
    "UPDATE main.t1 SET b = (SELECT y FROM db2.t2 WHERE x = main.t1.a);",
    "UPDATE db2.t2 SET y = 'updated' WHERE x IN (SELECT a FROM main.t1);",

    /* DELETE across databases */
    "DELETE FROM db2.t2 WHERE x IN (SELECT a FROM main.t1 WHERE a > 5);",
    "DELETE FROM main.t1 WHERE a NOT IN (SELECT x FROM db2.t2);",

    /* CREATE in attached database */
    "CREATE TABLE db2.t3(p INTEGER PRIMARY KEY, q TEXT);",
    "CREATE INDEX db2.idx1 ON t2(y);",
    "CREATE VIEW db2.v1 AS SELECT * FROM t2 WHERE x > 0;",
    "CREATE TRIGGER db2.tr1 AFTER INSERT ON t2 BEGIN SELECT 1; END;",

    /* Schema queries across databases */
    "SELECT * FROM db2.sqlite_schema;",
    "SELECT sql FROM db2.sqlite_schema WHERE type='table';",
    "PRAGMA db2.table_info(t2);",
    "PRAGMA db2.index_list(t2);",
    "PRAGMA database_list;",

    /* Transactions across databases */
    "BEGIN; INSERT INTO main.t1 VALUES(100,'a',1.0,NULL); INSERT INTO db2.t2 VALUES(100,'b',2); COMMIT;",
    "BEGIN; UPDATE main.t1 SET c = c + 1; UPDATE db2.t2 SET z = z + 1; ROLLBACK;",
    "SAVEPOINT sp1; INSERT INTO db2.t2 VALUES(200,'sp',0); RELEASE sp1;",

    /* VACUUM and REINDEX */
    "VACUUM db2;",
    "REINDEX db2.t2;",

    /* Integrity checks */
    "PRAGMA db2.integrity_check;",
    "PRAGMA db2.quick_check;",
    "PRAGMA db2.foreign_key_check;",

    /* Temp database operations */
    "CREATE TEMP TABLE temp_t(id INTEGER);",
    "INSERT INTO temp.temp_t SELECT a FROM main.t1;",
    "SELECT * FROM temp.temp_t, db2.t2;",

    /* UNION across databases */
    "SELECT a, b FROM main.t1 UNION SELECT x, y FROM db2.t2;",
    "SELECT a FROM main.t1 INTERSECT SELECT x FROM db2.t2;",
    "SELECT a FROM main.t1 EXCEPT SELECT x FROM db2.t2;",

    /* Subqueries with database prefixes */
    "SELECT * FROM main.t1 WHERE a = (SELECT max(x) FROM db2.t2);",
    "SELECT (SELECT count(*) FROM db2.t2) AS cnt, * FROM main.t1;",

    /* Common table expressions across databases */
    "WITH cte AS (SELECT * FROM db2.t2) SELECT * FROM main.t1, cte;",
    "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x<10) SELECT * FROM cnt, db2.t2;",
};

/* Database alias templates for ATTACH */
static const char *azAliases[] = {
    "db2", "aux", "backup", "temp2", "other"
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

    /* Create main database schema */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL, d BLOB);"
        "INSERT INTO t1 VALUES(1,'one',1.1,X'01');"
        "INSERT INTO t1 VALUES(2,'two',2.2,X'02');"
        "INSERT INTO t1 VALUES(3,'three',3.3,X'03');"
        "INSERT INTO t1 VALUES(4,'four',4.4,X'04');"
        "INSERT INTO t1 VALUES(5,'five',5.5,X'05');",
        NULL, NULL, NULL);

    /* Attach an in-memory database */
    sqlite3_exec(db, "ATTACH ':memory:' AS db2;", NULL, NULL, NULL);

    /* Create schema in attached database */
    sqlite3_exec(db,
        "CREATE TABLE db2.t2(x INTEGER PRIMARY KEY, y TEXT, z INTEGER);"
        "INSERT INTO db2.t2 VALUES(1,'alpha',10);"
        "INSERT INTO db2.t2 VALUES(2,'beta',20);"
        "INSERT INTO db2.t2 VALUES(3,'gamma',30);"
        "INSERT INTO db2.t2 VALUES(4,'delta',40);",
        NULL, NULL, NULL);

    /* Run cross-database queries */
    size_t nTemplates = sizeof(azAttachSql) / sizeof(azAttachSql[0]);
    for (size_t i = 0; i < nTemplates; i++) {
        nProgressCalls = 0;
        sqlite3_exec(db, azAttachSql[i], NULL, NULL, NULL);
    }

    /* Try ATTACH with fuzz-derived name (as alias) */
    if (size >= 2) {
        int aliasIdx = data[0] % (sizeof(azAliases)/sizeof(azAliases[0]));
        snprintf(sql, sizeof(sql), "ATTACH ':memory:' AS %s;", azAliases[aliasIdx]);
        sqlite3_exec(db, sql, NULL, NULL, NULL);

        snprintf(sql, sizeof(sql), "CREATE TABLE %s.fuzz_t(id INTEGER);", azAliases[aliasIdx]);
        sqlite3_exec(db, sql, NULL, NULL, NULL);

        snprintf(sql, sizeof(sql), "INSERT INTO %s.fuzz_t VALUES(%d);",
                 azAliases[aliasIdx], (int8_t)data[1]);
        sqlite3_exec(db, sql, NULL, NULL, NULL);

        snprintf(sql, sizeof(sql), "SELECT * FROM %s.fuzz_t, main.t1;", azAliases[aliasIdx]);
        sqlite3_exec(db, sql, NULL, NULL, NULL);

        snprintf(sql, sizeof(sql), "DETACH %s;", azAliases[aliasIdx]);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* DETACH and re-ATTACH */
    sqlite3_exec(db, "DETACH db2;", NULL, NULL, NULL);
    sqlite3_exec(db, "ATTACH ':memory:' AS db2;", NULL, NULL, NULL);

    /* Verify main database still works */
    sqlite3_exec(db, "SELECT * FROM main.t1;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA database_list;", NULL, NULL, NULL);

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
