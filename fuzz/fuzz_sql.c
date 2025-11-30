/*
** SQLite SQL Statement Fuzzer
**
** This fuzzer tests SQLite's SQL parser and execution engine with
** malformed/malicious SQL statements against an empty database.
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
static const int MAX_PROGRESS_CALLS = 100000;

static int progress_handler(void *pUnused) {
    (void)pUnused;
    nProgressCalls++;
    return nProgressCalls >= MAX_PROGRESS_CALLS;
}

/* Maximum SQL length */
static const size_t MAX_SQL_LEN = 100000;

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    char *sql = NULL;
    char *zErr = NULL;
    int rc;

    /* Skip empty or oversized inputs */
    if (size == 0 || size > MAX_SQL_LEN) {
        return 0;
    }

    /* Open a fresh in-memory database for each test */
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    /* Set progress handler to prevent infinite loops */
    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Set limits */
    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 1000000);
    sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 100000);
    sqlite3_limit(db, SQLITE_LIMIT_COLUMN, 100);
    sqlite3_limit(db, SQLITE_LIMIT_EXPR_DEPTH, 50);
    sqlite3_limit(db, SQLITE_LIMIT_COMPOUND_SELECT, 10);
    sqlite3_limit(db, SQLITE_LIMIT_VDBE_OP, 100000);
    sqlite3_limit(db, SQLITE_LIMIT_FUNCTION_ARG, 8);
    sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 2);
    sqlite3_limit(db, SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 100);
    sqlite3_limit(db, SQLITE_LIMIT_TRIGGER_DEPTH, 10);

    /* Create a rich test schema for better coverage */
    sqlite3_exec(db,
        /* Basic tables with various column types */
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL, d BLOB);"
        "CREATE TABLE t2(x, y, z);"
        "CREATE TABLE t3(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, value REAL DEFAULT 0.0, CHECK(value >= 0));"
        "CREATE TABLE t4(id INTEGER, parent_id INTEGER, data TEXT, FOREIGN KEY(parent_id) REFERENCES t4(id));"
        "CREATE TABLE t5(k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID;"

        /* Indexes */
        "CREATE INDEX t1_b ON t1(b);"
        "CREATE INDEX t1_bc ON t1(b, c);"
        "CREATE UNIQUE INDEX t2_xy ON t2(x, y);"

        /* Views */
        "CREATE VIEW v1 AS SELECT a, b FROM t1 WHERE c > 0;"
        "CREATE VIEW v2 AS SELECT t1.a, t2.x FROM t1, t2 WHERE t1.a = t2.x;"

        /* FTS5 full-text search table */
        "CREATE VIRTUAL TABLE fts USING fts5(content, detail=full);"

        /* R-Tree spatial index */
        "CREATE VIRTUAL TABLE rt USING rtree(id, minX, maxX, minY, maxY);"

        /* Triggers */
        "CREATE TRIGGER tr1 AFTER INSERT ON t1 BEGIN SELECT 1; END;"
        "CREATE TRIGGER tr2 BEFORE UPDATE ON t1 BEGIN SELECT 1; END;"

        /* Insert test data - t1 (10 rows) */
        "INSERT INTO t1 VALUES(1, 'hello', 3.14, X'DEADBEEF');"
        "INSERT INTO t1 VALUES(2, 'world', 2.71, X'CAFEBABE');"
        "INSERT INTO t1 VALUES(3, 'foo', -1.5, NULL);"
        "INSERT INTO t1 VALUES(4, 'bar', 0.0, X'00');"
        "INSERT INTO t1 VALUES(5, NULL, 100.0, X'FFFFFFFF');"
        "INSERT INTO t1 VALUES(6, 'hello', 3.14, X'01020304');"
        "INSERT INTO t1 VALUES(7, 'test', 999.999, X'');"
        "INSERT INTO t1 VALUES(8, '', 0.001, X'AABBCCDD');"
        "INSERT INTO t1 VALUES(9, 'HELLO', -999.0, NULL);"
        "INSERT INTO t1 VALUES(10, 'World', 1e10, X'00FF00FF');"

        /* Insert test data - t2 (5 rows) */
        "INSERT INTO t2 VALUES(1, 2, 3);"
        "INSERT INTO t2 VALUES(4, 5, 6);"
        "INSERT INTO t2 VALUES(1, 'text', 3.14);"
        "INSERT INTO t2 VALUES(NULL, NULL, NULL);"
        "INSERT INTO t2 VALUES(7, 8, 9);"

        /* Insert test data - t3 (3 rows) */
        "INSERT INTO t3(name, value) VALUES('alpha', 1.0);"
        "INSERT INTO t3(name, value) VALUES('beta', 2.5);"
        "INSERT INTO t3(name, value) VALUES('gamma', 0.0);"

        /* Insert test data - t4 hierarchy */
        "INSERT INTO t4 VALUES(1, NULL, 'root');"
        "INSERT INTO t4 VALUES(2, 1, 'child1');"
        "INSERT INTO t4 VALUES(3, 1, 'child2');"
        "INSERT INTO t4 VALUES(4, 2, 'grandchild');"

        /* Insert test data - t5 (key-value) */
        "INSERT INTO t5 VALUES('key1', 'value1');"
        "INSERT INTO t5 VALUES('key2', 'value2');"

        /* Insert FTS data */
        "INSERT INTO fts VALUES('The quick brown fox jumps over the lazy dog');"
        "INSERT INTO fts VALUES('Hello world this is a test document');"
        "INSERT INTO fts VALUES('SQLite is a fast embedded database engine');"

        /* Insert R-Tree data */
        "INSERT INTO rt VALUES(1, 0, 10, 0, 10);"
        "INSERT INTO rt VALUES(2, 5, 15, 5, 15);"
        "INSERT INTO rt VALUES(3, -5, 5, -5, 5);",
        NULL, NULL, NULL);

    /* Null-terminate the SQL (make a copy) */
    sql = malloc(size + 1);
    if (sql == NULL) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(sql, data, size);
    sql[size] = '\0';

    /* Execute the fuzzed SQL */
    nProgressCalls = 0;
    sqlite3_exec(db, sql, NULL, NULL, &zErr);
    sqlite3_free(zErr);

    /* Clean up */
    free(sql);
    sqlite3_close(db);

    return 0;
}

#ifdef __AFL_FUZZ_TESTCASE_LEN
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    /* Initialize SQLite once */
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
/* Standalone mode - read from file or stdin */
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

    /* Read entire input */
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
        if (n == 0)
            break;
        size += n;
    }

    if (argc > 1)
        fclose(f);

    fuzz_one_input(data, size);

    free(data);
    return 0;
}
#endif
