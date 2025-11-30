/*
** SQLite Collation Fuzzer
**
** Tests collation functions, string comparison, and locale-related
** code paths in sorting and indexing.
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

/* Custom collation - reverse comparison */
static int reverse_collate(void *pArg, int nA, const void *zA, int nB, const void *zB) {
    (void)pArg;
    int n = nA < nB ? nA : nB;
    int cmp = memcmp(zB, zA, n);  /* Reversed */
    if (cmp == 0) return nB - nA;
    return cmp;
}

/* Custom collation - length-based */
static int length_collate(void *pArg, int nA, const void *zA, int nB, const void *zB) {
    (void)pArg;
    (void)zA;
    (void)zB;
    return nA - nB;
}

/* Custom collation - case-insensitive */
static int nocase_custom(void *pArg, int nA, const void *zA, int nB, const void *zB) {
    (void)pArg;
    const unsigned char *a = (const unsigned char *)zA;
    const unsigned char *b = (const unsigned char *)zB;
    int n = nA < nB ? nA : nB;
    for (int i = 0; i < n; i++) {
        unsigned char ca = a[i];
        unsigned char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return ca - cb;
    }
    return nA - nB;
}

/* Collation SQL templates */
static const char *azCollationSql[] = {
    /* Built-in collations */
    "SELECT * FROM t1 ORDER BY b COLLATE BINARY;",
    "SELECT * FROM t1 ORDER BY b COLLATE NOCASE;",
    "SELECT * FROM t1 ORDER BY b COLLATE RTRIM;",

    /* Custom collations */
    "SELECT * FROM t1 ORDER BY b COLLATE REVERSE;",
    "SELECT * FROM t1 ORDER BY b COLLATE LENGTHCMP;",
    "SELECT * FROM t1 ORDER BY b COLLATE MYNOCASE;",

    /* Collation in comparisons */
    "SELECT * FROM t1 WHERE b = 'HELLO' COLLATE NOCASE;",
    "SELECT * FROM t1 WHERE b > 'abc' COLLATE BINARY;",
    "SELECT * FROM t1 WHERE b BETWEEN 'a' AND 'z' COLLATE NOCASE;",

    /* Collation in indexes */
    "CREATE INDEX idx_nocase ON t1(b COLLATE NOCASE);",
    "CREATE INDEX idx_binary ON t1(b COLLATE BINARY);",
    "CREATE INDEX idx_reverse ON t1(b COLLATE REVERSE);",

    /* Collation in GROUP BY */
    "SELECT b COLLATE NOCASE, count(*) FROM t1 GROUP BY b COLLATE NOCASE;",
    "SELECT b COLLATE BINARY, count(*) FROM t1 GROUP BY b COLLATE BINARY;",

    /* Collation in DISTINCT */
    "SELECT DISTINCT b COLLATE NOCASE FROM t1;",
    "SELECT DISTINCT b COLLATE BINARY FROM t1;",

    /* Collation in UNION */
    "SELECT b FROM t1 UNION SELECT b FROM t2 ORDER BY 1 COLLATE NOCASE;",
    "SELECT b FROM t1 INTERSECT SELECT b FROM t2;",

    /* Mixed collations */
    "SELECT * FROM t1 WHERE b COLLATE NOCASE = c COLLATE BINARY;",
    "SELECT * FROM t1 ORDER BY b COLLATE NOCASE, c COLLATE BINARY;",

    /* Collation with LIKE */
    "SELECT * FROM t1 WHERE b LIKE '%s' COLLATE NOCASE;",
    "SELECT * FROM t1 WHERE b LIKE 'A%' COLLATE NOCASE;",
    "SELECT * FROM t1 WHERE b GLOB '*' COLLATE BINARY;",

    /* Collation in subqueries */
    "SELECT * FROM t1 WHERE b IN (SELECT c FROM t2 ORDER BY c COLLATE NOCASE);",

    /* Unicode strings */
    "INSERT INTO t1 VALUES(100, 'Ångström', 'ÅNGSTRÖM');",
    "INSERT INTO t1 VALUES(101, 'Ñoño', 'ÑOÑO');",
    "INSERT INTO t1 VALUES(102, 'Müller', 'MÜLLER');",
    "SELECT * FROM t1 WHERE b = 'ÅNGSTRÖM' COLLATE NOCASE;",

    /* Min/Max with collation */
    "SELECT min(b COLLATE NOCASE), max(b COLLATE NOCASE) FROM t1;",
    "SELECT min(b COLLATE BINARY), max(b COLLATE BINARY) FROM t1;",

    /* Collation in CASE */
    "SELECT CASE WHEN b COLLATE NOCASE = 'HELLO' THEN 1 ELSE 0 END FROM t1;",

    /* Sorting edge cases */
    "SELECT * FROM t1 ORDER BY b COLLATE NOCASE ASC;",
    "SELECT * FROM t1 ORDER BY b COLLATE NOCASE DESC;",
    "SELECT * FROM t1 ORDER BY b COLLATE NOCASE ASC NULLS FIRST;",
    "SELECT * FROM t1 ORDER BY b COLLATE NOCASE ASC NULLS LAST;",

    /* String functions with implicit collation */
    "SELECT * FROM t1 WHERE lower(b) = lower(c);",
    "SELECT * FROM t1 WHERE upper(b) = 'HELLO';",
    "SELECT * FROM t1 WHERE instr(b COLLATE NOCASE, 'LL') > 0;",
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

    /* Register custom collations */
    sqlite3_create_collation(db, "REVERSE", SQLITE_UTF8, NULL, reverse_collate);
    sqlite3_create_collation(db, "LENGTHCMP", SQLITE_UTF8, NULL, length_collate);
    sqlite3_create_collation(db, "MYNOCASE", SQLITE_UTF8, NULL, nocase_custom);

    /* Create test tables */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c TEXT);"
        "CREATE TABLE t2(x INTEGER, y TEXT);"
        "INSERT INTO t1 VALUES(1, 'hello', 'HELLO');"
        "INSERT INTO t1 VALUES(2, 'Hello', 'hello');"
        "INSERT INTO t1 VALUES(3, 'HELLO', 'Hello');"
        "INSERT INTO t1 VALUES(4, 'world', 'WORLD');"
        "INSERT INTO t1 VALUES(5, 'World', 'world');"
        "INSERT INTO t1 VALUES(6, 'abc', 'ABC');"
        "INSERT INTO t1 VALUES(7, 'ABC', 'abc');"
        "INSERT INTO t1 VALUES(8, 'aBc', 'AbC');"
        "INSERT INTO t1 VALUES(9, NULL, NULL);"
        "INSERT INTO t1 VALUES(10, '', '');"
        "INSERT INTO t1 VALUES(11, ' ', '  ');"
        "INSERT INTO t1 VALUES(12, 'a', 'aaaa');"
        "INSERT INTO t1 VALUES(13, 'aaaa', 'a');"
        "INSERT INTO t2 VALUES(1, 'hello');"
        "INSERT INTO t2 VALUES(2, 'HELLO');"
        "INSERT INTO t2 VALUES(3, 'abc');",
        NULL, NULL, NULL);

    /* Add some fuzz-derived strings */
    if (size >= 2) {
        char fuzz_str[64];
        size_t len = (size > 60) ? 60 : size;
        memcpy(fuzz_str, data, len);
        fuzz_str[len] = '\0';

        /* Escape single quotes */
        char escaped[128];
        size_t j = 0;
        for (size_t i = 0; i < len && j < 120; i++) {
            if (fuzz_str[i] == '\'') {
                escaped[j++] = '\'';
            }
            escaped[j++] = fuzz_str[i];
        }
        escaped[j] = '\0';

        snprintf(sql, sizeof(sql), "INSERT INTO t1 VALUES(50, '%s', '%s');", escaped, escaped);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Run collation queries */
    size_t nQueries = sizeof(azCollationSql) / sizeof(azCollationSql[0]);
    for (size_t i = 0; i < nQueries; i++) {
        nProgressCalls = 0;
        sqlite3_exec(db, azCollationSql[i], NULL, NULL, NULL);
    }

    /* Collation list */
    sqlite3_exec(db, "PRAGMA collation_list;", NULL, NULL, NULL);

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
