/*
** SQLite CAST/Type Conversion Fuzzer
**
** Tests CAST expressions, type affinity, and implicit conversions.
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

static const char *azCastSql[] = {
    /* CAST to INTEGER */
    "SELECT CAST('123' AS INTEGER);",
    "SELECT CAST('  456  ' AS INTEGER);",
    "SELECT CAST('-789' AS INTEGER);",
    "SELECT CAST('12.34' AS INTEGER);",
    "SELECT CAST('1.5e2' AS INTEGER);",
    "SELECT CAST(123.456 AS INTEGER);",
    "SELECT CAST(X'0102' AS INTEGER);",
    "SELECT CAST(NULL AS INTEGER);",

    /* CAST to REAL */
    "SELECT CAST('123.456' AS REAL);",
    "SELECT CAST('1e10' AS REAL);",
    "SELECT CAST('-1.5e-5' AS REAL);",
    "SELECT CAST(123 AS REAL);",
    "SELECT CAST('inf' AS REAL);",
    "SELECT CAST('nan' AS REAL);",

    /* CAST to TEXT */
    "SELECT CAST(123 AS TEXT);",
    "SELECT CAST(123.456 AS TEXT);",
    "SELECT CAST(X'48454C4C4F' AS TEXT);",
    "SELECT CAST(NULL AS TEXT);",

    /* CAST to BLOB */
    "SELECT CAST('hello' AS BLOB);",
    "SELECT CAST(123 AS BLOB);",
    "SELECT CAST(NULL AS BLOB);",

    /* CAST to NUMERIC */
    "SELECT CAST('123' AS NUMERIC);",
    "SELECT CAST('123.456' AS NUMERIC);",
    "SELECT CAST('abc' AS NUMERIC);",

    /* Type affinity with table columns */
    "INSERT INTO typed VALUES(CAST('100' AS INTEGER), CAST(200 AS TEXT), CAST('3.14' AS REAL), CAST('blob' AS BLOB));",
    "SELECT typeof(a), typeof(b), typeof(c), typeof(d) FROM typed;",

    /* Implicit conversions in comparisons */
    "SELECT 1 = '1';",
    "SELECT 1.0 = '1.0';",
    "SELECT '10' > '9';",
    "SELECT 10 > '9';",
    "SELECT X'00' = 0;",

    /* Implicit conversions in arithmetic */
    "SELECT '10' + 5;",
    "SELECT '10.5' * 2;",
    "SELECT '100' / '10';",
    "SELECT 'abc' + 1;",

    /* Implicit conversions in concatenation */
    "SELECT 'value: ' || 123;",
    "SELECT 100 || 200;",
    "SELECT 1.5 || ' is a number';",

    /* Type functions */
    "SELECT typeof(123);",
    "SELECT typeof(123.456);",
    "SELECT typeof('hello');",
    "SELECT typeof(X'1234');",
    "SELECT typeof(NULL);",

    /* Hex and binary representations */
    "SELECT hex(123);",
    "SELECT hex('ABC');",
    "SELECT hex(CAST(255 AS BLOB));",

    /* Quote function */
    "SELECT quote(123);",
    "SELECT quote('hello');",
    "SELECT quote(X'0102');",
    "SELECT quote(NULL);",

    /* Unicode handling */
    "SELECT CAST(X'C3A9' AS TEXT);",
    "SELECT unicode('A');",
    "SELECT char(65);",

    /* printf conversions */
    "SELECT printf('%%d', '123');",
    "SELECT printf('%%f', '45.67');",
    "SELECT printf('%%s', 123);",
    "SELECT printf('%%x', 255);",

    /* zeroblob and typeof */
    "SELECT typeof(zeroblob(10));",
    "SELECT length(zeroblob(100));",

    /* Affinity in expressions */
    "SELECT a + 0 FROM typed;",
    "SELECT b || '' FROM typed;",
    "SELECT c * 1.0 FROM typed;",

    /* Edge cases */
    "SELECT CAST('' AS INTEGER);",
    "SELECT CAST('' AS REAL);",
    "SELECT CAST('9223372036854775807' AS INTEGER);",
    "SELECT CAST('9223372036854775808' AS INTEGER);",
    "SELECT CAST('-9223372036854775808' AS INTEGER);",
    "SELECT CAST('1e309' AS REAL);",

    /* Coercion in CASE */
    "SELECT CASE WHEN 1 THEN 'yes' ELSE 0 END;",
    "SELECT CASE 1 WHEN '1' THEN 'match' ELSE 'no' END;",

    /* Coercion in UNION */
    "SELECT 1 UNION SELECT '2' UNION SELECT 3.0;",
    "SELECT 'a' UNION SELECT 1 UNION SELECT NULL;",

    /* Coercion in IN */
    "SELECT 1 IN ('1', 2, '3');",
    "SELECT '1' IN (1, 2, 3);",

    /* Coercion in BETWEEN */
    "SELECT '5' BETWEEN 1 AND 10;",
    "SELECT 5 BETWEEN '1' AND '10';",
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

    /* Create table with specific type affinities */
    sqlite3_exec(db,
        "CREATE TABLE typed(a INTEGER, b TEXT, c REAL, d BLOB);"
        "CREATE TABLE nums(val NUMERIC);"
        "CREATE TABLE flex(x, y, z);",
        NULL, NULL, NULL);

    /* Insert mixed type data */
    sqlite3_exec(db,
        "INSERT INTO typed VALUES(1, 'text', 1.5, X'0102');"
        "INSERT INTO typed VALUES('2', 2, '2.5', 'not blob');"
        "INSERT INTO nums VALUES(123), ('456'), (78.9), ('12.34');"
        "INSERT INTO flex VALUES(1, '1', 1.0);"
        "INSERT INTO flex VALUES('a', 2, X'03');",
        NULL, NULL, NULL);

    /* Execute CAST operations based on fuzz input */
    size_t nOps = sizeof(azCastSql) / sizeof(azCastSql[0]);
    for (size_t i = 0; i < size && i < 40; i++) {
        int opIdx = data[i] % nOps;
        nProgressCalls = 0;
        sqlite3_exec(db, azCastSql[opIdx], NULL, NULL, NULL);
    }

    /* Fuzz-driven CAST operations */
    for (size_t i = 0; i < size && i < 20; i++) {
        int val = data[i];
        int typeIdx = (i + 1 < size) ? data[i + 1] % 5 : 0;
        const char *types[] = {"INTEGER", "REAL", "TEXT", "BLOB", "NUMERIC"};

        snprintf(sql, sizeof(sql), "SELECT CAST(%d AS %s);", val, types[typeIdx]);
        nProgressCalls = 0;
        sqlite3_exec(db, sql, NULL, NULL, NULL);

        snprintf(sql, sizeof(sql), "SELECT CAST('%d.%d' AS %s);", val, val % 10, types[typeIdx]);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Fuzz-driven hex strings */
    for (size_t i = 0; i + 1 < size && i < 10; i += 2) {
        snprintf(sql, sizeof(sql), "SELECT CAST(X'%02X%02X' AS TEXT);",
                 data[i], data[i + 1]);
        sqlite3_exec(db, sql, NULL, NULL, NULL);

        snprintf(sql, sizeof(sql), "SELECT CAST(X'%02X%02X' AS INTEGER);",
                 data[i], data[i + 1]);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
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
