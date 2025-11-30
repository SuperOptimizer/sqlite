/*
** SQLite JSON Functions Fuzzer
**
** This fuzzer specifically targets SQLite's JSON1 extension functions
** to find bugs in JSON parsing and manipulation.
**
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
static const int MAX_PROGRESS_CALLS = 50000;

static int progress_handler(void *pUnused) {
    (void)pUnused;
    nProgressCalls++;
    return nProgressCalls >= MAX_PROGRESS_CALLS;
}

/* Maximum input size */
static const size_t MAX_INPUT_LEN = 100000;

/*
** JSON function templates - %s will be replaced with fuzzed JSON
*/
static const char *azJsonSql[] = {
    /* Validation and type */
    "SELECT json_valid('%s');",
    "SELECT json_type('%s');",
    "SELECT json_type('%s', '$');",
    "SELECT json_type('%s', '$.a');",
    "SELECT json_type('%s', '$[0]');",

    /* Extraction */
    "SELECT json_extract('%s', '$');",
    "SELECT json_extract('%s', '$.a');",
    "SELECT json_extract('%s', '$.a.b');",
    "SELECT json_extract('%s', '$[0]');",
    "SELECT json_extract('%s', '$[0].a');",
    "SELECT '%s' -> '$';",
    "SELECT '%s' ->> '$.a';",
    "SELECT json('%s');",

    /* Modification */
    "SELECT json_insert('%s', '$.new', 123);",
    "SELECT json_insert('%s', '$[#]', 'appended');",
    "SELECT json_replace('%s', '$.a', 'replaced');",
    "SELECT json_set('%s', '$.a', 'set');",
    "SELECT json_set('%s', '$.new', json_object('x', 1));",
    "SELECT json_remove('%s', '$.a');",
    "SELECT json_remove('%s', '$[0]');",
    "SELECT json_patch('%s', '{\"patched\": true}');",

    /* Array operations */
    "SELECT json_array_length('%s');",
    "SELECT json_array_length('%s', '$');",
    "SELECT json_array_length('%s', '$.a');",

    /* Object construction */
    "SELECT json_object('input', '%s');",
    "SELECT json_array('%s', '%s');",

    /* Iteration */
    "SELECT * FROM json_each('%s');",
    "SELECT * FROM json_tree('%s');",
    "SELECT key, value, type FROM json_each('%s') LIMIT 100;",
    "SELECT key, value, type, path FROM json_tree('%s') LIMIT 100;",
    "SELECT fullkey, atom FROM json_tree('%s') WHERE atom IS NOT NULL LIMIT 50;",

    /* Aggregation */
    "SELECT json_group_array(value) FROM json_each('%s');",
    "SELECT json_group_object(key, value) FROM json_each('%s') WHERE typeof(key)='text';",

    /* Nested operations */
    "SELECT json_extract(json_set('%s', '$.x', 1), '$.x');",
    "SELECT json_type(json_insert('%s', '$.y', json_array(1,2,3)), '$.y');",

    /* Edge cases */
    "SELECT json_quote('%s');",
    "SELECT json_valid(json('%s'));",
};

/* Escape single quotes for SQL string */
static char *escape_sql_string(const uint8_t *data, size_t size) {
    /* Count quotes to determine buffer size */
    size_t quotes = 0;
    for (size_t i = 0; i < size; i++) {
        if (data[i] == '\'') quotes++;
        if (data[i] == '\0') break;  /* Stop at null */
    }

    /* Allocate buffer: original size + extra quotes + null */
    char *result = malloc(size + quotes + 1);
    if (!result) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < size && data[i] != '\0'; i++) {
        if (data[i] == '\'') {
            result[j++] = '\'';
            result[j++] = '\'';
        } else {
            result[j++] = data[i];
        }
    }
    result[j] = '\0';
    return result;
}

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    char *escaped = NULL;
    char *sql = NULL;
    size_t nTemplates = sizeof(azJsonSql) / sizeof(azJsonSql[0]);

    /* Skip empty inputs */
    if (size == 0 || size > MAX_INPUT_LEN) {
        return 0;
    }

    /* Open in-memory database */
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    /* Set progress handler */
    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Set limits */
    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 1000000);
    sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 200000);

    /* Create a table with JSON data for more complex tests */
    sqlite3_exec(db,
        "CREATE TABLE jt(id INTEGER PRIMARY KEY, data TEXT);"
        "INSERT INTO jt VALUES(1, '{\"a\":1,\"b\":[1,2,3]}');"
        "INSERT INTO jt VALUES(2, '[1,2,{\"x\":\"y\"}]');",
        NULL, NULL, NULL);

    /* Escape the input for SQL string */
    escaped = escape_sql_string(data, size);
    if (!escaped) {
        sqlite3_close(db);
        return 0;
    }

    /* Allocate SQL buffer */
    sql = malloc(strlen(escaped) * 2 + 1000);
    if (!sql) {
        free(escaped);
        sqlite3_close(db);
        return 0;
    }

    /* Run each JSON function template */
    for (size_t i = 0; i < nTemplates; i++) {
        char *zErr = NULL;

        /* Format SQL with escaped JSON */
        sprintf(sql, azJsonSql[i], escaped, escaped);

        /* Execute */
        nProgressCalls = 0;
        sqlite3_exec(db, sql, NULL, NULL, &zErr);
        sqlite3_free(zErr);
    }

    /* Also test with the JSON as a parameter binding */
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db, "SELECT json_valid(?), json_type(?), json(?)", -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt) {
        sqlite3_bind_text(stmt, 1, (const char*)data, size, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, (const char*)data, size, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, (const char*)data, size, SQLITE_TRANSIENT);
        nProgressCalls = 0;
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    /* Test json_each/json_tree with binding */
    rc = sqlite3_prepare_v2(db, "SELECT * FROM json_each(?) LIMIT 100", -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt) {
        sqlite3_bind_text(stmt, 1, (const char*)data, size, SQLITE_TRANSIENT);
        nProgressCalls = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW && nProgressCalls < MAX_PROGRESS_CALLS) {
            /* Just iterate */
        }
        sqlite3_finalize(stmt);
    }

    /* Clean up */
    free(sql);
    free(escaped);
    sqlite3_close(db);

    return 0;
}

#ifdef __AFL_FUZZ_TESTCASE_LEN
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

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
/* Standalone mode */
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
        if (n == 0) break;
        size += n;
    }

    if (argc > 1) fclose(f);

    fuzz_one_input(data, size);

    free(data);
    return 0;
}
#endif
