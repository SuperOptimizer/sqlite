/*
** SQLite FTS (Full-Text Search) Fuzzer
**
** Tests FTS3, FTS4, and FTS5 full-text search functionality
** including tokenization, MATCH queries, snippets, and highlights.
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

#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();
#endif

static int nProgressCalls = 0;
static const int MAX_PROGRESS_CALLS = 50000;

static int progress_handler(void *pUnused) {
    (void)pUnused;
    nProgressCalls++;
    return nProgressCalls >= MAX_PROGRESS_CALLS;
}

static const size_t MAX_INPUT_LEN = 50000;

/*
** FTS query templates - %s will be replaced with fuzzed content
*/
static const char *azFtsSql[] = {
    /* FTS5 basic queries */
    "SELECT * FROM fts5_content WHERE fts5_content MATCH '%s';",
    "SELECT * FROM fts5_content WHERE fts5_content MATCH '\"%s\"';",
    "SELECT * FROM fts5_content('%s');",
    "SELECT highlight(fts5_content, 0, '<b>', '</b>') FROM fts5_content WHERE fts5_content MATCH '%s';",
    "SELECT snippet(fts5_content, 0, '<b>', '</b>', '...', 10) FROM fts5_content WHERE fts5_content MATCH '%s';",
    "SELECT bm25(fts5_content) FROM fts5_content WHERE fts5_content MATCH '%s';",
    "SELECT * FROM fts5_content WHERE fts5_content MATCH '%s' ORDER BY rank;",

    /* FTS5 advanced */
    "SELECT * FROM fts5_content WHERE fts5_content MATCH '%s OR test';",
    "SELECT * FROM fts5_content WHERE fts5_content MATCH '%s AND document';",
    "SELECT * FROM fts5_content WHERE fts5_content MATCH '%s NOT bad';",
    "SELECT * FROM fts5_content WHERE fts5_content MATCH 'NEAR(%s test)';",
    "SELECT * FROM fts5_content WHERE fts5_content MATCH 'NEAR(%s test, 5)';",
    "SELECT * FROM fts5_content WHERE fts5_content MATCH '%s*';",
    "SELECT * FROM fts5_content WHERE fts5_content MATCH '^%s';",
    "SELECT * FROM fts5_content WHERE fts5_content MATCH '{content}: %s';",

    /* FTS3/4 queries */
    "SELECT * FROM fts3_content WHERE fts3_content MATCH '%s';",
    "SELECT * FROM fts4_content WHERE fts4_content MATCH '%s';",
    "SELECT snippet(fts3_content) FROM fts3_content WHERE fts3_content MATCH '%s';",
    "SELECT offsets(fts3_content) FROM fts3_content WHERE fts3_content MATCH '%s';",
    "SELECT matchinfo(fts3_content) FROM fts3_content WHERE fts3_content MATCH '%s';",
    "SELECT matchinfo(fts4_content, 'pcnalx') FROM fts4_content WHERE fts4_content MATCH '%s';",

    /* FTS operators */
    "SELECT * FROM fts5_content WHERE fts5_content MATCH '%s OR quick OR fox';",
    "SELECT * FROM fts5_content WHERE fts5_content MATCH '(%s) AND (test OR document)';",
    "SELECT * FROM fts5_content WHERE fts5_content MATCH '\"%s\" + test';",

    /* Phrase queries */
    "SELECT * FROM fts5_content WHERE fts5_content MATCH '\"%s test\"';",
    "SELECT * FROM fts5_content WHERE fts5_content MATCH '\"%s\" NEAR/3 \"test\"';",

    /* Column filters */
    "SELECT * FROM fts5_multi WHERE content MATCH '%s';",
    "SELECT * FROM fts5_multi WHERE title MATCH '%s';",
    "SELECT * FROM fts5_multi WHERE {content title} MATCH '%s';",

    /* Auxiliary functions */
    "SELECT fts5_source_id(fts5_content) FROM fts5_content WHERE fts5_content MATCH '%s' LIMIT 1;",
};

/* Escape single quotes */
static char *escape_sql(const uint8_t *data, size_t size) {
    size_t quotes = 0;
    for (size_t i = 0; i < size && data[i]; i++) {
        if (data[i] == '\'') quotes++;
    }

    char *result = malloc(size + quotes + 1);
    if (!result) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < size && data[i]; i++) {
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
    size_t nTemplates = sizeof(azFtsSql) / sizeof(azFtsSql[0]);

    if (size == 0 || size > MAX_INPUT_LEN) {
        return 0;
    }

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 500000);
    sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 100000);

    /* Create FTS tables */
    sqlite3_exec(db,
        /* FTS5 tables */
        "CREATE VIRTUAL TABLE fts5_content USING fts5(content);"
        "CREATE VIRTUAL TABLE fts5_multi USING fts5(title, content);"

        /* FTS3/4 tables */
        "CREATE VIRTUAL TABLE fts3_content USING fts3(content);"
        "CREATE VIRTUAL TABLE fts4_content USING fts4(content);"

        /* Insert test data */
        "INSERT INTO fts5_content VALUES('The quick brown fox jumps over the lazy dog');"
        "INSERT INTO fts5_content VALUES('Hello world this is a test document');"
        "INSERT INTO fts5_content VALUES('SQLite full text search is powerful');"
        "INSERT INTO fts5_content VALUES('Testing FTS5 with various query patterns');"
        "INSERT INTO fts5_content VALUES('Another document with some random text content');"
        "INSERT INTO fts5_content VALUES('Programming databases and search engines');"
        "INSERT INTO fts5_content VALUES('Alpha beta gamma delta epsilon');"
        "INSERT INTO fts5_content VALUES('One two three four five six seven eight');"

        "INSERT INTO fts5_multi VALUES('Title One', 'Content for the first document');"
        "INSERT INTO fts5_multi VALUES('Second Title', 'Another piece of content here');"
        "INSERT INTO fts5_multi VALUES('Test Title', 'Testing multi-column FTS');"

        "INSERT INTO fts3_content VALUES('FTS3 test content for searching');"
        "INSERT INTO fts3_content VALUES('Another FTS3 document with text');"

        "INSERT INTO fts4_content VALUES('FTS4 with more features enabled');"
        "INSERT INTO fts4_content VALUES('Second FTS4 document for testing');",
        NULL, NULL, NULL);

    escaped = escape_sql(data, size);
    if (!escaped) {
        sqlite3_close(db);
        return 0;
    }

    sql = malloc(strlen(escaped) * 2 + 500);
    if (!sql) {
        free(escaped);
        sqlite3_close(db);
        return 0;
    }

    /* Run each FTS template */
    for (size_t i = 0; i < nTemplates; i++) {
        char *zErr = NULL;
        sprintf(sql, azFtsSql[i], escaped);
        nProgressCalls = 0;
        sqlite3_exec(db, sql, NULL, NULL, &zErr);
        sqlite3_free(zErr);
    }

    /* Also test raw MATCH with binding */
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(db,
        "SELECT * FROM fts5_content WHERE fts5_content MATCH ?", -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt) {
        sqlite3_bind_text(stmt, 1, (const char*)data, size, SQLITE_TRANSIENT);
        nProgressCalls = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW && nProgressCalls < MAX_PROGRESS_CALLS);
        sqlite3_finalize(stmt);
    }

    /* Test INSERT into FTS */
    rc = sqlite3_prepare_v2(db,
        "INSERT INTO fts5_content VALUES(?)", -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt) {
        sqlite3_bind_text(stmt, 1, (const char*)data, size, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    /* Query after insert */
    sqlite3_exec(db, "SELECT * FROM fts5_content WHERE fts5_content MATCH 'test' LIMIT 10;",
                 NULL, NULL, NULL);

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
