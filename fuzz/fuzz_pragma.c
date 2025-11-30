/*
** SQLite PRAGMA Fuzzer
**
** Tests SQLite's PRAGMA system which controls database configuration
** and can trigger many different code paths.
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

/* PRAGMA templates - some take values, some don't */
static const char *azPragmaVal[] = {
    "PRAGMA cache_size = %s;",
    "PRAGMA page_size = %s;",
    "PRAGMA auto_vacuum = %s;",
    "PRAGMA synchronous = %s;",
    "PRAGMA journal_mode = %s;",
    "PRAGMA temp_store = %s;",
    "PRAGMA locking_mode = %s;",
    "PRAGMA secure_delete = %s;",
    "PRAGMA foreign_keys = %s;",
    "PRAGMA recursive_triggers = %s;",
    "PRAGMA cell_size_check = %s;",
    "PRAGMA checkpoint_fullfsync = %s;",
    "PRAGMA fullfsync = %s;",
    "PRAGMA query_only = %s;",
    "PRAGMA read_uncommitted = %s;",
    "PRAGMA reverse_unordered_selects = %s;",
    "PRAGMA legacy_file_format = %s;",
    "PRAGMA writable_schema = %s;",
    "PRAGMA encoding = '%s';",
    "PRAGMA application_id = %s;",
    "PRAGMA user_version = %s;",
    "PRAGMA schema_version = %s;",
    "PRAGMA busy_timeout = %s;",
    "PRAGMA soft_heap_limit = %s;",
    "PRAGMA hard_heap_limit = %s;",
    "PRAGMA threads = %s;",
    "PRAGMA mmap_size = %s;",
    "PRAGMA max_page_count = %s;",
    "PRAGMA wal_autocheckpoint = %s;",
    "PRAGMA analysis_limit = %s;",
    "PRAGMA trusted_schema = %s;",
};

static const char *azPragmaQuery[] = {
    "PRAGMA cache_size;",
    "PRAGMA page_size;",
    "PRAGMA page_count;",
    "PRAGMA freelist_count;",
    "PRAGMA auto_vacuum;",
    "PRAGMA synchronous;",
    "PRAGMA journal_mode;",
    "PRAGMA temp_store;",
    "PRAGMA locking_mode;",
    "PRAGMA secure_delete;",
    "PRAGMA foreign_keys;",
    "PRAGMA encoding;",
    "PRAGMA database_list;",
    "PRAGMA collation_list;",
    "PRAGMA function_list;",
    "PRAGMA module_list;",
    "PRAGMA pragma_list;",
    "PRAGMA compile_options;",
    "PRAGMA integrity_check;",
    "PRAGMA quick_check;",
    "PRAGMA foreign_key_check;",
    "PRAGMA table_list;",
    "PRAGMA index_list(t1);",
    "PRAGMA table_info(t1);",
    "PRAGMA table_xinfo(t1);",
    "PRAGMA index_info(t1_idx);",
    "PRAGMA foreign_key_list(t1);",
    "PRAGMA stats;",
    "PRAGMA data_version;",
    "PRAGMA journal_size_limit;",
    "PRAGMA optimize;",
    "PRAGMA wal_checkpoint;",
    "PRAGMA wal_checkpoint(PASSIVE);",
    "PRAGMA wal_checkpoint(FULL);",
    "PRAGMA wal_checkpoint(RESTART);",
    "PRAGMA wal_checkpoint(TRUNCATE);",
    "PRAGMA incremental_vacuum(10);",
    "PRAGMA shrink_memory;",
};

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

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Create test schema */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL, d BLOB);"
        "CREATE INDEX t1_idx ON t1(b);"
        "INSERT INTO t1 VALUES(1,'hello',3.14,X'DEADBEEF');",
        NULL, NULL, NULL);

    escaped = escape_sql(data, size);
    if (!escaped) {
        sqlite3_close(db);
        return 0;
    }

    sql = malloc(strlen(escaped) + 200);
    if (!sql) {
        free(escaped);
        sqlite3_close(db);
        return 0;
    }

    /* Run PRAGMAs with value */
    size_t nValPragmas = sizeof(azPragmaVal) / sizeof(azPragmaVal[0]);
    for (size_t i = 0; i < nValPragmas; i++) {
        sprintf(sql, azPragmaVal[i], escaped);
        nProgressCalls = 0;
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Run query-only PRAGMAs */
    size_t nQueryPragmas = sizeof(azPragmaQuery) / sizeof(azPragmaQuery[0]);
    for (size_t i = 0; i < nQueryPragmas; i++) {
        nProgressCalls = 0;
        sqlite3_exec(db, azPragmaQuery[i], NULL, NULL, NULL);
    }

    /* Try raw PRAGMA with fuzzed name */
    sprintf(sql, "PRAGMA %s;", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "PRAGMA %s = 1;", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    sprintf(sql, "PRAGMA main.%s;", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* PRAGMA table_info with fuzzed table name */
    sprintf(sql, "PRAGMA table_info(%s);", escaped);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    free(sql);
    free(escaped);
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
