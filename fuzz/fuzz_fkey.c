/*
** SQLite Foreign Key Fuzzer
**
** Tests foreign key constraints, cascading actions, and deferred checks.
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

static const char *azFkeySql[] = {
    /* Basic FK operations */
    "INSERT INTO child VALUES(%d, %d, 'child%d');",
    "UPDATE child SET parent_id = %d WHERE id = %d;",
    "DELETE FROM child WHERE id = %d;",
    "INSERT INTO parent VALUES(%d, 'parent%d');",
    "UPDATE parent SET id = %d WHERE id = %d;",
    "DELETE FROM parent WHERE id = %d;",

    /* Cascade operations */
    "INSERT INTO cascade_child VALUES(%d, %d, 'cc%d');",
    "UPDATE cascade_parent SET id = %d WHERE id = %d;",
    "DELETE FROM cascade_parent WHERE id = %d;",

    /* Set null operations */
    "INSERT INTO setnull_child VALUES(%d, %d, 'sn%d');",
    "DELETE FROM setnull_parent WHERE id = %d;",

    /* Set default operations */
    "INSERT INTO setdefault_child VALUES(%d, %d, 'sd%d');",
    "DELETE FROM setdefault_parent WHERE id = %d;",

    /* Restrict operations */
    "INSERT INTO restrict_child VALUES(%d, %d, 'rc%d');",
    "DELETE FROM restrict_parent WHERE id = %d;",

    /* Multi-column FK */
    "INSERT INTO multi_child VALUES(%d, %d, %d, 'mc%d');",
    "UPDATE multi_parent SET a = %d, b = %d WHERE a = 1;",

    /* Deferred FK */
    "INSERT INTO deferred_child VALUES(%d, %d, 'dc%d');",

    /* Self-referential */
    "INSERT INTO tree VALUES(%d, %d, 'node%d');",
    "UPDATE tree SET parent_id = %d WHERE id = %d;",
    "DELETE FROM tree WHERE id = %d;",
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

    /* Enable foreign keys */
    sqlite3_exec(db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);

    /* Create tables with various FK configurations */
    sqlite3_exec(db,
        /* Basic FK - NO ACTION (default) */
        "CREATE TABLE parent(id INTEGER PRIMARY KEY, name TEXT);"
        "CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id), data TEXT);"

        /* CASCADE on delete/update */
        "CREATE TABLE cascade_parent(id INTEGER PRIMARY KEY, name TEXT);"
        "CREATE TABLE cascade_child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES cascade_parent(id) ON DELETE CASCADE ON UPDATE CASCADE, data TEXT);"

        /* SET NULL on delete */
        "CREATE TABLE setnull_parent(id INTEGER PRIMARY KEY, name TEXT);"
        "CREATE TABLE setnull_child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES setnull_parent(id) ON DELETE SET NULL, data TEXT);"

        /* SET DEFAULT on delete */
        "CREATE TABLE setdefault_parent(id INTEGER PRIMARY KEY, name TEXT);"
        "CREATE TABLE setdefault_child(id INTEGER PRIMARY KEY, parent_id INTEGER DEFAULT 1 REFERENCES setdefault_parent(id) ON DELETE SET DEFAULT, data TEXT);"

        /* RESTRICT */
        "CREATE TABLE restrict_parent(id INTEGER PRIMARY KEY, name TEXT);"
        "CREATE TABLE restrict_child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES restrict_parent(id) ON DELETE RESTRICT, data TEXT);"

        /* Multi-column FK */
        "CREATE TABLE multi_parent(a INTEGER, b INTEGER, name TEXT, PRIMARY KEY(a, b));"
        "CREATE TABLE multi_child(id INTEGER PRIMARY KEY, pa INTEGER, pb INTEGER, data TEXT, FOREIGN KEY(pa, pb) REFERENCES multi_parent(a, b));"

        /* Deferred FK */
        "CREATE TABLE deferred_parent(id INTEGER PRIMARY KEY, name TEXT);"
        "CREATE TABLE deferred_child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES deferred_parent(id) DEFERRABLE INITIALLY DEFERRED, data TEXT);"

        /* Self-referential */
        "CREATE TABLE tree(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES tree(id), name TEXT);",
        NULL, NULL, NULL);

    /* Insert initial data */
    sqlite3_exec(db,
        "INSERT INTO parent VALUES(1, 'p1'), (2, 'p2'), (3, 'p3');"
        "INSERT INTO cascade_parent VALUES(1, 'cp1'), (2, 'cp2'), (3, 'cp3');"
        "INSERT INTO setnull_parent VALUES(1, 'sp1'), (2, 'sp2');"
        "INSERT INTO setdefault_parent VALUES(1, 'sdp1'), (2, 'sdp2');"
        "INSERT INTO restrict_parent VALUES(1, 'rp1'), (2, 'rp2');"
        "INSERT INTO multi_parent VALUES(1, 1, 'mp1'), (1, 2, 'mp2'), (2, 1, 'mp3');"
        "INSERT INTO deferred_parent VALUES(1, 'dp1'), (2, 'dp2');"
        "INSERT INTO tree VALUES(1, NULL, 'root'), (2, 1, 'c1'), (3, 1, 'c2');",
        NULL, NULL, NULL);

    /* Execute FK operations based on fuzz input */
    size_t nOps = sizeof(azFkeySql) / sizeof(azFkeySql[0]);
    for (size_t i = 0; i < size && i < 50; i++) {
        int opIdx = data[i] % nOps;
        int v1 = (i + 1 < size) ? (data[i + 1] % 10) + 1 : 1;
        int v2 = (i + 2 < size) ? (data[i + 2] % 5) + 1 : 1;
        int v3 = (i + 3 < size) ? data[i + 3] % 100 : 1;

        snprintf(sql, sizeof(sql), azFkeySql[opIdx], v1, v2, v3, v1);
        nProgressCalls = 0;
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Test deferred constraints */
    sqlite3_exec(db, "BEGIN DEFERRED;", NULL, NULL, NULL);
    sqlite3_exec(db, "INSERT INTO deferred_child VALUES(100, 999, 'orphan');", NULL, NULL, NULL);
    sqlite3_exec(db, "INSERT INTO deferred_parent VALUES(999, 'late');", NULL, NULL, NULL);
    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);

    /* FK checks */
    sqlite3_exec(db, "PRAGMA foreign_key_check;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA foreign_key_check(child);", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA foreign_key_list(child);", NULL, NULL, NULL);

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
