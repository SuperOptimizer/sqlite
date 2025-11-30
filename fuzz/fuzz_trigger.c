/*
** SQLite Trigger Fuzzer
**
** Tests trigger creation, execution, and recursive trigger behavior.
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

static const char *azTriggerSql[] = {
    /* BEFORE triggers */
    "CREATE TRIGGER tr_before_ins BEFORE INSERT ON t1 BEGIN SELECT 1; END;",
    "CREATE TRIGGER tr_before_upd BEFORE UPDATE ON t1 BEGIN SELECT NEW.a, OLD.a; END;",
    "CREATE TRIGGER tr_before_del BEFORE DELETE ON t1 BEGIN SELECT OLD.b; END;",

    /* AFTER triggers */
    "CREATE TRIGGER tr_after_ins AFTER INSERT ON t1 BEGIN INSERT INTO log VALUES(NEW.a, 'insert'); END;",
    "CREATE TRIGGER tr_after_upd AFTER UPDATE ON t1 BEGIN INSERT INTO log VALUES(NEW.a, 'update'); END;",
    "CREATE TRIGGER tr_after_del AFTER DELETE ON t1 BEGIN INSERT INTO log VALUES(OLD.a, 'delete'); END;",

    /* INSTEAD OF triggers on views */
    "CREATE TRIGGER tr_instead_ins INSTEAD OF INSERT ON v1 BEGIN INSERT INTO t1 VALUES(NEW.a, NEW.b, NEW.c); END;",
    "CREATE TRIGGER tr_instead_upd INSTEAD OF UPDATE ON v1 BEGIN UPDATE t1 SET b=NEW.b WHERE a=OLD.a; END;",
    "CREATE TRIGGER tr_instead_del INSTEAD OF DELETE ON v1 BEGIN DELETE FROM t1 WHERE a=OLD.a; END;",

    /* Column-specific triggers */
    "CREATE TRIGGER tr_col_upd AFTER UPDATE OF b ON t1 BEGIN SELECT 1; END;",
    "CREATE TRIGGER tr_col_upd2 AFTER UPDATE OF b, c ON t1 BEGIN SELECT 1; END;",

    /* Conditional triggers */
    "CREATE TRIGGER tr_when AFTER INSERT ON t1 WHEN NEW.a > 0 BEGIN SELECT 1; END;",
    "CREATE TRIGGER tr_when2 BEFORE UPDATE ON t1 WHEN OLD.b != NEW.b BEGIN SELECT 1; END;",
    "CREATE TRIGGER tr_when3 AFTER DELETE ON t1 WHEN OLD.a < 100 BEGIN SELECT 1; END;",

    /* Trigger with complex body */
    "CREATE TRIGGER tr_complex AFTER INSERT ON t1 BEGIN "
    "  INSERT INTO log VALUES(NEW.a, 'new'); "
    "  UPDATE t2 SET y = y + 1 WHERE x = NEW.a; "
    "  SELECT count(*) FROM t1; "
    "END;",

    /* Trigger with subquery */
    "CREATE TRIGGER tr_subq AFTER INSERT ON t1 BEGIN "
    "  INSERT INTO log SELECT NEW.a, b FROM t1 WHERE a = (SELECT max(a) FROM t1); "
    "END;",

    /* Trigger with CASE */
    "CREATE TRIGGER tr_case AFTER UPDATE ON t1 BEGIN "
    "  INSERT INTO log VALUES(NEW.a, CASE WHEN NEW.c > 0 THEN 'pos' ELSE 'neg' END); "
    "END;",

    /* Trigger referencing multiple tables */
    "CREATE TRIGGER tr_multi AFTER INSERT ON t1 BEGIN "
    "  UPDATE t2 SET y = (SELECT b FROM t1 WHERE a = NEW.a) WHERE x = NEW.a; "
    "END;",

    /* Recursive-safe trigger */
    "CREATE TRIGGER tr_recur AFTER INSERT ON log BEGIN "
    "  SELECT 1 WHERE (SELECT count(*) FROM log) < 10; "
    "END;",

    /* RAISE expressions */
    "CREATE TRIGGER tr_raise_ignore BEFORE INSERT ON t1 WHEN NEW.a < 0 BEGIN "
    "  SELECT RAISE(IGNORE); "
    "END;",
    "CREATE TRIGGER tr_raise_abort BEFORE INSERT ON t1 WHEN NEW.a = -999 BEGIN "
    "  SELECT RAISE(ABORT, 'invalid value'); "
    "END;",
    "CREATE TRIGGER tr_raise_rollback BEFORE UPDATE ON t1 WHEN NEW.c < 0 BEGIN "
    "  SELECT RAISE(ROLLBACK, 'negative not allowed'); "
    "END;",
    "CREATE TRIGGER tr_raise_fail BEFORE DELETE ON t1 WHEN OLD.a = 1 BEGIN "
    "  SELECT RAISE(FAIL, 'cannot delete row 1'); "
    "END;",
};

static const char *azOperations[] = {
    "INSERT INTO t1 VALUES(%d, 'fuzz%d', %d.0);",
    "UPDATE t1 SET b = 'modified%d' WHERE a = %d;",
    "UPDATE t1 SET c = %d.5 WHERE a > 0;",
    "DELETE FROM t1 WHERE a = %d;",
    "INSERT OR REPLACE INTO t1 VALUES(%d, 'replace', 0.0);",
    "INSERT OR IGNORE INTO t1 VALUES(%d, 'ignore', 1.0);",
    "UPDATE OR REPLACE t1 SET a = %d WHERE a = 1;",
    "INSERT INTO v1 VALUES(%d, 'view', 2.0);",
    "UPDATE v1 SET b = 'vmod' WHERE a = %d;",
    "DELETE FROM v1 WHERE a = %d;",
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

    /* Enable recursive triggers */
    sqlite3_exec(db, "PRAGMA recursive_triggers = ON;", NULL, NULL, NULL);

    /* Create schema */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT, c REAL);"
        "CREATE TABLE t2(x INTEGER PRIMARY KEY, y TEXT);"
        "CREATE TABLE log(id INTEGER, msg TEXT);"
        "CREATE VIEW v1 AS SELECT a, b, c FROM t1;"
        "INSERT INTO t1 VALUES(1, 'one', 1.0);"
        "INSERT INTO t1 VALUES(2, 'two', 2.0);"
        "INSERT INTO t1 VALUES(3, 'three', 3.0);"
        "INSERT INTO t2 VALUES(1, 'x');"
        "INSERT INTO t2 VALUES(2, 'y');",
        NULL, NULL, NULL);

    /* Create triggers based on fuzz input */
    size_t nTriggers = sizeof(azTriggerSql) / sizeof(azTriggerSql[0]);
    for (size_t i = 0; i < size && i < nTriggers; i++) {
        if (data[i] % 2 == 0) {
            nProgressCalls = 0;
            sqlite3_exec(db, azTriggerSql[i], NULL, NULL, NULL);
        }
    }

    /* Execute operations that fire triggers */
    size_t nOps = sizeof(azOperations) / sizeof(azOperations[0]);
    for (size_t i = 0; i < size && i < 30; i++) {
        int opIdx = data[i] % nOps;
        int val = (i < size - 1) ? data[i + 1] : (int)i;

        snprintf(sql, sizeof(sql), azOperations[opIdx], val % 100, val % 10, val);
        nProgressCalls = 0;
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Test trigger management */
    sqlite3_exec(db, "DROP TRIGGER IF EXISTS tr_before_ins;", NULL, NULL, NULL);
    sqlite3_exec(db, "DROP TRIGGER IF EXISTS tr_after_ins;", NULL, NULL, NULL);

    /* Verify state */
    sqlite3_exec(db, "SELECT * FROM log;", NULL, NULL, NULL);
    sqlite3_exec(db, "SELECT count(*) FROM t1;", NULL, NULL, NULL);

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
