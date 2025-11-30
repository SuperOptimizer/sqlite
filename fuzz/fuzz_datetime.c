/*
** SQLite Date/Time Functions Fuzzer
**
** Tests date(), time(), datetime(), julianday(), strftime(), and modifiers.
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

static const char *azDateSql[] = {
    /* Basic date/time functions */
    "SELECT date('now');",
    "SELECT time('now');",
    "SELECT datetime('now');",
    "SELECT julianday('now');",
    "SELECT unixepoch('now');",

    /* Date literals */
    "SELECT date('2024-01-15');",
    "SELECT datetime('2024-01-15 12:30:45');",
    "SELECT time('12:30:45');",
    "SELECT julianday('2024-01-15');",

    /* Date modifiers */
    "SELECT date('now', '+1 day');",
    "SELECT date('now', '-1 month');",
    "SELECT date('now', '+1 year');",
    "SELECT datetime('now', '+6 hours');",
    "SELECT datetime('now', '-30 minutes');",
    "SELECT datetime('now', '+45 seconds');",

    /* Multiple modifiers */
    "SELECT date('now', '+1 month', '+15 days');",
    "SELECT datetime('now', '-1 year', '+6 months', '+1 day');",
    "SELECT date('2024-01-01', '+1 month', 'start of month');",

    /* Start of modifiers */
    "SELECT date('now', 'start of month');",
    "SELECT date('now', 'start of year');",
    "SELECT datetime('now', 'start of day');",

    /* Weekday modifiers */
    "SELECT date('now', 'weekday 0');",
    "SELECT date('now', 'weekday 1');",
    "SELECT date('now', 'weekday 6');",

    /* Strftime formatting */
    "SELECT strftime('%%Y-%%m-%%d', 'now');",
    "SELECT strftime('%%H:%%M:%%S', 'now');",
    "SELECT strftime('%%Y-%%m-%%d %%H:%%M:%%S', 'now');",
    "SELECT strftime('%%j', 'now');",
    "SELECT strftime('%%W', 'now');",
    "SELECT strftime('%%w', 'now');",
    "SELECT strftime('%%s', 'now');",
    "SELECT strftime('%%f', 'now');",

    /* Unix epoch conversions */
    "SELECT datetime(0, 'unixepoch');",
    "SELECT datetime(1704067200, 'unixepoch');",
    "SELECT datetime(1704067200, 'unixepoch', 'localtime');",
    "SELECT strftime('%%s', 'now');",

    /* Julian day conversions */
    "SELECT datetime(2460324.5);",
    "SELECT julianday('2024-01-15 12:00:00');",

    /* Date arithmetic */
    "SELECT julianday('now') - julianday('2024-01-01');",
    "SELECT (julianday('now') - julianday('2000-01-01')) * 24;",

    /* Edge cases */
    "SELECT date('2024-02-29');",
    "SELECT date('2023-02-29');",
    "SELECT date('2024-12-31', '+1 day');",
    "SELECT datetime('2024-01-01 23:59:59', '+1 second');",

    /* Large offsets */
    "SELECT date('now', '+1000 days');",
    "SELECT date('now', '-500 years');",
    "SELECT date('now', '+%d days');",

    /* Localtime/UTC */
    "SELECT datetime('now', 'localtime');",
    "SELECT datetime('now', 'utc');",
    "SELECT datetime('2024-01-15 12:00:00', 'utc');",

    /* subsec/subsecond modifiers */
    "SELECT time('12:30:45.123');",
    "SELECT strftime('%%f', '12:30:45.123456');",

    /* Table with datetime columns */
    "SELECT * FROM events WHERE ts > datetime('now', '-1 day');",
    "SELECT * FROM events WHERE ts BETWEEN date('now', '-7 days') AND date('now');",
    "SELECT date(ts) AS d, count(*) FROM events GROUP BY d;",

    /* NULL handling */
    "SELECT date(NULL);",
    "SELECT datetime(NULL, '+1 day');",
    "SELECT strftime('%%Y', NULL);",

    /* Invalid inputs (should return NULL) */
    "SELECT date('invalid');",
    "SELECT datetime('not a date');",
    "SELECT strftime('%%Y', 'garbage');",

    /* Timediff (if available) */
    "SELECT timediff('2024-01-15', '2024-01-01');",
    "SELECT timediff('12:30:00', '10:00:00');",
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

    /* Create table with datetime data */
    sqlite3_exec(db,
        "CREATE TABLE events(id INTEGER PRIMARY KEY, ts TEXT, name TEXT);"
        "CREATE INDEX idx_ts ON events(ts);",
        NULL, NULL, NULL);

    /* Insert events with various timestamps */
    for (int i = 0; i < 20; i++) {
        snprintf(sql, sizeof(sql),
            "INSERT INTO events VALUES(%d, datetime('2024-01-01', '+%d days', '+%d hours'), 'event%d');",
            i, i * 5, i * 3, i);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Execute date/time queries based on fuzz input */
    size_t nOps = sizeof(azDateSql) / sizeof(azDateSql[0]);
    for (size_t i = 0; i < size && i < 40; i++) {
        int opIdx = data[i] % nOps;
        int dayOffset = (i + 1 < size) ? (int)(data[i + 1]) - 128 : 0;

        snprintf(sql, sizeof(sql), azDateSql[opIdx], dayOffset);
        nProgressCalls = 0;
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Fuzz-driven date modifiers */
    for (size_t i = 0; i < size && i < 20; i++) {
        int v1 = (int)(data[i]) - 128;
        int v2 = (i + 1 < size) ? data[i + 1] % 12 : 0;

        snprintf(sql, sizeof(sql),
            "SELECT datetime('2024-06-15', '%+d days', '%+d months');",
            v1, v2);
        nProgressCalls = 0;
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Fuzz-driven strftime formats */
    const char *formats[] = {"%%Y", "%%m", "%%d", "%%H", "%%M", "%%S", "%%j", "%%W", "%%w", "%%s", "%%f"};
    for (size_t i = 0; i < size && i < 10; i++) {
        int f1 = data[i] % 11;
        int f2 = (i + 1 < size) ? data[i + 1] % 11 : 0;

        snprintf(sql, sizeof(sql),
            "SELECT strftime('%s-%s', 'now');",
            formats[f1], formats[f2]);
        nProgressCalls = 0;
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
