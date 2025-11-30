/*
** SQLite R-Tree / Geospatial Fuzzer
**
** Tests R-Tree virtual tables and GEOPOLY functions which handle
** complex spatial data structures.
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

static const size_t MAX_INPUT_LEN = 20000;

/* R-Tree query templates */
static const char *azRtreeSql[] = {
    /* Basic R-Tree queries */
    "SELECT * FROM rt WHERE x1 > %s;",
    "SELECT * FROM rt WHERE x2 < %s;",
    "SELECT * FROM rt WHERE y1 > %s AND y2 < %s;",
    "SELECT * FROM rt WHERE x1 BETWEEN %s AND %s;",
    "SELECT id FROM rt WHERE x1=%s AND y1=%s AND x2=%s AND y2=%s;",

    /* R-Tree range queries */
    "SELECT * FROM rt WHERE x1 > %s AND x2 < 100;",
    "SELECT * FROM rt WHERE y1 < %s OR y2 > 50;",
    "SELECT count(*) FROM rt WHERE x1 > %s;",

    /* R-Tree with JOIN */
    "SELECT rt.id, t1.b FROM rt, t1 WHERE rt.id = t1.a AND rt.x1 > %s;",
    "SELECT * FROM rt JOIN t1 ON rt.id = t1.a WHERE rt.x1 < %s;",

    /* INSERT into R-Tree */
    "INSERT INTO rt VALUES(%s, 0, 10, 0, 10);",
    "INSERT INTO rt VALUES(1000 + %s, -50, 50, -50, 50);",
    "INSERT OR REPLACE INTO rt VALUES(%s, 1, 2, 3, 4);",

    /* UPDATE R-Tree */
    "UPDATE rt SET x1=%s WHERE id=1;",
    "UPDATE rt SET x2=%s, y2=%s WHERE id=2;",

    /* DELETE from R-Tree */
    "DELETE FROM rt WHERE x1 > %s;",
    "DELETE FROM rt WHERE id = %s;",
};

/* Geopoly templates */
static const char *azGeopolySql[] = {
    /* Geopoly shape creation */
    "SELECT geopoly_blob('[%s]');",
    "SELECT geopoly_json('[%s]');",
    "SELECT geopoly_svg('[%s]');",

    /* Geopoly area/perimeter */
    "SELECT geopoly_area('[%s]');",
    "SELECT geopoly_perimeter('[%s]');",
    "SELECT geopoly_bbox('[%s]');",

    /* Geopoly operations */
    "SELECT geopoly_contains_point('[0,0,10,0,10,10,0,10,0,0]', %s, 5);",
    "SELECT geopoly_contains_point('[[0,0],[10,0],[10,10],[0,10],[0,0]]', 5, %s);",

    /* Geopoly within/overlap */
    "SELECT geopoly_within('[0,0,5,0,5,5,0,5,0,0]', '[%s]');",
    "SELECT geopoly_overlap('[0,0,10,0,10,10,0,10,0,0]', '[%s]');",

    /* Geopoly regular shapes */
    "SELECT geopoly_regular(0, 0, %s, 4);",
    "SELECT geopoly_regular(0, 0, 10, %s);",
    "SELECT geopoly_regular(%s, %s, 5, 6);",

    /* Geopoly with virtual table */
    "INSERT INTO geo(_shape) VALUES(geopoly_regular(0,0,%s,5));",
    "SELECT * FROM geo WHERE geopoly_overlap(_shape, geopoly_regular(0,0,%s,4));",
    "SELECT geopoly_area(_shape) FROM geo WHERE rowid < %s;",

    /* Geopoly xform (transform) */
    "SELECT geopoly_xform('[0,0,10,0,10,10,0,10,0,0]', %s, 0, 0, 1, 0, 0);",
    "SELECT geopoly_xform('[0,0,10,0,10,10,0,10,0,0]', 1, %s, 0, 1, 0, 0);",

    /* Complex geopoly queries */
    "SELECT geopoly_ccw('[%s]');",
    "SELECT geopoly_group_bbox(geopoly_regular(0,0,5,4));",
};

static char *make_safe_number(const uint8_t *data, size_t size) {
    /* Convert fuzz data to a safe number string */
    char *result = malloc(32);
    if (!result) return NULL;

    if (size == 0) {
        strcpy(result, "0");
        return result;
    }

    /* Use first few bytes to make a number */
    int val = 0;
    for (size_t i = 0; i < size && i < 4; i++) {
        val = (val << 8) | data[i];
    }
    /* Keep in reasonable range */
    val = val % 10000;
    snprintf(result, 32, "%d", val);
    return result;
}

static char *make_coord_list(const uint8_t *data, size_t size) {
    /* Create a coordinate list for geopoly from fuzz data */
    if (size < 4) {
        char *result = strdup("[0,0],[10,0],[10,10],[0,10],[0,0]");
        return result;
    }

    /* Build coordinate pairs from data */
    size_t max_coords = (size / 2) < 20 ? (size / 2) : 20;
    if (max_coords < 3) max_coords = 3;

    char *result = malloc(max_coords * 20 + 10);
    if (!result) return NULL;

    size_t pos = 0;
    for (size_t i = 0; i < max_coords && (i*2+1) < size; i++) {
        int x = (int8_t)data[i*2];
        int y = (int8_t)data[i*2+1];
        if (i > 0) {
            pos += sprintf(result + pos, ",");
        }
        pos += sprintf(result + pos, "[%d,%d]", x, y);
    }
    /* Close polygon */
    if (max_coords > 0 && size >= 2) {
        int x0 = (int8_t)data[0];
        int y0 = (int8_t)data[1];
        pos += sprintf(result + pos, ",[%d,%d]", x0, y0);
    }

    return result;
}

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    int rc;
    char *num1 = NULL, *num2 = NULL;
    char *coords = NULL;
    char *sql = NULL;

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 500000);

    /* Create R-Tree virtual table */
    sqlite3_exec(db,
        "CREATE VIRTUAL TABLE rt USING rtree(id, x1, x2, y1, y2);"
        "INSERT INTO rt VALUES(1, 0, 10, 0, 10);"
        "INSERT INTO rt VALUES(2, 5, 15, 5, 15);"
        "INSERT INTO rt VALUES(3, -10, 0, -10, 0);"
        "INSERT INTO rt VALUES(4, 20, 30, 20, 30);"
        "INSERT INTO rt VALUES(5, -5, 5, -5, 5);",
        NULL, NULL, NULL);

    /* Create Geopoly virtual table */
    sqlite3_exec(db,
        "CREATE VIRTUAL TABLE geo USING geopoly();"
        "INSERT INTO geo(_shape) VALUES(geopoly_regular(0,0,10,4));"
        "INSERT INTO geo(_shape) VALUES(geopoly_regular(5,5,5,6));"
        "INSERT INTO geo(_shape) VALUES('[[-10,-10],[10,-10],[10,10],[-10,10],[-10,-10]]');",
        NULL, NULL, NULL);

    /* Create helper table */
    sqlite3_exec(db,
        "CREATE TABLE t1(a INTEGER PRIMARY KEY, b TEXT);"
        "INSERT INTO t1 VALUES(1,'one'),(2,'two'),(3,'three');",
        NULL, NULL, NULL);

    num1 = make_safe_number(data, size);
    num2 = make_safe_number(data + size/2, size - size/2);
    coords = make_coord_list(data, size);

    if (!num1 || !num2 || !coords) {
        free(num1);
        free(num2);
        free(coords);
        sqlite3_close(db);
        return 0;
    }

    sql = malloc(strlen(coords) + 500);
    if (!sql) {
        free(num1);
        free(num2);
        free(coords);
        sqlite3_close(db);
        return 0;
    }

    /* Run R-Tree queries */
    size_t nRtree = sizeof(azRtreeSql) / sizeof(azRtreeSql[0]);
    for (size_t i = 0; i < nRtree; i++) {
        nProgressCalls = 0;
        sprintf(sql, azRtreeSql[i], num1, num2, num1, num2);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Run Geopoly queries */
    size_t nGeopoly = sizeof(azGeopolySql) / sizeof(azGeopolySql[0]);
    for (size_t i = 0; i < nGeopoly; i++) {
        nProgressCalls = 0;
        sprintf(sql, azGeopolySql[i], coords, num1, num2, coords);
        sqlite3_exec(db, sql, NULL, NULL, NULL);
    }

    /* Direct R-Tree queries with raw fuzz data as bounds */
    sprintf(sql, "SELECT * FROM rt WHERE x1 > %d AND x2 < %d;",
            (int8_t)data[0], (int8_t)data[size > 1 ? 1 : 0] + 100);
    sqlite3_exec(db, sql, NULL, NULL, NULL);

    /* R-Tree integrity check */
    sqlite3_exec(db, "SELECT rtreecheck('rt');", NULL, NULL, NULL);

    free(sql);
    free(num1);
    free(num2);
    free(coords);
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
