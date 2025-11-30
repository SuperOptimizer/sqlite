/*
** SQLite BLOB I/O Fuzzer
**
** Tests incremental BLOB I/O API: sqlite3_blob_open/read/write/close.
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

static int fuzz_one_input(const uint8_t *data, size_t size) {
    sqlite3 *db = NULL;
    sqlite3_blob *pBlob = NULL;
    int rc;
    char sql[256];
    unsigned char buf[256];

    if (size == 0 || size > MAX_INPUT_LEN) return 0;

    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) return 0;

    nProgressCalls = 0;
    sqlite3_progress_handler(db, 100, progress_handler, NULL);

    /* Create table with BLOB column */
    sqlite3_exec(db,
        "CREATE TABLE blobs(id INTEGER PRIMARY KEY, data BLOB, name TEXT);"
        "CREATE TABLE large_blobs(id INTEGER PRIMARY KEY, content BLOB);",
        NULL, NULL, NULL);

    /* Insert initial BLOB data */
    for (int i = 1; i <= 10; i++) {
        sqlite3_stmt *pStmt = NULL;
        snprintf(sql, sizeof(sql), "INSERT INTO blobs VALUES(%d, ?, 'blob%d');", i, i);
        if (sqlite3_prepare_v2(db, sql, -1, &pStmt, NULL) == SQLITE_OK) {
            /* Create blob of varying size */
            int blobSize = 100 + (i * 50);
            unsigned char *blobData = malloc(blobSize);
            if (blobData) {
                memset(blobData, (unsigned char)i, blobSize);
                sqlite3_bind_blob(pStmt, 1, blobData, blobSize, SQLITE_TRANSIENT);
                sqlite3_step(pStmt);
                free(blobData);
            }
            sqlite3_finalize(pStmt);
        }
    }

    /* Insert larger blobs */
    for (int i = 1; i <= 5; i++) {
        sqlite3_stmt *pStmt = NULL;
        snprintf(sql, sizeof(sql), "INSERT INTO large_blobs VALUES(%d, ?);", i);
        if (sqlite3_prepare_v2(db, sql, -1, &pStmt, NULL) == SQLITE_OK) {
            int blobSize = 1000 * i;
            unsigned char *blobData = malloc(blobSize);
            if (blobData) {
                for (int j = 0; j < blobSize; j++) {
                    blobData[j] = (unsigned char)(j % 256);
                }
                sqlite3_bind_blob(pStmt, 1, blobData, blobSize, SQLITE_TRANSIENT);
                sqlite3_step(pStmt);
                free(blobData);
            }
            sqlite3_finalize(pStmt);
        }
    }

    /* Process fuzz input for blob operations */
    for (size_t i = 0; i < size; i++) {
        int op = data[i] % 12;
        int rowId = (i + 1 < size) ? (data[i + 1] % 10) + 1 : 1;
        int offset = (i + 2 < size) ? data[i + 2] % 200 : 0;
        int len = (i + 3 < size) ? (data[i + 3] % 100) + 1 : 50;

        nProgressCalls = 0;

        switch (op) {
            case 0: /* Open blob for reading */
                if (pBlob) sqlite3_blob_close(pBlob);
                pBlob = NULL;
                sqlite3_blob_open(db, "main", "blobs", "data", rowId, 0, &pBlob);
                break;

            case 1: /* Open blob for writing */
                if (pBlob) sqlite3_blob_close(pBlob);
                pBlob = NULL;
                sqlite3_blob_open(db, "main", "blobs", "data", rowId, 1, &pBlob);
                break;

            case 2: /* Read from blob */
                if (pBlob) {
                    int blobBytes = sqlite3_blob_bytes(pBlob);
                    if (offset < blobBytes && len > 0) {
                        int readLen = (offset + len > blobBytes) ? blobBytes - offset : len;
                        if (readLen > (int)sizeof(buf)) readLen = sizeof(buf);
                        sqlite3_blob_read(pBlob, buf, readLen, offset);
                    }
                }
                break;

            case 3: /* Write to blob */
                if (pBlob) {
                    int blobBytes = sqlite3_blob_bytes(pBlob);
                    if (offset < blobBytes && len > 0) {
                        int writeLen = (offset + len > blobBytes) ? blobBytes - offset : len;
                        if (writeLen > (int)sizeof(buf)) writeLen = sizeof(buf);
                        memset(buf, data[i], writeLen);
                        sqlite3_blob_write(pBlob, buf, writeLen, offset);
                    }
                }
                break;

            case 4: /* Reopen blob to different row */
                if (pBlob) {
                    sqlite3_blob_reopen(pBlob, rowId);
                }
                break;

            case 5: /* Get blob size */
                if (pBlob) {
                    (void)sqlite3_blob_bytes(pBlob);
                }
                break;

            case 6: /* Close and reopen */
                if (pBlob) {
                    sqlite3_blob_close(pBlob);
                    pBlob = NULL;
                }
                sqlite3_blob_open(db, "main", "large_blobs", "content",
                                  (rowId % 5) + 1, 0, &pBlob);
                break;

            case 7: /* Read at various offsets */
                if (pBlob) {
                    int blobBytes = sqlite3_blob_bytes(pBlob);
                    for (int j = 0; j < 5 && j * 50 < blobBytes; j++) {
                        int readLen = 50;
                        if (j * 50 + readLen > blobBytes) readLen = blobBytes - j * 50;
                        if (readLen > 0 && readLen <= (int)sizeof(buf)) {
                            sqlite3_blob_read(pBlob, buf, readLen, j * 50);
                        }
                    }
                }
                break;

            case 8: /* Zeroblob insert */
                snprintf(sql, sizeof(sql),
                    "INSERT INTO blobs VALUES(%d, zeroblob(%d), 'zero');",
                    100 + rowId, len * 10);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                break;

            case 9: /* BLOB literal insert */
                snprintf(sql, sizeof(sql),
                    "INSERT INTO blobs VALUES(%d, X'%02X%02X%02X%02X', 'hex');",
                    200 + rowId, data[i], offset, len, rowId);
                sqlite3_exec(db, sql, NULL, NULL, NULL);
                break;

            case 10: /* Query with BLOB functions */
                sqlite3_exec(db, "SELECT length(data), hex(substr(data, 1, 10)) FROM blobs;",
                            NULL, NULL, NULL);
                break;

            case 11: /* BLOB comparison */
                sqlite3_exec(db, "SELECT * FROM blobs WHERE data > X'00';", NULL, NULL, NULL);
                break;
        }
    }

    if (pBlob) {
        sqlite3_blob_close(pBlob);
    }

    /* Additional BLOB queries */
    sqlite3_exec(db, "SELECT typeof(data), length(data) FROM blobs;", NULL, NULL, NULL);
    sqlite3_exec(db, "SELECT id FROM blobs WHERE data = data;", NULL, NULL, NULL);
    sqlite3_exec(db, "SELECT instr(data, X'0505') FROM blobs;", NULL, NULL, NULL);

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
