cmake_minimum_required(VERSION 3.16)
project(sqlite-fuzz C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Output binaries to bin/
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Check if amalgamation has been generated
if(NOT EXISTS "${CMAKE_SOURCE_DIR}/sqlite3.c")
    message(STATUS "Generating SQLite amalgamation...")

    # Create sqlite_cfg.h if it doesn't exist
    if(NOT EXISTS "${CMAKE_SOURCE_DIR}/sqlite_cfg.h")
        file(WRITE "${CMAKE_SOURCE_DIR}/sqlite_cfg.h" "/* Auto-generated empty config */\n")
    endif()

    # Run make to generate amalgamation using the linux-generic makefile
    execute_process(
        COMMAND make -f Makefile.linux-generic sqlite3.c
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        RESULT_VARIABLE MAKE_RESULT
        OUTPUT_VARIABLE MAKE_OUTPUT
        ERROR_VARIABLE MAKE_ERROR
    )

    if(NOT MAKE_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to generate SQLite amalgamation:\n${MAKE_OUTPUT}\n${MAKE_ERROR}")
    endif()
endif()

# SQLite compile-time options for fuzzing
add_compile_definitions(
    # Core options
    SQLITE_THREADSAFE=0
    SQLITE_DEFAULT_MEMSTATUS=0
    SQLITE_DEFAULT_WAL_SYNCHRONOUS=1
    SQLITE_LIKE_DOESNT_MATCH_BLOBS
    SQLITE_MAX_EXPR_DEPTH=0
    # SQLITE_OMIT_DECLTYPE  # conflicts with COLUMN_METADATA
    SQLITE_OMIT_DEPRECATED
    SQLITE_OMIT_SHARED_CACHE
    SQLITE_USE_ALLOCA

    # Enable features useful for fuzzing
    SQLITE_ENABLE_DBSTAT_VTAB
    SQLITE_ENABLE_FTS5
    SQLITE_ENABLE_RTREE
    SQLITE_ENABLE_GEOPOLY
    SQLITE_ENABLE_JSON1
    SQLITE_ENABLE_MATH_FUNCTIONS
    SQLITE_ENABLE_DESERIALIZE

    # Additional features for more coverage
    SQLITE_ENABLE_FTS3
    SQLITE_ENABLE_FTS3_PARENTHESIS
    SQLITE_ENABLE_FTS4
    SQLITE_ENABLE_STAT4
    SQLITE_ENABLE_UPDATE_DELETE_LIMIT
    SQLITE_ENABLE_COLUMN_METADATA
    SQLITE_ENABLE_EXPLAIN_COMMENTS
    SQLITE_ENABLE_NORMALIZE
    SQLITE_ENABLE_PREUPDATE_HOOK
    SQLITE_ENABLE_SESSION
    SQLITE_ENABLE_SNAPSHOT
    SQLITE_ENABLE_SORTER_REFERENCES
    SQLITE_ENABLE_STMTVTAB
    SQLITE_ENABLE_BYTECODE_VTAB
    SQLITE_ENABLE_OFFSET_SQL_FUNC
    SQLITE_ENABLE_UNKNOWN_SQL_FUNCTION

    # Disable features that can cause issues in fuzzing
    SQLITE_OMIT_LOAD_EXTENSION
    SQLITE_OMIT_RANDOMNESS

    # Memory limits for fuzzing
    SQLITE_MAX_LENGTH=1000000
    SQLITE_MAX_SQL_LENGTH=100000
    SQLITE_MAX_PAGE_COUNT=1000
)

# Include directories
include_directories(${CMAKE_SOURCE_DIR})

# Create static library from the amalgamation
add_library(sqlite3_fuzz STATIC sqlite3.c)
target_link_libraries(sqlite3_fuzz m dl pthread)

# Option to build fuzz targets
option(SQLITE_BUILD_FUZZ "Build fuzz targets" ON)

if(SQLITE_BUILD_FUZZ)
    # Fuzz target: Database file fuzzer
    # Uses AFL++ persistent mode with __AFL_FUZZ_INIT() / __AFL_LOOP()
    add_executable(fuzz-sqlite-db fuzz/fuzz_db.c)
    target_link_libraries(fuzz-sqlite-db sqlite3_fuzz m dl pthread)

    # Fuzz target: SQL statement fuzzer
    add_executable(fuzz-sqlite-sql fuzz/fuzz_sql.c)
    target_link_libraries(fuzz-sqlite-sql sqlite3_fuzz m dl pthread)

    # Fuzz target: SQL + DB combined fuzzer
    add_executable(fuzz-sqlite-dbsql fuzz/fuzz_dbsql.c)
    target_link_libraries(fuzz-sqlite-dbsql sqlite3_fuzz m dl pthread)

    # Fuzz target: Prepared statement API fuzzer
    add_executable(fuzz-sqlite-stmt fuzz/fuzz_stmt.c)
    target_link_libraries(fuzz-sqlite-stmt sqlite3_fuzz m dl pthread)

    # Fuzz target: JSON functions fuzzer
    add_executable(fuzz-sqlite-json fuzz/fuzz_json.c)
    target_link_libraries(fuzz-sqlite-json sqlite3_fuzz m dl pthread)

    # Fuzz target: FTS (Full-Text Search) fuzzer
    add_executable(fuzz-sqlite-fts fuzz/fuzz_fts.c)
    target_link_libraries(fuzz-sqlite-fts sqlite3_fuzz m dl pthread)

    # Fuzz target: Expression fuzzer
    add_executable(fuzz-sqlite-expr fuzz/fuzz_expr.c)
    target_link_libraries(fuzz-sqlite-expr sqlite3_fuzz m dl pthread)

    # Fuzz target: ALTER TABLE / schema modification fuzzer
    add_executable(fuzz-sqlite-alter fuzz/fuzz_alter.c)
    target_link_libraries(fuzz-sqlite-alter sqlite3_fuzz m dl pthread)

    # Fuzz target: printf format string fuzzer
    add_executable(fuzz-sqlite-printf fuzz/fuzz_printf.c)
    target_link_libraries(fuzz-sqlite-printf sqlite3_fuzz m dl pthread)

    # Fuzz target: PRAGMA fuzzer
    add_executable(fuzz-sqlite-pragma fuzz/fuzz_pragma.c)
    target_link_libraries(fuzz-sqlite-pragma sqlite3_fuzz m dl pthread)

    # Fuzz target: R-Tree / Geospatial fuzzer
    add_executable(fuzz-sqlite-rtree fuzz/fuzz_rtree.c)
    target_link_libraries(fuzz-sqlite-rtree sqlite3_fuzz m dl pthread)

    # Fuzz target: Window functions fuzzer
    add_executable(fuzz-sqlite-window fuzz/fuzz_window.c)
    target_link_libraries(fuzz-sqlite-window sqlite3_fuzz m dl pthread)

    # Fuzz target: ATTACH/DETACH database fuzzer
    add_executable(fuzz-sqlite-attach fuzz/fuzz_attach.c)
    target_link_libraries(fuzz-sqlite-attach sqlite3_fuzz m dl pthread)

    # Fuzz target: Aggregate functions fuzzer
    add_executable(fuzz-sqlite-agg fuzz/fuzz_agg.c)
    target_link_libraries(fuzz-sqlite-agg sqlite3_fuzz m dl pthread)

    # Fuzz target: Deserialize database format fuzzer
    add_executable(fuzz-sqlite-deserialize fuzz/fuzz_deserialize.c)
    target_link_libraries(fuzz-sqlite-deserialize sqlite3_fuzz m dl pthread)

    # Fuzz target: CTE (Common Table Expressions) fuzzer
    add_executable(fuzz-sqlite-cte fuzz/fuzz_cte.c)
    target_link_libraries(fuzz-sqlite-cte sqlite3_fuzz m dl pthread)

    # Fuzz target: VACUUM/REINDEX maintenance fuzzer
    add_executable(fuzz-sqlite-vacuum fuzz/fuzz_vacuum.c)
    target_link_libraries(fuzz-sqlite-vacuum sqlite3_fuzz m dl pthread)

    # Fuzz target: Collation fuzzer
    add_executable(fuzz-sqlite-collation fuzz/fuzz_collation.c)
    target_link_libraries(fuzz-sqlite-collation sqlite3_fuzz m dl pthread)

    # Fuzz target: Session extension fuzzer
    add_executable(fuzz-sqlite-session fuzz/fuzz_session.c)
    target_link_libraries(fuzz-sqlite-session sqlite3_fuzz m dl pthread)

    # Fuzz target: Snapshot API fuzzer
    add_executable(fuzz-sqlite-snapshot fuzz/fuzz_snapshot.c)
    target_link_libraries(fuzz-sqlite-snapshot sqlite3_fuzz m dl pthread)

    # Fuzz target: Trigger fuzzer
    add_executable(fuzz-sqlite-trigger fuzz/fuzz_trigger.c)
    target_link_libraries(fuzz-sqlite-trigger sqlite3_fuzz m dl pthread)

    # Fuzz target: Foreign Key fuzzer
    add_executable(fuzz-sqlite-fkey fuzz/fuzz_fkey.c)
    target_link_libraries(fuzz-sqlite-fkey sqlite3_fuzz m dl pthread)

    # Fuzz target: Virtual Table fuzzer
    add_executable(fuzz-sqlite-vtab fuzz/fuzz_vtab.c)
    target_link_libraries(fuzz-sqlite-vtab sqlite3_fuzz m dl pthread)

    # Fuzz target: Savepoint/Transaction fuzzer
    add_executable(fuzz-sqlite-savepoint fuzz/fuzz_savepoint.c)
    target_link_libraries(fuzz-sqlite-savepoint sqlite3_fuzz m dl pthread)

    # Fuzz target: UPSERT/Conflict resolution fuzzer
    add_executable(fuzz-sqlite-upsert fuzz/fuzz_upsert.c)
    target_link_libraries(fuzz-sqlite-upsert sqlite3_fuzz m dl pthread)

    # Fuzz target: Subquery fuzzer
    add_executable(fuzz-sqlite-subquery fuzz/fuzz_subquery.c)
    target_link_libraries(fuzz-sqlite-subquery sqlite3_fuzz m dl pthread)

    # Fuzz target: Index/Constraint fuzzer
    add_executable(fuzz-sqlite-index fuzz/fuzz_index.c)
    target_link_libraries(fuzz-sqlite-index sqlite3_fuzz m dl pthread)

    # Fuzz target: BLOB I/O fuzzer
    add_executable(fuzz-sqlite-blob fuzz/fuzz_blob.c)
    target_link_libraries(fuzz-sqlite-blob sqlite3_fuzz m dl pthread)

    # Fuzz target: Authorization callback fuzzer
    add_executable(fuzz-sqlite-auth fuzz/fuzz_auth.c)
    target_link_libraries(fuzz-sqlite-auth sqlite3_fuzz m dl pthread)

    # Fuzz target: Backup API fuzzer
    add_executable(fuzz-sqlite-backup fuzz/fuzz_backup.c)
    target_link_libraries(fuzz-sqlite-backup sqlite3_fuzz m dl pthread)

    # Fuzz target: Date/Time functions fuzzer
    add_executable(fuzz-sqlite-datetime fuzz/fuzz_datetime.c)
    target_link_libraries(fuzz-sqlite-datetime sqlite3_fuzz m dl pthread)

    # Fuzz target: CAST/Type conversion fuzzer
    add_executable(fuzz-sqlite-cast fuzz/fuzz_cast.c)
    target_link_libraries(fuzz-sqlite-cast sqlite3_fuzz m dl pthread)
endif()
