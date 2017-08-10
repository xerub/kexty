/*
 *  kernel symbol resolver
 *
 *  Copyright (c) 2015 xerub
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include "kdb.h"

struct kdb {
    sqlite3 *db;
    sqlite3_stmt *stmt;
};

unsigned int
djb_hash(const char *key)
{
    unsigned int hash = 5381;

    for (; *key; key++) {
        hash = ((hash << 5) + hash) + (*key);
    }

    return hash;
}

struct kdb *
kdb_init(const char *database, const char *kernel)
{
    int rv;
    char *sql;
    sqlite3 *db;
    sqlite3_stmt *stmt;
    struct kdb *k;

    if (!kernel) {
        return NULL;
    }

    k = malloc(sizeof(struct kdb));
    if (!k) {
        return NULL;
    }

    rv = sqlite3_open_v2(database, &db, SQLITE_OPEN_READONLY, NULL);
    if (rv) {
        sqlite3_close(db);
        free(k);
        return NULL;
    }

    sql = "SELECT Value FROM Symbols WHERE Kernel IS ?1 AND Symbol IS ?2";
    rv = sqlite3_prepare_v2(db, sql, strlen(sql) + 1, &stmt, NULL);
    if (rv) {
        sqlite3_close(db);
        free(k);
        return NULL;
    }

    rv = sqlite3_bind_int64(stmt, 1, djb_hash(kernel));
    if (rv) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        free(k);
        return NULL;
    }

    k->db = db;
    k->stmt = stmt;
    return k;
}

unsigned long long
kdb_find(struct kdb *k, const char *symbol)
{
    int rv;
    int err = 0;
    int row = 0;

    sqlite3_stmt *stmt;
    sqlite3_int64 x = 0;

    if (!k) {
        return 0;
    }
    stmt = k->stmt;

    rv = sqlite3_reset(stmt);
    if (rv) {
        return 0;
    }

    rv = sqlite3_bind_text(stmt, 2, symbol, strlen(symbol), SQLITE_STATIC);
    if (rv) {
        return 0;
    }

    while (1) {
        rv = sqlite3_step(stmt);
        if (rv == SQLITE_ROW) {
            if (row) {
                err = 1;
                break;
            }
            x = sqlite3_column_int64(stmt, 0);
            row++;
#if 666 /* a bit faster */
            break;
#endif
        } else if (rv == SQLITE_DONE) {
            break;
        } else {
            err = 2;
            break;
        }
    }

    if (err || !row) {
        return 0;
    }
    return x;
}

void
kdb_term(struct kdb *k)
{
    if (k) {
        sqlite3_finalize(k->stmt);
        sqlite3_close(k->db);
        free(k);
    }
}

#if 0
int
main(void)
{
    struct kdb *k;
    unsigned long long x;

    k = kdb_init("kernel.db", "Darwin Kernel Version 14.0.0: Fri Sep 27 23:00:47 PDT 2013; root:xnu-2423.3.12~1/RELEASE_ARM_S5L8950X");

    x = kdb_find(k, "_kOSBooleanTrue");
    printf("0x%llx\n", x);

    x = kdb_find(k, "_kOSBooleanFalse");
    printf("0x%llx\n", x);

    kdb_term(k);
    return 0;
}
#endif
