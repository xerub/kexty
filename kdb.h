#ifndef KDB_H
#define KDB_H

struct kdb;

/*
CREATE TABLE Symbols(Kernel int, Symbol varchar(255), Value int);
INSERT INTO "Symbols" VALUES(1166736973,'_kOSBooleanTrue',2150771920);
INSERT INTO "Symbols" VALUES(1166736973,'_kOSBooleanFalse',2150771924);

1166736973 = djb_hash("Darwin Kernel Version 14.0.0: Fri Sep 27 23:00:47 PDT 2013; root:xnu-2423.3.12~1/RELEASE_ARM_S5L8950X")
*/

struct kdb *kdb_init(const char *database, const char *kernel);
unsigned long long kdb_find(struct kdb *k, const char *symbol);
void kdb_term(struct kdb *k);

unsigned int djb_hash(const char *key);

#endif
