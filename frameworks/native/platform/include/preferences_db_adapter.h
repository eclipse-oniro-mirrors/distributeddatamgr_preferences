/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PREFERENCES_DB_ADAPTER_H
#define PREFERENCES_DB_ADAPTER_H

#include <vector>
#include <shared_mutex>
#include <list>

#include <string>
namespace OHOS {
namespace NativePreferences {

typedef struct GRD_DB GRD_DB;

const char * const TABLENAME = "preferences_data";
const char * const TABLE_MODE = "{\"mode\" : \"kv\", \"indextype\" : \"hash\"}";

#define GRD_DB_OPEN_CREATE 0x01
#define GRD_DB_CLOSE_IGNORE_ERROR 0x01

typedef struct GRD_KVItem {
    void *data;
    uint32_t dataLen;
} GRD_KVItemT;

typedef enum GRD_KvScanMode {
    KV_SCAN_PREFIX = 0,
    KV_SCAN_EQUAL_OR_LESS_KEY = 1,
    KV_SCAN_EQUAL_OR_GREATER_KEY = 2,
    KV_SCAN_RANGE = 3,
    KV_SCAN_ALL = 4,
    KV_SCAN_BUTT    // INVALID SCAN
} GRD_KvScanModeE;

typedef struct GRD_FilterOption {
    GRD_KvScanModeE mode;
    GRD_KVItemT begin;
    GRD_KVItemT end;
} GRD_FilterOptionT;

typedef struct GRD_ResultSet GRD_ResultSet;

typedef int32_t (*DBOpen)(const char *dbPath, const char *configStr, uint32_t flags, GRD_DB **db);
typedef int32_t (*DBClose)(GRD_DB *db, uint32_t flags);
typedef int32_t (*DBCreateCollection)(GRD_DB *db, const char *tableName, const char *optionStr, uint32_t flags);
typedef int32_t (*DBDropCollection)(GRD_DB *db, const char *collectionName, uint32_t flags);
typedef int32_t (*DBIndexPreload)(GRD_DB *db, const char *tableName);
typedef int32_t (*DBKvPut)(GRD_DB *db, const char *tableName, const GRD_KVItemT *key, const GRD_KVItemT *value);
typedef int32_t (*DBKvGet)(GRD_DB *db, const char *tableName, const GRD_KVItemT *key, const GRD_KVItemT *value);
typedef int32_t (*DBKvDel)(GRD_DB *db, const char *tableName, const GRD_KVItemT *key);
typedef int32_t (*DBKvFilter)(GRD_DB *db, const char *tableName, const GRD_FilterOptionT *scanParams,
    GRD_ResultSet **resultSet);

typedef int32_t (*ResultNext)(GRD_ResultSet *resultset);
typedef int32_t (*GetValue)(GRD_ResultSet *resultSet, char **value);
typedef int32_t (*GetItem)(GRD_ResultSet *resultSet, void *key, void *value);
typedef int32_t (*GetItemSize)(GRD_ResultSet *resultSet, uint32_t *keySize, uint32_t *valueSize);
typedef int32_t (*Fetch)(GRD_ResultSet *resultSet, GRD_KVItemT *key, GRD_KVItemT *value);
typedef int32_t (*KVFreeItem)(GRD_KVItemT *item);
typedef int32_t (*FreeResultSet)(GRD_ResultSet *resultSet);

struct GRD_APIInfo {
    DBOpen DbOpenApi = nullptr;
    DBClose DbCloseApi = nullptr;
    DBCreateCollection DbCreateCollectionApi = nullptr;
    DBDropCollection DbDropCollectionApi = nullptr;
    DBIndexPreload DbIndexPreloadApi = nullptr;
    DBKvPut DbKvPutApi = nullptr;
    DBKvGet DbKvGetApi = nullptr;
    DBKvDel DbKvDelApi = nullptr;
    DBKvFilter DbKvFilterApi = nullptr;
    ResultNext NextApi = nullptr;
    GetValue GetValueApi = nullptr;
    GetItem GetItemApi = nullptr;
    GetItemSize GetItemSizeApi = nullptr;
    Fetch FetchApi = nullptr;
    KVFreeItem FreeItemApi = nullptr;
    FreeResultSet FreeResultSetApi = nullptr;
};

class PreferenceDbAdapter {
public:
    static bool IsEnhandceDbEnable();
    static GRD_APIInfo& GetApiInstance();
    static void ApiInit();

    static void *gLibrary_;
    static std::mutex apiMutex_;
    static GRD_APIInfo api_;
    static std::atomic<bool> isInit_;
};


class PreferencesDb {
public:
    PreferencesDb();
    ~PreferencesDb();
    int Init(const std::string &dbPath);
    int Put(const std::vector<uint8_t> &key, const std::vector<uint8_t> &value);
    int Delete(const std::vector<uint8_t> &key);
    int Get(const std::vector<uint8_t> &key, std::vector<uint8_t> &value);
    int GetAll(std::list<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &data);
private:
    GRD_KVItemT BlobToKvItem(const std::vector<uint8_t> &blob);
    std::vector<uint8_t> KvItemToBlob(GRD_KVItemT &item);
    GRD_DB *db_ = nullptr;
};

// grd errcode
#define GRD_OK 0
#define GRD_NOT_SUPPORT (-1000)
#define GRD_OVER_LIMIT (-2000)
#define GRD_INVALID_ARGS (-3000)
#define GRD_FAILED_MEMORY_ALLOCATE (-13000)
#define GRD_FAILED_MEMORY_RELEASE (-14000)
#define GRD_PERMISSION_DENIED (-43000)

} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_THREAD_H