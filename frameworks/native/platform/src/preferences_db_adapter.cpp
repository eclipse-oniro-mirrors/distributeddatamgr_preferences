/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "preferences_db_adapter.h"

#ifndef _WIN32
#include <dlfcn.h>
#endif

#include "log_print.h"
#include "preferences_errno.h"

namespace OHOS {
namespace NativePreferences {

void *PreferenceDbAdapter::gLibrary_ = NULL;

std::mutex PreferenceDbAdapter::apiMutex_;

GRD_APIInfo PreferenceDbAdapter::api_;

std::atomic<bool> PreferenceDbAdapter::isInit_ = false;

void GRD_DBApiInitEnhance(GRD_APIInfo &GRD_DBApiInfo)
{
#ifndef _WIN32
    GRD_DBApiInfo.DbOpenApi = (DBOpen)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_DBOpen");
    GRD_DBApiInfo.DbCloseApi = (DBClose)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_DBClose");
    GRD_DBApiInfo.DbCreateCollectionApi = (DBCreateCollection)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_CreateCollection");
    GRD_DBApiInfo.DbDropCollectionApi = (DBDropCollection)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_DropCollection");
    GRD_DBApiInfo.DbIndexPreloadApi = (DBIndexPreload)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_IndexPreload");
    GRD_DBApiInfo.DbKvPutApi = (DBKvPut)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_KVPut");
    GRD_DBApiInfo.DbKvGetApi = (DBKvGet)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_KVGet");
    GRD_DBApiInfo.DbKvDelApi = (DBKvDel)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_KVDel");
    GRD_DBApiInfo.DbKvFilterApi = (DBKvFilter)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_KVFilter");
    GRD_DBApiInfo.NextApi = (ResultNext)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_Next");
    GRD_DBApiInfo.GetValueApi = (GetValue)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_GetValue");
    GRD_DBApiInfo.GetItemApi = (GetItem)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_GetItem");
    GRD_DBApiInfo.GetItemSizeApi = (GetItemSize)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_KVGetSize");
    GRD_DBApiInfo.FetchApi = (Fetch)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_Fetch");
    GRD_DBApiInfo.FreeValueApi = (KVFreeItem)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_FreeValue");
    GRD_DBApiInfo.FreeResultSetApi = (FreeResultSet)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_FreeResultSet");
#endif
}

// todo hbx: 错误码转换
// const GrdErrnoPair GRD_ERRNO_MAP[] = {
//     { GRD_OK, E_OK },
//     { GRD_NOT_SUPPORT, -E_NOT_SUPPORT },
//     { GRD_OVER_LIMIT, -E_MAX_LIMITS },
//     { GRD_INVALID_ARGS, -E_INVALID_ARGS },
//     { GRD_FAILED_FILE_OPERATION, -E_SYSTEM_PreferenceDbAdapter::api_FAIL },
//     { GRD_INVALID_FILE_FORMAT, -E_INVALID_PASSWD_OR_CORRUPTED_DB },
//     { GRD_INSUFFICIENT_SPACE, -E_INTERNAL_ERROR },
//     { GRD_INNER_ERR, -E_INTERNAL_ERROR },
//     { GRD_RESOURCE_BUSY, -E_BUSY },
//     { GRD_NO_DATA, -E_NOT_FOUND },
//     { GRD_FAILED_MEMORY_ALLOCATE, -E_OUT_OF_MEMORY },
//     { GRD_FAILED_MEMORY_RELEASE, -E_OUT_OF_MEMORY },
//     { GRD_DATA_CONFLICT, -E_INVALID_DATA },
//     { GRD_NOT_AVAILABLE, -E_NOT_FOUND },
//     { GRD_INVALID_FORMAT, -E_INVALID_FORMAT },
//     { GRD_TIME_OUT, -E_TIMEOUT },
//     { GRD_DB_INSTANCE_ABNORMAL, -E_INTERNAL_ERROR },
//     { GRD_DISK_SPACE_FULL, -E_INTERNAL_ERROR },
//     { GRD_CRC_CHECK_DISABLED, -E_INVALID_ARGS },
//     { GRD_PERMISSION_DENIED, -E_DENIED_SQL },
//     { GRD_REBUILD_DATABASE, -E_REBUILD_DATABASE}, // rebuild database means ok
// };

int TransferGrdErrno(int err)
{
    if (err > 0) {
        return err;
    }
//     for (const auto &item : GRD_ERRNO_MAP) {
//         if (item.grdCode == err) {
//             return item.kvDbCode;
//         }
//     }
    return E_ERROR;
}

bool PreferenceDbAdapter::IsRdLoad()
{
    return PreferenceDbAdapter::gLibrary_ != NULL;
}

GRD_APIInfo& PreferenceDbAdapter::GetApiInstance()
{
    if (PreferenceDbAdapter::isInit_) {
        return PreferenceDbAdapter::api_;
    }
    ApiInit();
    return PreferenceDbAdapter::api_;
}

void PreferenceDbAdapter::ApiInit()
{
    if (PreferenceDbAdapter::isInit_) {
        return;
    }
    std::lock_guard<std::mutex> lck(PreferenceDbAdapter::apiMutex_);
#ifndef _WIN32
    PreferenceDbAdapter::gLibrary_ = dlopen("libgaussdb_rd_vector.z.so", RTLD_LAZY);
    if (PreferenceDbAdapter::gLibrary_ != nullptr) {
        GRD_DBApiInitEnhance(PreferenceDbAdapter::api_);
    } else {
        LOG_DEBUG("use default db kernel");
    }
#endif
    PreferenceDbAdapter::isInit_ = true;
    return;
}

PreferencesDb::PreferencesDb()
{
}
PreferencesDb::~PreferencesDb()
{
    if (db_ != nullptr) {
        PreferenceDbAdapter::GetApiInstance().DbCloseApi(db_, GRD_DB_CLOSE_IGNORE_ERROR);
    }
}

int PreferencesDb::Init(const std::string &dbPath)
{
    if(db_ != nullptr) {
        LOG_DEBUG("db handle is already inited");
        return E_OK;
    }
    std::string configStr = R"("pageSize": 4, "redoFlushByTrx": 1, "redoPubBufSize": 256, "maxConnNum": 100,
        "bufferPoolSize": 512, "crcCheckEnable": 0, "bufferPoolPolicy": "BUF_PRIORITY_INDEX")";
    int errCode = TransferGrdErrno(PreferenceDbAdapter::GetApiInstance().DbOpenApi(dbPath.c_str(), configStr.c_str(), GRD_DB_OPEN_CREATE,
        &db_));
    if (errCode != E_OK) {
        LOG_ERROR("rd open failed:%d", errCode);
        return errCode;
    }
    errCode = TransferGrdErrno(PreferenceDbAdapter::GetApiInstance().DbCreateCollectionApi(db_, TABLENAME, TABLE_MODE, 0));
    if (errCode != E_OK) {
        LOG_ERROR("rd create table failed:%d", errCode);
        return errCode;
    }
    errCode = TransferGrdErrno(PreferenceDbAdapter::GetApiInstance().DbCreateCollectionApi(db_, TABLENAME, TABLE_MODE, 0));
    if (errCode != E_OK) {
        LOG_ERROR("rd create table failed:%d", errCode);
        return errCode;
    }
    errCode = TransferGrdErrno(PreferenceDbAdapter::GetApiInstance().DbIndexPreloadApi(db_, TABLENAME));
    if (errCode != E_OK) {
        LOG_ERROR("[RdSingleVerStorageEngine] GRD_IndexPreload FAILED %d", errCode);
        return errCode;
    }
    return errCode;
}

int PreferencesDb::Put(const std::vector<uint8_t> &key, const std::vector<uint8_t> &value)
{
    if (db_ == nullptr) {
        LOG_DEBUG("db handle is nullptr");
        return E_ERROR;
    }
    GRD_KVItemT innerKey = BlobToKvItem(key);
    GRD_KVItemT innerVal = BlobToKvItem(value);
    int ret = TransferGrdErrno(PreferenceDbAdapter::GetApiInstance().DbKvPutApi(db_, TABLENAME, &innerKey, &innerVal));
    if (ret != E_OK) {
        LOG_ERROR("rd put failed:%d", ret);
    }
    return ret;
}

int PreferencesDb::Delete(const std::vector<uint8_t> &key)
{
    if (db_ == nullptr) {
        LOG_DEBUG("db handle is nullptr");
        return E_ERROR;
    }
    GRD_KVItemT innerKey = BlobToKvItem(key);
    int ret = TransferGrdErrno(PreferenceDbAdapter::GetApiInstance().DbKvDelApi(db_, TABLENAME, &innerKey));
    if (ret != E_OK) {
        LOG_ERROR("rd put failed:%d", ret);
    }
    return ret;
}
int PreferencesDb::Get(const std::vector<uint8_t> &key, std::vector<uint8_t> &value)
{
    if (db_ == nullptr) {
        LOG_DEBUG("db handle is nullptr");
        return E_ERROR;
    }
    GRD_KVItemT innerKey = BlobToKvItem(key);
    GRD_KVItemT innerVal = { 0 };
    int ret = TransferGrdErrno(PreferenceDbAdapter::GetApiInstance().DbKvGetApi(db_, TABLENAME, &innerKey, &innerVal));
    if (ret != E_OK) {
        LOG_ERROR("[rdUtils][GetKvData] Cannot get the data %d", ret);
        return ret;
    }
    value.resize(innerVal.dataLen);
    value = KvItemToBlob(innerVal);
    (void)PreferenceDbAdapter::GetApiInstance().FreeValueApi(&innerVal);
    return E_OK;
}

int PreferencesDb::GetAll(std::list<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &data)
{
    if (db_ == nullptr) {
        LOG_DEBUG("db handle is nullptr");
        return E_ERROR;
    }
    GRD_FilterOptionT param;
    param.mode = KV_SCAN_PREFIX; // need change later
    param.begin = { nullptr, 0};
    param.end = { nullptr, 0};
    GRD_ResultSet *resultSet = nullptr;
    int ret = TransferGrdErrno(PreferenceDbAdapter::GetApiInstance().DbKvFilterApi(db_, TABLENAME, &param, &resultSet));
    if (ret != E_OK) {
        LOG_ERROR("ger reulstSet failed %d", ret);
        return ret;
    }
    while (TransferGrdErrno(PreferenceDbAdapter::GetApiInstance().NextApi(resultSet)) == E_OK) {
        std::pair<std::vector<uint8_t>, std::vector<uint8_t>> dataIem;
        uint32_t keySize = 0;
        uint32_t valueSize = 0;
        ret = TransferGrdErrno(PreferenceDbAdapter::GetApiInstance().GetItemSizeApi(resultSet, &keySize, &valueSize));
        if (ret != E_OK) {
            LOG_ERROR("ger reulstSet kv size failed %d", ret);
            PreferenceDbAdapter::GetApiInstance().FreeResultSetApi(resultSet);
            return ret;
        }
        dataIem.first.resize(keySize);
        dataIem.second.resize(valueSize);
        GRD_KVItem key = {dataIem.first.data(), 0};
        GRD_KVItem value = {dataIem.second.data(), 0};
        ret = TransferGrdErrno(PreferenceDbAdapter::GetApiInstance().GetItemApi(resultSet, &key, &value));
        if (ret != E_OK) {
            LOG_ERROR("ger reulstSet failed %d", ret);
            PreferenceDbAdapter::GetApiInstance().FreeResultSetApi(resultSet);
            return ret;
        }
        data.emplace_back(std::move(dataIem));
    }
    return E_OK;
}

GRD_KVItemT PreferencesDb::BlobToKvItem(const std::vector<uint8_t> &blob)
{
    return {
        .data = (void *)&blob[0],
        .dataLen = (uint32_t)blob.size()
    };
}

std::vector<uint8_t> PreferencesDb::KvItemToBlob(GRD_KVItemT &item)
{
    return std::vector<uint8_t>((uint8_t *)item.data, (uint8_t *)item.data + item.dataLen);
}
} // End of namespace NativePreferences
} // End of namespace OHOS