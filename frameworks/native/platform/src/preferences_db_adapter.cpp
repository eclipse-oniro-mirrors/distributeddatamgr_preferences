/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <map>
#include <thread>
#include "preferences_db_adapter.h"
#include "log_print.h"
#include "preferences_errno.h"
#include "preferences_file_operation.h"

namespace OHOS {
namespace NativePreferences {

void *PreferenceDbAdapter::gLibrary_ = NULL;

std::mutex PreferenceDbAdapter::apiMutex_;

GRD_APIInfo PreferenceDbAdapter::api_;

std::atomic<bool> PreferenceDbAdapter::isInit_ = false;

#if !defined(WINDOWS_PLATFORM)
static const std::chrono::milliseconds WAIT_REPAIRE_TIMEOUT(5);
#endif

const char * const TABLENAME = "preferences_data";
const char * const TABLE_MODE = "{\"mode\" : \"kv\", \"indextype\" : \"hash\"}";
const char * const CONFIG_STR =
    "{\"pageSize\": 4, \"redoFlushByTrx\": 2, \"redoPubBufSize\": 256, \"maxConnNum\": 100, "
    "\"bufferPoolSize\": 1024, \"crcCheckEnable\": 0, \"bufferPoolPolicy\" : \"BUF_PRIORITY_INDEX\", "
    "\"sharedModeEnable\" : 1, \"MetaInfoBak\": 1}";
const int CREATE_COLLECTION_RETRY_TIMES = 2;
const int DB_REPAIR_RETRY_TIMES = 3;

void GRDDBApiInitEnhance(GRD_APIInfo &GRD_DBApiInfo)
{
#ifndef _WIN32
    GRD_DBApiInfo.DbOpenApi = (DBOpen)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_DBOpen");
    GRD_DBApiInfo.DbCloseApi = (DBClose)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_DBClose");
    GRD_DBApiInfo.DbCreateCollectionApi = (DBCreateCollection)dlsym(PreferenceDbAdapter::gLibrary_,
        "GRD_CreateCollection");
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
    GRD_DBApiInfo.FreeItemApi = (KVFreeItem)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_KVFreeItem");
    GRD_DBApiInfo.FreeResultSetApi = (FreeResultSet)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_FreeResultSet");
    GRD_DBApiInfo.DbRepairApi = (DBRepair)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_DBRepair");
    GRD_DBApiInfo.DbGetConfigApi = (DBGetConfig)dlsym(PreferenceDbAdapter::gLibrary_, "GRD_GetConfig");
#endif
}

const std::map<int, int> GRDErrnoMap = {
    { GRD_OK, E_OK },
    { GRD_NOT_SUPPORT, E_NOT_SUPPORTED },
    { GRD_OVER_LIMIT, E_DEFAULT_EXCEED_LENGTH_LIMIT },
    { GRD_INVALID_ARGS, E_INVALID_ARGS },
    { GRD_FAILED_MEMORY_ALLOCATE, E_OUT_OF_MEMORY },
    { GRD_FAILED_MEMORY_RELEASE, E_OUT_OF_MEMORY },
    { GRD_PERMISSION_DENIED, PERMISSION_DENIED },
    { GRD_NO_DATA, E_NO_DATA }
};

int TransferGrdErrno(int err)
{
    if (err > 0) {
        return err;
    }

    auto iter = GRDErrnoMap.find(err);
    if (iter != GRDErrnoMap.end()) {
        return iter->second;
    }

    return E_ERROR;
}

bool PreferenceDbAdapter::IsEnhandceDbEnable()
{
    return PreferenceDbAdapter::gLibrary_ != nullptr;
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
    if (PreferenceDbAdapter::isInit_) {
        return;
    }
    PreferenceDbAdapter::gLibrary_ = DBDlOpen();
    if (PreferenceDbAdapter::gLibrary_ != nullptr) {
        GRDDBApiInitEnhance(PreferenceDbAdapter::api_);
    } else {
        LOG_DEBUG("use default db kernel");
    }
    PreferenceDbAdapter::isInit_ = true;
    return;
}

PreferencesDb::PreferencesDb()
{
}

PreferencesDb::~PreferencesDb()
{
    if (db_ != nullptr || PreferenceDbAdapter::GetApiInstance().DbCloseApi != nullptr) {
        PreferenceDbAdapter::GetApiInstance().DbCloseApi(db_, GRD_DB_CLOSE_IGNORE_ERROR);
        db_ = nullptr;
        LOG_DEBUG("destructor: calling close db.");
    } else {
        LOG_DEBUG("destructor: db closed before or dbClose api not loaded, db closed before ? %{public}d.",
            db_ == nullptr);
    }
}

ReportParam PreferencesDb::GetReportParam(const std::string &info, uint32_t errCode)
{
    ReportParam reportParam = {
        bundleName_,
        ENHANCE_DB,
        ExtractFileName(dbPath_),
        errCode,
        errno,
        info};
    return reportParam;
}

int PreferencesDb::CloseDb()
{
    if (db_ != nullptr) {
        if (PreferenceDbAdapter::GetApiInstance().DbCloseApi == nullptr) {
            LOG_ERROR("api load failed: DbCloseApi");
            return E_ERROR;
        }
        int errCode = PreferenceDbAdapter::GetApiInstance().DbCloseApi(db_, GRD_DB_CLOSE_IGNORE_ERROR);
        if (errCode != E_OK) {
            LOG_ERROR("close db failed, errcode=%{public}d, file: %{public}s", errCode,
                ExtractFileName(dbPath_).c_str());
            return TransferGrdErrno(errCode);
        }
        LOG_INFO("db has been closed.");
        db_ = nullptr;
        return E_OK;
    }
    LOG_INFO("CloseDb: DB closed before.");
    return E_OK;
}

int PreferencesDb::CreateCollection()
{
    if (PreferenceDbAdapter::GetApiInstance().DbCreateCollectionApi == nullptr) {
        LOG_ERROR("api load failed: DbCreateCollectionApi");
        return E_ERROR;
    }
    int errCode = PreferenceDbAdapter::GetApiInstance().DbCreateCollectionApi(db_, TABLENAME,
        TABLE_MODE, 0);
    if (errCode != GRD_OK) {
        LOG_ERROR("rd create table failed:%{public}d", errCode);
    }
    return TransferGrdErrno(errCode);
}

int PreferencesDb::OpenDb(bool isNeedRebuild)
{
    if (PreferenceDbAdapter::GetApiInstance().DbOpenApi == nullptr) {
        LOG_ERROR("api load failed: DbOpenApi");
        return E_ERROR;
    }
    uint32_t flag = GRD_DB_OPEN_CREATE;
    if (isNeedRebuild) {
        flag |= GRD_DB_OPEN_CHECK;
    }
    int errCode = PreferenceDbAdapter::GetApiInstance().DbOpenApi(dbPath_.c_str(), CONFIG_STR, flag, &db_);
    if (errCode != GRD_OK) {
        // log outside
        std::string errMsg = isNeedRebuild ? "open db failed with open_create | open_check" :
                "open db failed with open_create";
        LOG_ERROR("%{public}s, errCode: %{public}d, isRebuild:%{public}d", errMsg.c_str(), errCode, isNeedRebuild);
    }
    return errCode;
}

int PreferencesDb::RepairDb()
{
    if (PreferenceDbAdapter::GetApiInstance().DbRepairApi == nullptr) {
        LOG_ERROR("api load failed: DbRepairApi");
        return E_ERROR;
    }
    int errCode = PreferenceDbAdapter::GetApiInstance().DbRepairApi(dbPath_.c_str(), CONFIG_STR);
    if (errCode != GRD_OK) {
        std::string errMsg = "db repair failed";
        LOG_ERROR("repair db failed, errCode: %{public}d", errCode);
    }
    return errCode;
}

int PreferencesDb::TryRepairAndRebuild(int openCode)
{
    LOG_ERROR("db corrupted, errCode: %{public}d, begin to rebuild, db: %{public}s", openCode,
        ExtractFileName(dbPath_).c_str());
    int retryTimes = DB_REPAIR_RETRY_TIMES;
    int innerErr = GRD_OK;
    do {
        innerErr = RepairDb();
        if (innerErr == GRD_OK) {
            LOG_INFO("db repair success");
            return innerErr;
        } else if (innerErr == GRD_DB_BUSY) {
            LOG_ERROR("db repair failed, busy, retry times : %{public}d, errCode: %{public}d",
                (DB_REPAIR_RETRY_TIMES - retryTimes + 1), innerErr);
#if !defined(WINDOWS_PLATFORM)
            std::this_thread::sleep_for(WAIT_REPAIRE_TIMEOUT);
#endif
        } else {
            // other error, break to rebuild
            LOG_ERROR("db repair failed: %{public}d, begin to rebuild", innerErr);
            break;
        }
        retryTimes--;
    } while (retryTimes > 0);

    innerErr = OpenDb(true);
    if (innerErr == GRD_OK || innerErr == GRD_REBUILD_DATABASE) {
        LOG_INFO("rebuild db success, errCode: %{public}d", innerErr);
        return GRD_OK;
    }
    LOG_ERROR("rebuild db failed, errCode: %{public}d, file: %{public}s", innerErr, ExtractFileName(dbPath_).c_str());
    return innerErr;
}

int PreferencesDb::Init(const std::string &dbPath, const std::string &bundleName)
{
    if (db_ != nullptr) {
        LOG_DEBUG("Init: already init.");
        return E_OK;
    }
    if (PreferenceDbAdapter::GetApiInstance().DbIndexPreloadApi == nullptr) {
        LOG_ERROR("api load failed: DbIndexPreloadApi");
        return E_ERROR;
    }
    dbPath_ = dbPath + ".db";
    bundleName_ = bundleName;
    int errCode = OpenDb(false);
    if (errCode == GRD_DATA_CORRUPTED) {
        PreferencesDfxManager::ReportDbFault(GetReportParam("db corrupted", errCode));
    }
    if (errCode == GRD_DATA_CORRUPTED || errCode == GRD_INNER_ERR) {
        int innerErr = TryRepairAndRebuild(errCode);
        if (innerErr != GRD_OK) {
            // log inside
            return TransferGrdErrno(innerErr);
        }
        if (errCode == GRD_DATA_CORRUPTED) {
            ReportParam param = GetReportParam("db repair success", GRD_OK);
            param.errnoCode = 0;
            PreferencesDfxManager::ReportDbFault(param);
        }
    } else if (errCode != GRD_OK) {
        LOG_ERROR("db open failed, errCode: %{public}d", errCode);
        return TransferGrdErrno(errCode);
    }

    errCode = CreateCollection();
    if (errCode != E_OK) {
        LOG_ERROR("create collection failed when init: %{public}d, but ignored.", errCode);
        // ignore create collection error
    }

    errCode = TransferGrdErrno(PreferenceDbAdapter::GetApiInstance().DbIndexPreloadApi(db_, TABLENAME));
    if (errCode != E_OK) {
        LOG_ERROR("Init: Index preload FAILED %{public}d", errCode);
        return errCode;
    }
    return errCode;
}

int PreferencesDb::Put(const std::vector<uint8_t> &key, const std::vector<uint8_t> &value)
{
    if (db_ == nullptr) {
        LOG_ERROR("Put failed, db has been closed.");
        return E_ALREADY_CLOSED;
    } else if (PreferenceDbAdapter::GetApiInstance().DbKvPutApi == nullptr) {
        LOG_ERROR("api load failed: DbKvPutApi");
        return E_ERROR;
    }

    GRD_KVItemT innerKey = BlobToKvItem(key);
    GRD_KVItemT innerVal = BlobToKvItem(value);

    int retryTimes = CREATE_COLLECTION_RETRY_TIMES;
    int ret = E_OK;
    do {
        ret = PreferenceDbAdapter::GetApiInstance().DbKvPutApi(db_, TABLENAME, &innerKey, &innerVal);
        if (ret == GRD_UNDEFINED_TABLE) {
            LOG_INFO("CreateCollection called when Put, file: %{public}s", ExtractFileName(dbPath_).c_str());
            (void)CreateCollection();
        } else {
            if (ret == GRD_OK) {
                return TransferGrdErrno(ret);
            } else {
                LOG_ERROR("rd put failed:%{public}d", ret);
                return TransferGrdErrno(ret);
            }
        }
        retryTimes--;
    } while (retryTimes > 0);

    LOG_ERROR("rd put over retry times, errcode: :%{public}d", ret);
    return TransferGrdErrno(ret);
}

int PreferencesDb::Delete(const std::vector<uint8_t> &key)
{
    if (db_ == nullptr) {
        LOG_ERROR("Delete failed, db has been closed.");
        return E_ALREADY_CLOSED;
    } else if (PreferenceDbAdapter::GetApiInstance().DbKvDelApi == nullptr) {
        LOG_ERROR("api load failed: DbKvDelApi");
        return E_ERROR;
    }

    GRD_KVItemT innerKey = BlobToKvItem(key);

    int retryTimes = CREATE_COLLECTION_RETRY_TIMES;
    int ret = E_OK;
    do {
        ret = PreferenceDbAdapter::GetApiInstance().DbKvDelApi(db_, TABLENAME, &innerKey);
        if (ret == GRD_UNDEFINED_TABLE) {
            LOG_INFO("CreateCollection called when Delete, file: %{public}s", ExtractFileName(dbPath_).c_str());
            (void)CreateCollection();
        } else {
            if (ret == E_OK) {
                return TransferGrdErrno(ret);
            } else {
                LOG_ERROR("rd delete failed:%{public}d", ret);
                return TransferGrdErrno(ret);
            }
        }
        retryTimes--;
    } while (retryTimes > 0);

    LOG_ERROR("rd delete over retry times, errcode: :%{public}d", ret);
    return TransferGrdErrno(ret);
}

int PreferencesDb::Get(const std::vector<uint8_t> &key, std::vector<uint8_t> &value)
{
    if (db_ == nullptr) {
        LOG_ERROR("Get failed, db has been closed.");
        return E_ALREADY_CLOSED;
    } else if (PreferenceDbAdapter::GetApiInstance().DbKvGetApi == nullptr ||
        PreferenceDbAdapter::GetApiInstance().FreeItemApi == nullptr) {
        LOG_ERROR("api load failed: DbKvGetApi or FreeItemApi");
        return E_ERROR;
    }

    GRD_KVItemT innerKey = BlobToKvItem(key);
    GRD_KVItemT innerVal = { NULL, 0 };

    int retryTimes = CREATE_COLLECTION_RETRY_TIMES;
    int ret = E_OK;
    do {
        ret = PreferenceDbAdapter::GetApiInstance().DbKvGetApi(db_, TABLENAME, &innerKey, &innerVal);
        if (ret == GRD_UNDEFINED_TABLE) {
            LOG_INFO("CreateCollection called when Get, file: %{public}s", ExtractFileName(dbPath_).c_str());
            (void)CreateCollection();
        } else {
            if (ret == E_OK) {
                break;
            } else {
                LOG_ERROR("rd get failed:%{public}d", ret);
                return TransferGrdErrno(ret);
            }
        }
        retryTimes--;
    } while (retryTimes > 0);

    if (retryTimes == 0) {
        LOG_ERROR("rd get over retry times, errcode: :%{public}d", ret);
        return TransferGrdErrno(ret);
    }
    value.resize(innerVal.dataLen);
    value = KvItemToBlob(innerVal);
    (void)PreferenceDbAdapter::GetApiInstance().FreeItemApi(&innerVal);
    return TransferGrdErrno(ret);
}

int PreferencesDb::GetAllInner(std::list<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &data,
    GRD_ResultSet *resultSet)
{
    if (PreferenceDbAdapter::GetApiInstance().NextApi == nullptr ||
        PreferenceDbAdapter::GetApiInstance().GetItemSizeApi == nullptr ||
        PreferenceDbAdapter::GetApiInstance().FreeResultSetApi == nullptr ||
        PreferenceDbAdapter::GetApiInstance().GetItemApi == nullptr) {
        LOG_ERROR("api load failed: NextApi or GetItemSizeApi or FreeResultSetApi or GetItemApi");
        return E_ERROR;
    }
    int ret = E_OK;
    while (TransferGrdErrno(PreferenceDbAdapter::GetApiInstance().NextApi(resultSet)) == E_OK) {
        std::pair<std::vector<uint8_t>, std::vector<uint8_t>> dataItem;
        uint32_t keySize = 0;
        uint32_t valueSize = 0;
        ret = PreferenceDbAdapter::GetApiInstance().GetItemSizeApi(resultSet, &keySize, &valueSize);
        if (ret != GRD_OK) {
            LOG_ERROR("ger reulstSet kv size failed %{public}d", ret);
            PreferenceDbAdapter::GetApiInstance().FreeResultSetApi(resultSet);
            return TransferGrdErrno(ret);
        }
        dataItem.first.resize(keySize);
        dataItem.second.resize(valueSize);
        ret = PreferenceDbAdapter::GetApiInstance().GetItemApi(resultSet, dataItem.first.data(),
            dataItem.second.data());
        if (ret != E_OK) {
            LOG_ERROR("ger reulstSet failed %{public}d", ret);
            PreferenceDbAdapter::GetApiInstance().FreeResultSetApi(resultSet);
            return TransferGrdErrno(ret);
        }
        data.emplace_back(std::move(dataItem));
    }
    return TransferGrdErrno(ret);
}

int PreferencesDb::GetAll(std::list<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &data)
{
    if (db_ == nullptr) {
        LOG_ERROR("GetAll failed, db has been closed.");
        return E_ALREADY_CLOSED;
    } else if (PreferenceDbAdapter::GetApiInstance().DbKvFilterApi == nullptr) {
        LOG_ERROR("api load failed: DbKvFilterApi");
        return E_ERROR;
    }

    GRD_FilterOptionT param;
    param.mode = KV_SCAN_ALL;
    GRD_ResultSet *resultSet = nullptr;

    int retryTimes = CREATE_COLLECTION_RETRY_TIMES;
    int ret = E_OK;
    do {
        ret = PreferenceDbAdapter::GetApiInstance().DbKvFilterApi(db_, TABLENAME, &param, &resultSet);
        if (ret == GRD_UNDEFINED_TABLE) {
            LOG_INFO("CreateCollection called when GetAll, file: %{public}s", ExtractFileName(dbPath_).c_str());
            (void)CreateCollection();
        } else {
            if (ret == GRD_OK) {
                break;
            } else {
                LOG_ERROR("rd kv filter failed:%{public}d", ret);
                return TransferGrdErrno(ret);
            }
        }
        retryTimes--;
    } while (retryTimes > 0);

    if (retryTimes == 0) {
        LOG_ERROR("rd get over retry times, errcode: :%{public}d", ret);
        return TransferGrdErrno(ret);
    }

    return GetAllInner(data, resultSet);
}

int PreferencesDb::DropCollection()
{
    if (db_ == nullptr) {
        LOG_ERROR("DropCollection failed, db has been closed.");
        return E_ALREADY_CLOSED;
    } else if (PreferenceDbAdapter::GetApiInstance().DbDropCollectionApi == nullptr) {
        LOG_ERROR("api load failed: DbDropCollectionApi");
        return E_ERROR;
    }

    int errCode = PreferenceDbAdapter::GetApiInstance().DbDropCollectionApi(db_, TABLENAME, 0);
    if (errCode != E_OK) {
        LOG_ERROR("rd drop collection failed:%{public}d", errCode);
    }
    return TransferGrdErrno(errCode);
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
    return std::vector<uint8_t>(static_cast<uint8_t *>(item.data),
        static_cast<uint8_t *>(item.data) + item.dataLen);
}

int PreferencesDb::GetKernelDataVersion(int64_t &dataVersion)
{
    if (db_ == nullptr) {
        LOG_ERROR("Get kernel data version failed, db has been closed.");
        return E_ALREADY_CLOSED;
    } else if (PreferenceDbAdapter::GetApiInstance().DbGetConfigApi == nullptr) {
        LOG_ERROR("api load failed: DbGetConfigApi");
        return E_ERROR;
    }

    GRD_DbValueT kernelDataVersion = PreferenceDbAdapter::GetApiInstance().DbGetConfigApi(db_,
        GRD_ConfigTypeE::GRD_CONFIG_DATA_VERSION);
    if (kernelDataVersion.type != GRD_DbDataTypeE::GRD_DB_DATATYPE_INTEGER) {
        LOG_ERROR("get wrong data version type: %d", kernelDataVersion.type);
        return E_ERROR;
    }

    dataVersion = kernelDataVersion.value.longValue;
    return E_OK;
}
} // End of namespace NativePreferences
} // End of namespace OHOS