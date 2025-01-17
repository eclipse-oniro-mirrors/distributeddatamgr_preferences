/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "preferences_helper.h"

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <utility>

#include "log_print.h"
#include "preferences.h"
#include "preferences_db_adapter.h"
#include "preferences_errno.h"
#include "preferences_file_lock.h"
#include "preferences_file_operation.h"
#include "preferences_dfx_adapter.h"
#include "preferences_impl.h"
#include "preferences_enhance_impl.h"

namespace OHOS {
namespace NativePreferences {
std::map<std::string, std::pair<std::shared_ptr<Preferences>, bool>> PreferencesHelper::prefsCache_;
std::mutex PreferencesHelper::prefsCacheMutex_;
std::atomic<bool> PreferencesHelper::isReportFault_(false);
static constexpr const int DB_SUFFIX_NUM = 6;
static constexpr const char *DB_SUFFIX[DB_SUFFIX_NUM] = { ".ctrl", ".ctrl.dwr", ".redo", ".undo", ".safe", ".map" };

static bool IsFileExist(const std::string &path)
{
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

static int RemoveEnhanceDb(const std::string &filePath)
{
    if (std::remove(filePath.c_str()) != 0) {
        LOG_ERROR("remove %{public}s failed.", ExtractFileName(filePath).c_str());
        return E_DELETE_FILE_FAIL;
    }
    return E_OK;
}

static int RemoveEnhanceDbFileIfNeed(const std::string &filePath)
{
    std::string dbFilePath = filePath + ".db";
    if (IsFileExist(dbFilePath) && RemoveEnhanceDb(dbFilePath) != E_OK) {
        LOG_ERROR("remove dbFilePath failed.");
        return E_DELETE_FILE_FAIL;
    }
    for (int index = 0; index < DB_SUFFIX_NUM; index++) {
        std::string tmpFilePath = dbFilePath + DB_SUFFIX[index];
        if (IsFileExist(tmpFilePath) && RemoveEnhanceDb(tmpFilePath) != E_OK) {
            return E_DELETE_FILE_FAIL;
        }
    }
    LOG_DEBUG("db files has been removed.");
    return E_OK;
}

std::string PreferencesHelper::GetRealPath(const std::string &path, int &errorCode)
{
    if (path.empty()) {
        LOG_ERROR("The path can not be empty.");
        errorCode = E_EMPTY_FILE_PATH;
        return "";
    }
    if (path.length() > PATH_MAX) {
        LOG_ERROR("The path exceeds max length.");
        errorCode = E_PATH_EXCEED_MAX_LENGTH;
        return "";
    }
    std::string::size_type pos = path.find_last_of('/');
    if (pos == std::string::npos) {
        LOG_ERROR("path can not be relative path.");
        errorCode = E_RELATIVE_PATH;
        return "";
    }
#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM)
    if (path.at(1) != ':') {
        LOG_ERROR("The path can not be relative path.");
        errorCode = E_RELATIVE_PATH;
        return "";
    }
    std::string filePath = path.substr(0, pos);
    if (Access(filePath) != 0 && !Mkdir(filePath)) {
        LOG_ERROR("Failed to create path");
        errorCode = E_INVALID_FILE_PATH;
        return "";
    }
#else
    if (path.front() != '/') {
        LOG_ERROR("The path can not be relative path.");
        errorCode = E_RELATIVE_PATH;
        return "";
    }
#endif
    std::string fileName = path.substr(pos + 1, path.length());
    if (fileName.empty()) {
        LOG_ERROR("file name can not be empty.");
        errorCode = E_EMPTY_FILE_NAME;
        return "";
    }
    errorCode = E_OK;
    return path;
}

static bool IsInTrustList(const std::string &bundleName)
{
    std::vector<std::string> trustList = {"uttest", "alipay", "com.jd.", "cmblife", "os.mms", "os.ouc",
        "meetimeservice"};
    for (size_t i = 0; i < trustList.size(); i++) {
        if (bundleName.find(trustList[i]) != std::string::npos) {
            return true;
        }
    }
    return false;
}

int PreferencesHelper::GetPreferencesInner(const Options &options, bool &isEnhancePreferences,
    std::shared_ptr<Preferences> &pref)
{
    if (IsInTrustList(options.bundleName)) {
        if (!IsFileExist(options.filePath) && IsStorageTypeSupported(StorageType::CLKV)) {
            pref = PreferencesEnhanceImpl::GetPreferences(options);
            isEnhancePreferences = true;
            return std::static_pointer_cast<PreferencesEnhanceImpl>(pref)->Init();
        }
        pref = PreferencesImpl::GetPreferences(options);
        isEnhancePreferences = false;
        return std::static_pointer_cast<PreferencesImpl>(pref)->Init();
    }
    if (!options.isEnhance) {
        // xml
        if (IsFileExist(options.filePath + ".db")) {
            LOG_ERROR("CLKV exists, failed to get preferences by XML.");
            return E_NOT_SUPPORTED;
        }
        pref = PreferencesImpl::GetPreferences(options);
        isEnhancePreferences = false;
        return std::static_pointer_cast<PreferencesImpl>(pref)->Init();
    }
    // clkv
    if (IsFileExist(options.filePath)) {
        LOG_ERROR("XML exists, failed to get preferences by CLKV.");
        return E_NOT_SUPPORTED;
    }
    if (!IsStorageTypeSupported(StorageType::CLKV)) {
        // log inside
        return E_NOT_SUPPORTED;
    }
    pref = PreferencesEnhanceImpl::GetPreferences(options);
    isEnhancePreferences = true;
    return std::static_pointer_cast<PreferencesEnhanceImpl>(pref)->Init();
}

std::shared_ptr<Preferences> PreferencesHelper::GetPreferences(const Options &options, int &errCode)
{
    std::string realPath = GetRealPath(options.filePath, errCode);
    if (realPath == "" || errCode != E_OK) {
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(prefsCacheMutex_);
    auto it = prefsCache_.find(realPath);
    if (it != prefsCache_.end()) {
        auto pre = it->second.first;
        if (pre != nullptr) {
            LOG_DEBUG("GetPreferences: found preferences in cache");
            return pre;
        }
        LOG_DEBUG("GetPreferences: found preferences in cache but it's null, erase it.");
        prefsCache_.erase(it);
    }

    const_cast<Options &>(options).filePath = realPath;
    std::string::size_type pos = realPath.find_last_of('/');
    std::string filePath = realPath.substr(0, pos);
    if (Access(filePath.c_str()) != 0) {
        LOG_ERROR("The path is invalid, prefName is %{public}s.", ExtractFileName(filePath).c_str());
        if (!PreferencesHelper::isReportFault_.exchange(true)) {
            ReportParam param = { options.bundleName, NORMAL_DB, ExtractFileName(options.filePath),
                E_INVALID_FILE_PATH, 2, "The path is invalid." };
            PreferencesDfxManager::Report(param, EVENT_NAME_PREFERENCES_FAULT);
        }
    }
    bool isEnhancePreferences = false;
    std::shared_ptr<Preferences> pref = nullptr;
    errCode = GetPreferencesInner(options, isEnhancePreferences, pref);
    if (errCode != E_OK) {
        return nullptr;
    }
    prefsCache_.insert({realPath, {pref, isEnhancePreferences}});
    return pref;
}

std::pair<std::string, int> PreferencesHelper::DeletePreferencesInner(const std::string &realPath)
{
    std::string bundleName;
    int errCode = E_OK;
    std::map<std::string, std::pair<std::shared_ptr<Preferences>, bool>>::iterator it = prefsCache_.find(realPath);
    if (it != prefsCache_.end()) {
        auto pref = it->second.first;
        if (pref != nullptr) {
            LOG_INFO("Begin to Delete Preferences: %{public}s", ExtractFileName(realPath).c_str());
            bundleName = pref->GetBundleName();
            if (it->second.second) {
                errCode = pref->CloseDb();
            } else {
                errCode = std::static_pointer_cast<PreferencesImpl>(pref)->Close();
            }
        }
        if (errCode == E_OK) {
            prefsCache_.erase(it);
        }
    }

    return { bundleName, errCode };
}

int PreferencesHelper::DeletePreferences(const std::string &path)
{
    int errCode = E_OK;
    std::string realPath = GetRealPath(path, errCode);
    if (realPath == "" || errCode != E_OK) {
        return errCode;
    }

    std::string bundleName;
    {
        std::lock_guard<std::mutex> lock(prefsCacheMutex_);
        auto [ name, code ] = DeletePreferencesInner(realPath);
        if (code != E_OK) {
            LOG_ERROR("failed to close when delete preferences, errCode is: %{public}d", code);
            return code;
        }
        bundleName = name;
    }

    std::string filePath = realPath.c_str();
    std::string backupPath = MakeFilePath(filePath, STR_BACKUP);
    std::string brokenPath = MakeFilePath(filePath, STR_BROKEN);
    std::string lockFilePath = MakeFilePath(filePath, STR_LOCK);

    bool isMultiProcessing = false;
    PreferencesFileLock fileLock(filePath);
    fileLock.WriteLock(isMultiProcessing);
    if (isMultiProcessing) {
        LOG_ERROR("The file has cross-process operations, fileName is %{public}s.", ExtractFileName(filePath).c_str());
        ReportParam param = { bundleName, NORMAL_DB, ExtractFileName(path),
            E_OPERAT_IS_CROSS_PROESS, 0, "Cross-process operations exist during file deleting." };
        PreferencesDfxManager::Report(param, EVENT_NAME_PREFERENCES_FAULT);
    }
    std::remove(filePath.c_str());
    std::remove(backupPath.c_str());
    std::remove(brokenPath.c_str());
    std::remove(lockFilePath.c_str());
    if (RemoveEnhanceDbFileIfNeed(path) != E_OK) {
        return E_DELETE_FILE_FAIL;
    }

    if (IsFileExist(filePath) || IsFileExist(backupPath) || IsFileExist(brokenPath) || IsFileExist(lockFilePath)) {
        return E_DELETE_FILE_FAIL;
    }
    return E_OK;
}

int PreferencesHelper::RemovePreferencesFromCache(const std::string &path)
{
    int errCode = E_OK;
    std::string realPath = GetRealPath(path, errCode);
    if (realPath == "" || errCode != E_OK) {
        return errCode;
    }

    std::lock_guard<std::mutex> lock(prefsCacheMutex_);
    std::map<std::string, std::pair<std::shared_ptr<Preferences>, bool>>::iterator it = prefsCache_.find(realPath);
    if (it == prefsCache_.end()) {
        LOG_DEBUG("RemovePreferencesFromCache: preferences not in cache, just return");
        return E_OK;
    }

    auto pref = it->second.first;
    if (pref != nullptr) {
        if (it->second.second) {
            errCode = std::static_pointer_cast<PreferencesEnhanceImpl>(pref)->CloseDb();
            if (errCode != E_OK) {
                LOG_ERROR("RemovePreferencesFromCache: failed to close db.");
                return E_ERROR;
            }
        } else {
            std::static_pointer_cast<PreferencesImpl>(pref)->Close();
        }
    }

    prefsCache_.erase(it);
    return E_OK;
}

bool PreferencesHelper::IsStorageTypeSupported(const StorageType &type)
{
    if (type == StorageType::XML) {
        return true;
    }
    if (type == StorageType::CLKV) {
#if !defined(CROSS_PLATFORM) && defined(ARKDATA_DATABASE_CORE_ENABLE)
        return true;
#else
        LOG_WARN("CLKV not support this platform.");
        return false;
#endif
    }
    return false;
}
} // End of namespace NativePreferences
} // End of namespace OHOS