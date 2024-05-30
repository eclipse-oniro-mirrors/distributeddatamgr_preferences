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
#include "preferences_impl.h"
#include "preferences_enhance_impl.h"
#include "securec.h"
namespace OHOS {
namespace NativePreferences {
std::map<std::string, std::shared_ptr<Preferences>> PreferencesHelper::prefsCache_;
std::mutex PreferencesHelper::prefsCacheMutex_;

static bool IsFileExist(const std::string &path)
{
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

static int RemoveEnhanceDbFileIfNeed(const std::string &filePath)
{
    if (IsFileExist(filePath.c_str()) && std::remove(filePath.c_str()) != 0) {
        LOG_ERROR("remove filePath failed.");
        return E_DELETE_FILE_FAIL;
    }
    std::string tmpFilePath = filePath + ".ctrl";
    if (IsFileExist(tmpFilePath.c_str()) && std::remove(tmpFilePath.c_str()) != 0) {
        LOG_ERROR("remove ctrlFile failed.");
        return E_DELETE_FILE_FAIL;
    }
    tmpFilePath = filePath + ".redo";
    if (IsFileExist(tmpFilePath.c_str()) && std::remove(tmpFilePath.c_str()) != 0) {
        LOG_ERROR("remove ctrlFile failed.");
        return E_DELETE_FILE_FAIL;
    }
    tmpFilePath = filePath + ".undo";
    if (IsFileExist(tmpFilePath.c_str()) && std::remove(tmpFilePath.c_str()) != 0) {
        LOG_ERROR("remove ctrlFile failed.");
        return E_DELETE_FILE_FAIL;
    }
    tmpFilePath = filePath + ".safe";
    if (IsFileExist(tmpFilePath.c_str()) && std::remove(tmpFilePath.c_str()) != 0) {
        LOG_ERROR("remove ctrlFile failed.");
        return E_DELETE_FILE_FAIL;
    }
    tmpFilePath = filePath + ".map";
    if (IsFileExist(tmpFilePath.c_str()) && std::remove(tmpFilePath.c_str()) != 0) {
        LOG_ERROR("remove ctrlFile failed.");
        return E_DELETE_FILE_FAIL;
    }
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

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
static bool IsUseEnhanceDb(std::string bundleName)
{
    PreferenceDbAdapter::ApiInit();
    return (bundleName.find("uttest") != std::string::npos) && PreferenceDbAdapter::IsEnhandceDbEnable();
}
#endif

std::shared_ptr<Preferences> PreferencesHelper::GetPreferences(const Options &options, int &errCode)
{
    std::string realPath = GetRealPath(options.filePath, errCode);
    if (realPath == "" || errCode != E_OK) {
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(prefsCacheMutex_);
    std::map<std::string, std::shared_ptr<Preferences>>::iterator it = prefsCache_.find(realPath);
    if (it != prefsCache_.end()) {
        return it->second;
    }

    const_cast<Options &>(options).filePath = realPath;
    std::shared_ptr<Preferences> pref = nullptr;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) &&!defined(IOS_PLATFORM)
    if (IsUseEnhanceDb(options.bundleName)) {
        LOG_DEBUG("PreferencesHelper::GetPreferences using enhance db.");
        pref = PreferencesEnhanceImpl::GetPreferences(options);
        errCode = std::static_pointer_cast<PreferencesEnhanceImpl>(pref)->Init();
    } else {
        pref = PreferencesImpl::GetPreferences(options);
        errCode = std::static_pointer_cast<PreferencesImpl>(pref)->Init();
    }
#else
    pref = PreferencesImpl::GetPreferences(options);
    errCode = std::static_pointer_cast<PreferencesImpl>(pref)->Init();
#endif
    if (errCode != E_OK) {
        return nullptr;
    }
    prefsCache_.insert(make_pair(realPath, pref));
    return pref;
}

int PreferencesHelper::DeletePreferences(const std::string &path)
{
    int errCode = E_OK;
    std::string realPath = GetRealPath(path, errCode);
    if (realPath == "" || errCode != E_OK) {
        return errCode;
    }

    std::string dataGroupId = "";
    {
        std::lock_guard<std::mutex> lock(prefsCacheMutex_);
        std::map<std::string, std::shared_ptr<Preferences>>::iterator it = prefsCache_.find(realPath);
        if (it != prefsCache_.end()) {
            dataGroupId = it->second->GetGroupId();
            prefsCache_.erase(it);
        }
    }

    std::string filePath = realPath.c_str();
    std::string backupPath = MakeFilePath(filePath, STR_BACKUP);
    std::string brokenPath = MakeFilePath(filePath, STR_BROKEN);
    std::string lockFilePath = MakeFilePath(filePath, STR_LOCK);

    PreferencesFileLock fileLock(lockFilePath, dataGroupId);
    std::remove(filePath.c_str());
    std::remove(backupPath.c_str());
    std::remove(brokenPath.c_str());
    if (RemoveEnhanceDbFileIfNeed(path) != E_OK) {
        return E_DELETE_FILE_FAIL;
    }

    if (!dataGroupId.empty()) {
        std::remove(lockFilePath.c_str());
    }

    if (IsFileExist(filePath) || IsFileExist(backupPath) || IsFileExist(brokenPath)) {
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
    std::map<std::string, std::shared_ptr<Preferences>>::iterator it = prefsCache_.find(realPath);
    if (it == prefsCache_.end()) {
        return E_OK;
    }
    prefsCache_.erase(it);
    return E_OK;
}
} // End of namespace NativePreferences
} // End of namespace OHOS
