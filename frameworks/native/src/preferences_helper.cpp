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

#include <climits>
#include <cstdlib>

#include <cerrno>
#include <utility>

#include "adaptor.h"
#include "filelock.h"
#include "log_print.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_impl.h"
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

std::string PreferencesHelper::GetRealPath(const std::string &path, int &errorCode)
{
    if (path.empty()) {
        LOG_ERROR("The path can not be empty.");
        errorCode = E_EMPTY_FILE_PATH;
        return "";
    }
    if (path.front() != '/' && path.at(1) != ':') {
        LOG_ERROR("The path can not be relative path.");
        errorCode = E_RELATIVE_PATH;
        return "";
    }
    if (strlen(path.c_str()) > PATH_MAX) {
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
    std::string filePath = path.substr(0, pos);
#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM)
    if (ACCESS(filePath.c_str()) != 0 && MKDIR(filePath.c_str())) {
        LOG_ERROR("Failed to create path");
        errorCode = E_INVALID_FILE_PATH;
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

std::shared_ptr<Preferences> PreferencesHelper::GetPreferences(const std::string &path, int &errCode)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::string realPath = GetRealPath(path, errCode);
    if (realPath == "" || errCode != E_OK) {
        LOG_ERROR("fails to get real path, errCode %{public}d", errCode);
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(prefsCacheMutex_);
    std::map<std::string, std::shared_ptr<Preferences>>::iterator it = prefsCache_.find(realPath);
    if (it != prefsCache_.end()) {
        return it->second;
    }

    std::string filePath = realPath.c_str();
    std::shared_ptr<PreferencesImpl> pref = PreferencesImpl::GetPreferences(filePath);
    errCode = pref->Init();
    if (errCode != E_OK) {
        LOG_ERROR("Preferences Init failed.");
        return nullptr;
    }
    prefsCache_.insert(make_pair(realPath, pref));
    return pref;
}

int PreferencesHelper::DeletePreferences(const std::string &path)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int errCode = E_OK;
    std::string realPath = GetRealPath(path, errCode);
    if (realPath == "" || errCode != E_OK) {
        return errCode;
    }

    std::lock_guard<std::mutex> lock(prefsCacheMutex_);
    std::map<std::string, std::shared_ptr<Preferences>>::iterator it = prefsCache_.find(realPath);
    if (it != prefsCache_.end()) {
        prefsCache_.erase(it);
    }

    std::string filePath = realPath.c_str();
    std::string backupPath = PreferencesImpl::MakeFilePath(filePath, STR_BACKUP);
    std::string brokenPath = PreferencesImpl::MakeFilePath(filePath, STR_BROKEN);
    std::string lockFilePath = PreferencesImpl::MakeFilePath(filePath, STR_LOCK);
    FileLock fileLock;
    if (fileLock.TryLock(lockFilePath) == E_ERROR) {
        return E_ERROR;
    }

    std::remove(filePath.c_str());
    std::remove(backupPath.c_str());
    std::remove(brokenPath.c_str());

    if (IsFileExist(filePath) || IsFileExist(backupPath) || IsFileExist(brokenPath)) {
        fileLock.UnLock();
        return E_DELETE_FILE_FAIL;
    }
    fileLock.UnLock();
    return E_OK;
}

int PreferencesHelper::RemovePreferencesFromCache(const std::string &path)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
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
