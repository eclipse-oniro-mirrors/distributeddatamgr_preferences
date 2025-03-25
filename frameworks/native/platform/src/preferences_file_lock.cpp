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

#include "preferences_utils.h"
#include "preferences_file_lock.h"
#include "preferences_file_operation.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <thread>

#include "log_print.h"
#include "visibility.h"
namespace OHOS {
namespace NativePreferences {
std::map<std::string, std::shared_ptr<std::mutex>> PreferencesLockManager::inProcessMutexs_;
std::mutex PreferencesLockManager::mapMutex_;

std::shared_ptr<std::mutex> PreferencesLockManager::Get(const std::string fileName)
{
    std::lock_guard<std::mutex> lockMutex(mapMutex_);
    auto iter = inProcessMutexs_.find(fileName);
    if (iter != inProcessMutexs_.end()) {
        return iter->second;
    }
    auto res = inProcessMutexs_.insert_or_assign(fileName, std::make_shared<std::mutex>());
    return res.first->second;
}

#if !defined(WINDOWS_PLATFORM)
static const std::chrono::milliseconds WAIT_CONNECT_TIMEOUT(20);
static const int ATTEMPTS = 50;
PreferencesFileLock::PreferencesFileLock(const std::string &path)
{
    filePath_ = MakeFilePath(path, STR_LOCK);
    inProcessMutex_ = PreferencesLockManager::Get(filePath_);
    inProcessMutex_->lock();
}

PreferencesFileLock::~PreferencesFileLock()
{
    inProcessMutex_->unlock();
    if (fd_ > 0) {
        struct flock fileLockInfo = { 0 };
        fileLockInfo.l_type = F_UNLCK;
        fileLockInfo.l_whence = SEEK_SET;
        fileLockInfo.l_start = 0;
        fileLockInfo.l_len = 0;
        if (fcntl(fd_, F_SETLK, &fileLockInfo) == -1) {
            LOG_ERROR("failed to release file lock error %{public}d.", errno);
        }
        close(fd_);
        fd_ = -1;
    }
}

void PreferencesFileLock::ReadLock(bool &isMultiProcessing)
{
    Lock(F_RDLCK, isMultiProcessing);
}

void PreferencesFileLock::WriteLock(bool &isMultiProcessing)
{
    Lock(F_WRLCK, isMultiProcessing);
}

void PreferencesFileLock::Lock(short lockType, bool &isMultiProcessing)
{
    fd_ = open(filePath_.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (fd_ == -1) {
        LOG_ERROR("Couldn't open file %{public}s errno %{public}d.", ExtractFileName(filePath_).c_str(), errno);
        return;
    }
    struct flock fileLockInfo = { 0 };
    fileLockInfo.l_type = lockType;
    fileLockInfo.l_whence = SEEK_SET;
    fileLockInfo.l_start = 0;
    fileLockInfo.l_len = 0;

    for (size_t i = 0; i < ATTEMPTS; ++i) {
        if (fcntl(fd_, F_SETLK, &fileLockInfo) != -1) {
            LOG_DEBUG("successfully obtained file lock");
            return;
        }
        LOG_DEBUG("Attempt to obtain file lock again %{public}d", errno);
        isMultiProcessing = true;
        std::this_thread::sleep_for(WAIT_CONNECT_TIMEOUT);
    }
    LOG_ERROR("attempt to lock file %{public}s failed.", ExtractFileName(filePath_).c_str());
}

#else

PreferencesFileLock::PreferencesFileLock(const std::string &path)
{
    fd_ = -1;
    inProcessMutex_.reset();
}

PreferencesFileLock::~PreferencesFileLock()
{
}

void PreferencesFileLock::ReadLock(bool &isMultiProcessing)
{
}

void PreferencesFileLock::WriteLock(bool &isMultiProcessing)
{
}

void PreferencesFileLock::Lock(short lockType, bool &isMultiProcessing)
{
}

#endif
} // End of namespace NativePreferences
} // End of namespace OHOS