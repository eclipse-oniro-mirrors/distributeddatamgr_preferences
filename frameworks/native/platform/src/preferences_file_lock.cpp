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

#include "preferences_file_lock.h"

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

static UNUSED_FUNCTION std::string ExtractFileName(const std::string &path)
{
    auto pos = path.rfind('/');
    if (pos == std::string::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

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
static const std::chrono::microseconds WAIT_CONNECT_TIMEOUT(20);
static const int ATTEMPTS = 5;
PreferencesFileLock::PreferencesFileLock(const std::string &path, const std::string &dataGroupId)
    : inProcessMutex_(PreferencesLockManager::Get(path))
{
    inProcessMutex_->lock();
    if (dataGroupId.empty()) {
        return;
    }
    fd_ = open(path.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (fd_ == -1) {
        LOG_ERROR("Couldn't open file %{public}s errno %{public}d.", ExtractFileName(path).c_str(), errno);
        return;
    }
    struct flock fileLockInfo = { 0 };
    fileLockInfo.l_type = F_WRLCK;
    fileLockInfo.l_whence = SEEK_SET;
    fileLockInfo.l_start = 0;
    fileLockInfo.l_len = 0;

    for (size_t i = 0; i < ATTEMPTS; ++i) {
        if (fcntl(fd_, F_SETLK, &fileLockInfo) != -1) {
            LOG_DEBUG("successfully obtained file lock");
            return;
        }
        LOG_DEBUG("Attempt to obtain file lock again %{public}d", errno);
        std::this_thread::sleep_for(WAIT_CONNECT_TIMEOUT);
    }
    LOG_ERROR("attempt to lock file %{public}s failed. Please try again", ExtractFileName(path).c_str());
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

#else

PreferencesFileLock::PreferencesFileLock(const std::string &path, const std::string &dataGroupId)
{
    fd_ = -1;
    inProcessMutex_.reset();
}

PreferencesFileLock::~PreferencesFileLock()
{
}

#endif
} // End of namespace NativePreferences
} // End of namespace OHOS