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
namespace OHOS {
namespace NativePreferences {

#if !defined(WINDOWS_PLATFORM)
static const std::chrono::microseconds WAIT_CONNECT_TIMEOUT(20);
static const int ATTEMPTS = 5;

PreferencesFileLock::PreferencesFileLock()
{
}

PreferencesFileLock::~PreferencesFileLock()
{
    if (fd_ > 0) {
        close(fd_);
    }
}

int PreferencesFileLock::TryLock(const std::string &fileName)
{
    int fd = open(fileName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (fd == -1) {
        LOG_ERROR("Couldn't open file %{public}s errno %{public}d.", fileName.c_str(), errno);
        return (errno == EACCES) ? PERMISSION_DENIED : E_ERROR;
    }
    struct flock fileLockInfo = { 0 };
    fileLockInfo.l_type = F_WRLCK;
    fileLockInfo.l_whence = SEEK_SET;
    fileLockInfo.l_start = 0;
    fileLockInfo.l_len = 0;

    for (size_t i = 0; i < ATTEMPTS; ++i) {
        if (fcntl(fd, F_SETLK, &fileLockInfo) != -1) {
            fd_ = fd;
            return E_OK;
        }
        std::this_thread::sleep_for(WAIT_CONNECT_TIMEOUT);
    }
    close(fd);
    return E_ERROR;
}

int PreferencesFileLock::UnLock()
{
    int errCode = E_OK;
    if (fd_ > 0) {
        struct flock fileLockInfo = { 0 };
        fileLockInfo.l_type = F_UNLCK;
        fileLockInfo.l_whence = SEEK_SET;
        fileLockInfo.l_start = 0;
        fileLockInfo.l_len = 0;
        if (fcntl(fd_, F_SETLK, &fileLockInfo) == -1) {
            LOG_ERROR("failed to release file lock error %{public}d.", errno);
            errCode = E_ERROR;
        }
        close(fd_);
        fd_ = -1;
    }
    return errCode;
}

#else

PreferencesFileLock::PreferencesFileLock()
{
    fd_ = -1;
}

PreferencesFileLock::~PreferencesFileLock()
{
}

int PreferencesFileLock::TryLock(const std::string &fileName)
{
    return E_OK;
}

int PreferencesFileLock::UnLock()
{
    return E_OK;
}
#endif
} // End of namespace NativePreferences
} // End of namespace OHOS