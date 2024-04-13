/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef PREFERENCES_FILE_OPERATION_H
#define PREFERENCES_FILE_OPERATION_H

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#include "visibility.h"

#ifndef _WIN32
#include <dlfcn.h>
#endif

#if defined(WINDOWS_PLATFORM)

#include <iostream>
#include <windows.h>

#else

#include <stdarg.h>

#if !(defined(MAC_PLATFORM) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM))

#include <cstdlib>

#endif

#endif

#ifndef FILE_MODE
#define FILE_MODE 0770
#endif

#ifndef FILE_EXIST
#define FILE_EXIST 0
#endif

#ifndef INT_MAX
#define INT_MAX 2147483647
#endif

namespace OHOS {
namespace NativePreferences {

static UNUSED_FUNCTION void *DBDlOpen()
{
#ifndef _WIN32
    return dlopen("libgaussdb_rd_vector.z.so", RTLD_LAZY);
#else
    return nullptr;
#endif
}

static UNUSED_FUNCTION int Mkdir(const std::string &filePath)
{
#if defined(WINDOWS_PLATFORM)
    return mkdir(filePath.c_str());
#else
    return mkdir(filePath.c_str(), FILE_MODE);
#endif
}

static UNUSED_FUNCTION int Access(const std::string &filePath)
{
#if defined(WINDOWS_PLATFORM)
    return _access(filePath.c_str(), FILE_EXIST);
#else
    return access(filePath.c_str(), FILE_EXIST);
#endif
}

static UNUSED_FUNCTION bool Fsync(const std::string &filePath)
{
#if defined(WINDOWS_PLATFORM)
    int fd = _open(filePath.c_str(), _O_WRONLY, _S_IWRITE);
    if (fd == -1) {
        return false;
    }
    HANDLE handle = (HANDLE)_get_osfhandle(fd);
    if (handle == INVALID_HANDLE_VALUE || !FlushFileBuffers(handle)) {
        _close(fd);
        return false;
    }
    _close(fd);
#else
    int fd = open(filePath.c_str(), O_RDWR, S_IRUSR | S_IWUSR);
    if (fd == -1 || fsync(fd) == -1) {
        close(fd);
        return false;
    }
    close(fd);
#endif
    return true;
}
} // namespace NativePreferences
} // namespace OHOS
#endif // PREFERENCES_FILE_OPERATION_H