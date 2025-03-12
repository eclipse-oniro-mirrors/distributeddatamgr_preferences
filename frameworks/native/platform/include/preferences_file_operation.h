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
#include "preferences_anonymous.h"

#ifndef _WIN32
#include <dlfcn.h>
#endif

#if defined(WINDOWS_PLATFORM)

#include <iostream>
#include <windows.h>
#include <io.h>

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

constexpr int32_t PRE_OFFSET_SIZE = 1;
constexpr int32_t AREA_MINI_SIZE = 4;
constexpr int32_t AREA_OFFSET_SIZE = 5;
constexpr int32_t FILE_PATH_MINI_SIZE = 6;

static UNUSED_FUNCTION void *DBDlOpen()
{
#ifndef _WIN32
    return dlopen("libarkdata_db_core.z.so", RTLD_LAZY);
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

static UNUSED_FUNCTION int Open(const std::string &filePath)
{
#if defined(WINDOWS_PLATFORM)
    return _open(filePath.c_str(), _O_WRONLY | _O_CREAT | _O_TRUNC, _S_IREAD | _S_IWRITE);
#else
    return open(filePath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0660);
#endif
}

static UNUSED_FUNCTION int Write(int fd, const unsigned char *buffer, ssize_t count)
{
#if defined(WINDOWS_PLATFORM)
    HANDLE hFile = (HANDLE)_get_osfhandle(fd); // 转换文件描述符为 HANDLE
    if (hFile == INVALID_HANDLE_VALUE) {
        return -1;
    }
    DWORD bytesWritten = 0;
    return WriteFile(hFile, buffer, (DWORD)count, &bytesWritten, NULL) ? (int)bytesWritten : -1;
#else
    return write(fd, buffer, count);
#endif
}

static UNUSED_FUNCTION int Close(int fd)
{
#if defined(WINDOWS_PLATFORM)
    return _close(fd);
#else
    return close(fd);
#endif
}

static UNUSED_FUNCTION bool Fsync(int fd)
{
#if defined(WINDOWS_PLATFORM)
    HANDLE handle = (HANDLE)_get_osfhandle(fd);
    if (handle == INVALID_HANDLE_VALUE || !FlushFileBuffers(handle)) {
        return false;
    }
#else
    if (fd == -1) {
        return false;
    }
    if (fsync(fd) == -1) {
        return false;
    }
#endif
    return true;
}

static UNUSED_FUNCTION std::string ExtractFileName(const std::string &path)
{
    auto pre = path.find("/");
    auto end = path.rfind("/");
    if (pre == std::string::npos || end - pre < FILE_PATH_MINI_SIZE) {
        return Anonymous::ToBeAnonymous(path);
    }
    std::string fileName = path.substr(end + 1); // preferences file name
    auto filePath = path.substr(pre, end - pre);
    auto area = filePath.find("/el");
    if (area == std::string::npos || area + AREA_MINI_SIZE > path.size()) {
        filePath = "";
    } else if (area + AREA_OFFSET_SIZE < path.size()) {
        filePath = path.substr(area, AREA_MINI_SIZE) + "/***";
    } else {
        filePath = path.substr(area, AREA_MINI_SIZE);
    }
    fileName = Anonymous::ToBeAnonymous(fileName);
    return path.substr(0, pre + PRE_OFFSET_SIZE) + "***" + filePath + "/"+ fileName;
}
} // namespace NativePreferences
} // namespace OHOS
#endif // PREFERENCES_FILE_OPERATION_H
