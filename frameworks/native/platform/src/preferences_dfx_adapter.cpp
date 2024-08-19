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

#include "preferences_dfx_adapter.h"
#include "preferences_file_operation.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#include "log_print.h"
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include <thread>
#include <fstream>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include "accesstoken_kit.h"
#include "hisysevent_c.h"
#include "ipc_skeleton.h"
#endif

namespace OHOS {
namespace NativePreferences {

#define HMFS_MONITOR_FL 0x00000002
#define HMFS_IOCTL_HW_GET_FLAGS _IOR(0xf5, 70, unsigned int)
#define HMFS_IOCTL_HW_SET_FLAGS _IOR(0xf5, 71, unsigned int)

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
std::string GetCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    auto now_ms = std::chrono::time_point_cast<std::chrono::microseconds>(now);
    auto epoch = now_ms.time_since_epoch();
    auto value = std::chrono::duration_cast<std::chrono::microseconds>(epoch);
    auto timestamp = value.count();

    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm *tm = std::localtime(&tt);
    if (tm == nullptr) {
        return "";
    }

    const int offset = 1000;
    const int width = 3;
    std::stringstream oss;
    oss << std::put_time(tm, "%Y-%m-%d %H:%M:%S.") << std::setfill('0') << std::setw(width)
        << ((timestamp / offset) % offset) << "." << std::setfill('0') << std::setw(width) << (timestamp % offset);
    return oss.str();
}

std::string PreferencesDfxManager::GetModuleName()
{
    std::string moduleName = "";
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if ((tokenType == Security::AccessToken::TOKEN_NATIVE) || (tokenType == Security::AccessToken::TOKEN_SHELL)) {
        Security::AccessToken::NativeTokenInfo tokenInfo;
        if (Security::AccessToken::AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo) == 0) {
            moduleName = tokenInfo.processName;
        }
    }
    return moduleName;
}

void SetFileControlFlag(const std::string &fileName, FlagControlType flagControlType)
{
    int fd = open(fileName.c_str(), O_RDONLY, S_IRWXU | S_IRWXG);
    if (fd == -1) {
        LOG_ERROR("Couldn't open file %{public}s errno %{public}d.", ExtractFileName(fileName).c_str(), errno);
        return;
    }
    unsigned int flags = 0;
    int ret = ioctl(fd, HMFS_IOCTL_HW_GET_FLAGS, &flags);
    if (ret < 0) {
        LOG_DEBUG("Failed to get control flag, errno: %{public}d.", errno);
        close(fd);
        return;
    }

    if ((flagControlType == FlagControlType::SET_FLAG && (flags & HMFS_MONITOR_FL)) ||
        (flagControlType == FlagControlType::CLEAR_FLAG && !(flags & HMFS_MONITOR_FL))) {
        close(fd);
        return;
    }

    if (flagControlType == FlagControlType::SET_FLAG) {
        flags |= HMFS_MONITOR_FL;
    } else if (flagControlType == FlagControlType::CLEAR_FLAG) {
        flags &= ~HMFS_MONITOR_FL;
    }
 
    ret = ioctl(fd, HMFS_IOCTL_HW_SET_FLAGS, &flags);
    if (ret < 0) {
        LOG_DEBUG("Failed to set flags:%{public}d, errno: %{public}d.", flagControlType, errno);
        close(fd);
        return;
    }

    LOG_DEBUG("Flag control operation success type: %{public}d.", flagControlType);
    close(fd);
}

void PreferencesDfxManager::ReportDbFault(const ReportParam &reportParam)
{
    std::thread thread([reportParam]() {
        std::string nowTime = GetCurrentTime();
        std::string moudleName = GetModuleName();
        HiSysEventParam params[] = {
            { .name = "BUNDLE_NAME",
                .t = HISYSEVENT_STRING,
                .v = { .s = const_cast<char *>(reportParam.bundleName.c_str()) },
                .arraySize = 0 },
            { .name = "MODULE_NAME",
                .t = HISYSEVENT_STRING,
                .v = { .s = const_cast<char *>(moudleName.c_str()) },
                .arraySize = 0 },
            { .name = "STORE_TYPE",
                .t = HISYSEVENT_STRING,
                .v = { .s = const_cast<char *>(reportParam.dbType.c_str()) },
                .arraySize = 0 },
            { .name = "STORE_NAME",
                .t = HISYSEVENT_STRING,
                .v = { .s = const_cast<char *>(reportParam.storeName.c_str()) },
                .arraySize = 0 },
            { .name = "SECURITY_LEVEL", .t = HISYSEVENT_UINT32, .v = { .ui32 = 0u }, .arraySize = 0 },
            { .name = "PATH_AREA", .t = HISYSEVENT_UINT32, .v = { .ui32 = 0u }, .arraySize = 0 },
            { .name = "ENCRYPT_STATUS", .t = HISYSEVENT_UINT32, .v = { .ui32 = 0u }, .arraySize = 0 },
            { .name = "INTERGITY_CHECK", .t = HISYSEVENT_UINT32, .v = { .ui32 = 0u }, .arraySize = 0 },
            { .name = "ERROR_CODE", .t = HISYSEVENT_UINT32, .v = { .ui32 = reportParam.errCode }, .arraySize = 0 },
            { .name = "ERRNO", .t = HISYSEVENT_INT32, .v = { .i32 = reportParam.errnoCode }, .arraySize = 0 },
            { .name = "APPENDIX",
                .t = HISYSEVENT_STRING,
                .v = { .s = const_cast<char *>(reportParam.appendix.c_str()) },
                .arraySize = 0 },
            { .name = "ERROR_TIME",
                .t = HISYSEVENT_STRING,
                .v = { .s = const_cast<char *>(nowTime.c_str()) },
                .arraySize = 0 },
        };
        size_t len = sizeof(params) / sizeof(params[0]);
        OH_HiSysEvent_Write(DISTRIBUTED_DATAMGR, EVENT_NAME_DB_CORRUPTED, HISYSEVENT_FAULT, params, len);
    });
    thread.detach();
}
#else
std::string GetCurrentTime()
{
    return "";
}

std::string PreferencesDfxManager::GetModuleName()
{
    return "";
}

void SetFileControlFlag(const std::string &fileName, FlagControlType flagControlType)
{
}

void PreferencesDfxManager::ReportDbFault(const ReportParam &reportParam)
{
}
#endif
} // End of namespace NativePreferences
} // End of namespace OHOS
