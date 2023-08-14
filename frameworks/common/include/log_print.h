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
#ifndef PRE_LOG_PRINTF_H
#define PRE_LOG_PRINTF_H

#include <string>
#include <vector>

#include "hilog/log.h"

namespace OHOS {
namespace PreferencesJsKit {
static inline OHOS::HiviewDFX::HiLogLabel LogLabel()
{
    return { LOG_CORE, 0xD001653, "PreferencesJsKit" };
}
}

namespace NativePreferences {
static inline OHOS::HiviewDFX::HiLogLabel LogLabel()
{
    return { LOG_CORE, 0xD001653, "NativePreferences" };
}
}
namespace StorageJsKit {
static inline OHOS::HiviewDFX::HiLogLabel LogLabel()
{
    return { LOG_CORE, 0xD001653, "StorageJsKit" };
}
}
} // namespace OHOS
#define LOG_DEBUG(fmt, ...)                                                                                \
    do {                                                                                                   \
        using HiLog = OHOS::HiviewDFX::HiLog;                                                              \
        auto lable = LogLabel();                                                                           \
        if (HiLogIsLoggable(lable.domain, lable.tag, LogLevel::LOG_DEBUG)) {                               \
            HiLog::Debug(lable, "%{public}d: %{public}s " fmt " ", __LINE__, __FUNCTION__, ##__VA_ARGS__); \
        }                                                                                                  \
    } while (0)

#define LOG_RECORD_FILE_NAME(message)                                                                      \
    do {                                                                                                   \
        const char *name = fileName.data();                                                                \
        auto pos = fileName.rfind('/');                                                                    \
        pos = (pos != std::string::npos) ? pos + 1 : 0;                                                    \
        LOG_DEBUG(message " fileName is %{private}s.", name + pos);                                         \
    } while (0)

#define LOG_INFO(fmt, ...)                                                                                 \
    do {                                                                                                   \
        using HiLog = OHOS::HiviewDFX::HiLog;                                                              \
        auto lable = LogLabel();                                                                           \
        if (HiLogIsLoggable(lable.domain, lable.tag, LogLevel::LOG_INFO)) {                                \
            HiLog::Info(lable, "%{public}d: %{public}s " fmt " ", __LINE__, __FUNCTION__, ##__VA_ARGS__);  \
        }                                                                                                  \
    } while (0)

#define LOG_WARN(fmt, ...)                                                                                 \
    do {                                                                                                   \
        using HiLog = OHOS::HiviewDFX::HiLog;                                                              \
        auto lable = LogLabel();                                                                           \
        if (HiLogIsLoggable(lable.domain, lable.tag, LogLevel::LOG_WARN)) {                                \
            HiLog::Warn(lable, "%{public}d: %{public}s " fmt " ", __LINE__, __FUNCTION__, ##__VA_ARGS__);  \
        }                                                                                                  \
    } while (0)

#define LOG_ERROR(fmt, ...)                                                                                \
    do {                                                                                                   \
        using HiLog = OHOS::HiviewDFX::HiLog;                                                              \
        auto lable = LogLabel();                                                                           \
        if (HiLogIsLoggable(lable.domain, lable.tag, LogLevel::LOG_ERROR)) {                               \
            HiLog::Error(lable, "%{public}d: %{public}s " fmt " ", __LINE__, __FUNCTION__, ##__VA_ARGS__); \
        }                                                                                                  \
    } while (0)

#define LOG_FATAL(fmt, ...)                                                                                \
    do {                                                                                                   \
        using HiLog = OHOS::HiviewDFX::HiLog;                                                              \
        auto lable = LogLabel();                                                                           \
        if (HiLogIsLoggable(lable.domain, lable.tag, LogLevel::LOG_FATAL)) {                               \
            HiLog::Fatal(lable, "%{public}d: %{public}s " fmt " ", __LINE__, __FUNCTION__, ##__VA_ARGS__); \
        }                                                                                                  \
    } while (0)

#endif
