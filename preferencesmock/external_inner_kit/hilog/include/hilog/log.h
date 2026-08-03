/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HILOG_LOG_H
#define HILOG_LOG_H

#include <algorithm>

typedef enum {
    LOG_LEVEL_MIN = 0,
    LOG_DEBUG = 3,
    LOG_INFO = 4,
    LOG_WARN = 5,
    LOG_ERROR = 6,
    LOG_FATAL = 7,
    LOG_LEVEL_MAX = 8,
} LogLevel;

typedef enum {
    LOG_TYPE_MIN = 0,
    LOG_APP = 0,
    LOG_INIT = 1,
    LOG_CORE = 2,
    LOG_TYPE_MAX = 3,
} LogType;

namespace OHOS {
namespace HiviewDFX {
using HiLogLabel = struct {
    LogType type;
    unsigned int domain;
    const char *tag;
};

class HiLog {
public:
    static int Debug(const HiLogLabel &label, const char *fmt, ...);
    static int Info(const HiLogLabel &label, const char *fmt, ...);
    static int Warn(const HiLogLabel &label, const char *fmt, ...);
    static int Error(const HiLogLabel &label, const char *fmt, ...);
    static int Fatal(const HiLogLabel &label, const char *fmt, ...);
};
}
}

bool HiLogIsLoggable(unsigned int domain, const char *tag, LogLevel level);
int HiLogPrint(LogType type, LogLevel level, unsigned int domain, const char *tag, const char *fmt, ...);
#define HILOG_IMPL(type, level, domain, tag, ...) HiLogPrint(type, level, domain, tag, ##__VA_ARGS__)

#endif