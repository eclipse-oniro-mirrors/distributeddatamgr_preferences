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

#ifndef PREFERENCES_DFX_ADAPTER_H
#define PREFERENCES_DFX_ADAPTER_H

#include <string>

#include "preferences_errno.h"
namespace OHOS {
namespace NativePreferences {

static constexpr const char *NORMAL_DB = "XMLDB";
static constexpr const char *ENHANCE_DB = "ENHANCEDB";
static constexpr const char *EVENT_NAME_DB_CORRUPTED = "DATABASE_CORRUPTED";
static constexpr const char *EVENT_NAME_PREFERENCES_FAULT = "PREFERENCES_FAULT";
static constexpr const char *EVENT_NAME_ARKDATA_PREFERENCES_FAULT = "ARKDATA_PREFERENCES_FAULT";
static constexpr const char *DISTRIBUTED_DATAMGR = "DISTDATAMGR";

struct ReportParam {
    std::string bundleName; // bundleName
    std::string dbType;     // NORMAL_DB or ENHANCE_DB
    std::string storeName;  // filename
    uint32_t errCode = E_OK;
    int32_t errnoCode = 0;  // errno
    // additional info, "operation: reason", such as "read failed"
    std::string appendix;   // additional info
};

struct ReportFaultParam {
    std::string faultType; // faultType
    std::string bundleName; // bundleName
    std::string dbType;     // NORMAL_DB or ENHANCE_DB
    std::string storeName;  // filename
    int32_t errCode = E_OK;
    // additional info, "operation: reason", such as "read failed"
    std::string appendix;   // additional info
};

class PreferencesDfxManager {
public:
    static void Report(const ReportParam &reportParam, const char *eventName);
    static void ReportFault(const ReportFaultParam &reportParam);
    static std::string GetModuleName();
};
} // namespace NativePreferences
} // namespace OHOS
#endif