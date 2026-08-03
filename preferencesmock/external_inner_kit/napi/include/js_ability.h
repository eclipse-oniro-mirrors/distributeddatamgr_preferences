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

#ifndef DISTRIBUTEDDATAMGR_APPDATAMGR_JSABILITY_H
#define DISTRIBUTEDDATAMGR_APPDATAMGR_JSABILITY_H
#include <iostream>
#include <string>

#include "preferences_error.h"

#include "ability.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_base_context.h"

namespace OHOS {
namespace AppDataMgrJsKit {
class Context {
public:
    explicit Context(std::shared_ptr<AbilityRuntime::Context> stageContext);
    explicit Context(std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext);

    std::string GetDatabaseDir();
    int GetSystemDatabaseDir(const std::string &dataGroupId, std::string &databaseDir);
    std::string GetBundleName();
    std::string GetModuleName();
    std::string GetUri();
    std::string GetReadPermission();
    std::string GetWritePermission();
    int32_t GetArea() const;
    bool IsSystemAppCalled();
    bool IsHasProxyDataConfig() const;
    bool IsStageMode() const;

private:
    int32_t area_ = 0;
    std::string databaseDir_;
    std::string bundleName_;
    std::string moduleName_;
    std::string uri_;
    std::string readPermission_;
    std::string writePermission_;
    bool hasProxyDataConfig_ = false;
    bool isSystemAppCalled_ = false;
    bool isStageMode_ = false;
    std::shared_ptr<AbilityRuntime::Context> stageContext_;
};
} // namespace AppDataMgrJsKit

namespace PreferencesJsKit {
namespace JSAbility {
enum CONTEXT_MODE { INIT = -1, FA = 0, STAGE = 1 };
struct ContextInfo {
    std::string bundleName;
    std::string preferencesDir;
};
static CONTEXT_MODE gContextNode = INIT;
CONTEXT_MODE GetContextMode(napi_env env, napi_value value);
std::shared_ptr<JSError> GetContextInfo(napi_env env, napi_value value,
    const std::string &dataGroupId, ContextInfo &contextInfo);
} // namespace JSAbility
} // namespace PreferencesJsKit
} // namespace OHOS

#endif // DISTRIBUTEDDATAMGR_APPDATAMGR_JSABILITY_H