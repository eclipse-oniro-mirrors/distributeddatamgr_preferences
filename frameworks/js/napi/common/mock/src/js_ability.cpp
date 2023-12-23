/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "js_ability.h"

#include <cstdlib>

#include "log_print.h"

namespace OHOS {
namespace PreferencesJsKit {
namespace JSAbility {
CONTEXT_MODE GetContextMode(napi_env env, napi_value value)
{
    return STAGE;
}

std::shared_ptr<JSError> GetContextInfo(napi_env env, napi_value value,
    const std::string &dataGroupId, ContextInfo &contextInfo)
{
    if (!dataGroupId.empty()) {
        return std::make_shared<InnerError>(NativePreferences::E_NOT_SUPPORTED);
    }
    std::string baseDir = "";
#ifdef WINDOWS_PLATFORM
    baseDir = getenv("TEMP");
    if (!baseDir.empty()) {
        contextInfo.preferencesDir = baseDir + "\\HuaweiDevEcoStudioPreferences";
    }
#endif

#ifdef MAC_PLATFORM
    baseDir = getenv("LOGNAME");
    if (!baseDir.empty()) {
        baseDir = "/Users/" + baseDir + "/Library/Caches";
        contextInfo.preferencesDir = baseDir + "/HuaweiDevEcoStudioPreferences";
    }
#endif
    return nullptr;
}
} // namespace JSAbility
} // namespace PreferencesJsKit
} // namespace OHOS
