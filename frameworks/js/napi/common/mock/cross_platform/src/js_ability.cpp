/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "log_print.h"
#include "napi_preferences_error.h"

namespace OHOS {
namespace PreferencesJsKit {
int JSAbility::GetContextInfo(napi_env env, napi_value value, const std::string &dataGroupId, ContextInfo &contextInfo)
{
    if (!dataGroupId.empty()) {
        return NativePreferences::E_NOT_SUPPORTED;
    }
    auto stageContext = AbilityRuntime::Platform::GetStageModeContext(env, value);
    if (stageContext == nullptr) {
        LOG_ERROR("GetStageModeContext failed.");
        return E_INVALID_PARAM;
    }
    contextInfo.preferencesDir = stageContext->GetPreferencesDir();
    return OK;
}
} // namespace PreferencesJsKit
} // namespace OHOS
