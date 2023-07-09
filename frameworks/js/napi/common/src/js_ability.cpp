/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "extension_context.h"
#include "log_print.h"
#include "napi_preferences_error.h"

namespace OHOS {
namespace PreferencesJsKit {
int JSAbility::GetContextInfo(napi_env env, napi_value value, const std::string &dataGroupId, ContextInfo &contextInfo)
{
    bool isStage = false;
    AbilityRuntime::IsStageContext(env, value, isStage);
    if (isStage) {
        auto stageContext = AbilityRuntime::GetStageModeContext(env, value);
        if (stageContext == nullptr) {
            LOG_ERROR("GetStageModeContext failed.");
            return E_INVALID_PARAM;
        }

        int errcode = stageContext->GetSystemPreferencesDir(dataGroupId, contextInfo.preferencesDir);
        if (errcode != 0) {
            return E_INVALID_DATA_GROUP_ID;
        }
        contextInfo.bundleName = stageContext->GetBundleName();
        return OK;
    }

    if (!dataGroupId.empty()) {
        return E_UNSUPPORTED_MODE;
    }

    auto ability = AbilityRuntime::GetCurrentAbility(env);
    if (ability == nullptr) {
        LOG_ERROR("GetCurrentAbility failed.");
        return E_INVALID_PARAM;
    }

    auto abilityContext = ability->GetAbilityContext();
    if (ability == nullptr) {
        LOG_ERROR("GetAbilityContext failed.");
        return E_INVALID_PARAM;
    }
    contextInfo.preferencesDir = abilityContext->GetPreferencesDir();
    return OK;
}
} // namespace PreferencesJsKit
} // namespace OHOS
