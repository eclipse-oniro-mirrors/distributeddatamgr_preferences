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
napi_status JSAbility::IsStageContext(napi_env env, napi_value value, bool &isStageMode)
{
    napi_status status = AbilityRuntime::IsStageContext(env, value, isStageMode);
    return status;
}

int JSAbility::GetContextInfo(napi_env env, napi_value value, const std::string &dataGroupId, const bool &isStageMode,
    ContextInfo &contextInfo)
{
    if (isStageMode) {
        auto stageContext = AbilityRuntime::GetStageModeContext(env, value);
        if (stageContext == nullptr) {
            LOG_ERROR("failed to get stage mode context.");
            return E_INNER_ERROR;
        }

        int errcode = stageContext->GetSystemPreferencesDir(dataGroupId, false, contextInfo.preferencesDir);
        if (errcode != 0) {
            return E_DATA_GROUP_ID_INVALID;
        }
        contextInfo.bundleName = stageContext->GetBundleName();
        return OK;
    }

    if (!dataGroupId.empty()) {
        return E_NOT_STAGE_MODE;
    }

    auto ability = AbilityRuntime::GetCurrentAbility(env);
    if (ability == nullptr) {
        LOG_ERROR("failed to get current ability.");
        return E_INNER_ERROR;
    }

    auto abilityContext = ability->GetAbilityContext();
    if (ability == nullptr) {
        LOG_ERROR("failed to get ability context.");
        return E_INNER_ERROR;
    }
    abilityContext->GetSystemPreferencesDir("", false, contextInfo.preferencesDir);
    return OK;
}
} // namespace PreferencesJsKit
} // namespace OHOS
