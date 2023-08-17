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
namespace JSAbility {
CONTEXT_MODE GetContextMode(napi_env env, napi_value value)
{
    if (gContextNode == INIT) {
        bool isStageMode;
        napi_status status = AbilityRuntime::IsStageContext(env, value, isStageMode);
        gContextNode = (status == napi_ok && isStageMode) ? STAGE : FA;
        LOG_INFO("set gContextNode = %{public}d", gContextNode);
    }
    return gContextNode;
}

int GetContextInfo(napi_env env, napi_value value, const std::string &dataGroupId, ContextInfo &contextInfo)
{
    if (GetContextMode(env, value) == STAGE) {
        if (auto stageContext = AbilityRuntime::GetStageModeContext(env, value)) {
            int errcode = stageContext->GetSystemPreferencesDir(dataGroupId, false, contextInfo.preferencesDir);
            if (errcode != 0) {
                LOG_ERROR("GetSystemPreferencesDir fails, rc = %{public}d", errcode);
                return E_DATA_GROUP_ID_INVALID;
            }
            contextInfo.bundleName = stageContext->GetBundleName();
            return OK;
        } else {
            LOG_ERROR("failed to get stage mode context.");
            return E_INNER_ERROR;
        }
    }

    if (!dataGroupId.empty()) {
        LOG_ERROR("dataGroupId should be empty in fa mode");
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
} // namespace JSAbility
} // namespace PreferencesJsKit
} // namespace OHOS
