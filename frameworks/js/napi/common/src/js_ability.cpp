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

namespace OHOS {
namespace PreferencesJsKit {
namespace JSAbility {
CONTEXT_MODE GetContextMode(napi_env env, napi_value value)
{
    if (gContextNode == INIT) {
        bool isStageMode;
        napi_status status = AbilityRuntime::IsStageContext(env, value, isStageMode);
        if (status == napi_ok) {
            gContextNode = isStageMode ? STAGE : FA;
        }
        LOG_INFO("set gContextNode: %{public}d, status: %{public}d,", gContextNode, status);
    }
    return gContextNode;
}

std::shared_ptr<JSError> GetContextInfo(napi_env env, napi_value value,
    const std::string &dataGroupId, ContextInfo &contextInfo)
{
    if (GetContextMode(env, value) == STAGE) {
        if (auto stageContext = AbilityRuntime::GetStageModeContext(env, value)) {
            int errcode = stageContext->GetSystemPreferencesDir(dataGroupId, false, contextInfo.preferencesDir);
            if (errcode != 0) {
                LOG_ERROR("GetSystemPreferencesDir fails, rc = %{public}d", errcode);
                return std::make_shared<InnerError>(E_DATA_GROUP_ID_INVALID);
            }
            contextInfo.bundleName = stageContext->GetBundleName();
            return nullptr;
        } else {
            LOG_ERROR("failed to get the context of the stage model.");
            return std::make_shared<ParamTypeError>("The context is invalid.");
        }
    }

    if (!dataGroupId.empty()) {
        LOG_ERROR("dataGroupId should be empty in fa mode");
        return std::make_shared<InnerError>(E_NOT_STAGE_MODE);
    }

    auto ability = AbilityRuntime::GetCurrentAbility(env);
    if (ability == nullptr) {
        LOG_ERROR("failed to get current ability.");
        return std::make_shared<ParamTypeError>("The context is invalid.");
    }

    auto abilityContext = ability->GetAbilityContext();
    if (ability == nullptr) {
        LOG_ERROR("failed to get ability context.");
        return std::make_shared<ParamTypeError>("The context is invalid.");
    }
    abilityContext->GetSystemPreferencesDir("", false, contextInfo.preferencesDir);
    return nullptr;
}
} // namespace JSAbility
} // namespace PreferencesJsKit
} // namespace OHOS
