/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "js_ani_ability.h"
#include "extension_context.h"

namespace OHOS {
namespace PreferencesJsKit {
namespace JSAbility {
CONTEXT_MODE GetContextMode(ani_env* env, ani_object value)
{
    if (gContextNode == INIT) {
        ani_boolean isStageMode;
        ani_status status = IsStageContext(env, value, isStageMode);
        if (status == ANI_OK) {
            gContextNode = isStageMode ? STAGE : FA;
        }
    }
    return gContextNode;
}

std::shared_ptr<JSError> GetContextInfo(ani_env* env, ani_object value,
    const std::string &dataGroupId, ContextInfo &contextInfo)
{
    if (GetContextMode(env, value) == STAGE) {
        if (auto stageContext = GetStageModeContext(env, value)) {
            int errcode = stageContext->GetSystemPreferencesDir(dataGroupId, false, contextInfo.preferencesDir);
            if (errcode != 0) {
                return std::make_shared<InnerError>(E_DATA_GROUP_ID_INVALID);
            }
            contextInfo.bundleName = stageContext->GetBundleName();
            return nullptr;
        } else {
            return std::make_shared<ParamTypeError>("The context is invalid.");
        }
    }

    if (!dataGroupId.empty()) {
        return std::make_shared<InnerError>(E_NOT_STAGE_MODE);
    }

    AppExecFwk::Ability* ability = GetCurrentAbility(env);
    if (ability == nullptr) {
        return std::make_shared<ParamTypeError>("The context is invalid.");
    }

    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext = ability->GetAbilityContext();
    if (ability == nullptr) {
        return std::make_shared<ParamTypeError>("The context is invalid.");
    }
    abilityContext->GetSystemPreferencesDir("", false, contextInfo.preferencesDir);
    return nullptr;
}
} // namespace JSAbility
} // namespace PreferencesJsKit
} // namespace OHOS
