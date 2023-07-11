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
Context::Context(std::shared_ptr<AbilityRuntime::Context> stageContext)
{
    preferencesDir_ = stageContext->GetPreferencesDir();
}

Context::Context(std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext)
{
    preferencesDir_ = abilityContext->GetPreferencesDir();
}

std::string Context::GetPreferencesDir()
{
    return preferencesDir_;
}

std::shared_ptr<Context> JSAbility::GetContext(napi_env env, napi_value value)
{
    bool mode = false;
    AbilityRuntime::IsStageContext(env, value, mode);
    if (mode) {
        auto stageContext = AbilityRuntime::GetStageModeContext(env, value);
        if (stageContext == nullptr) {
            LOG_ERROR("GetStageModeContext failed.");
            return nullptr;
        }
        return std::make_shared<Context>(stageContext);
    }

    auto ability = AbilityRuntime::GetCurrentAbility(env);
    if (ability == nullptr) {
        LOG_ERROR("GetCurrentAbility failed.");
        return nullptr;
    }
    auto abilityContext = ability->GetAbilityContext();
    if (abilityContext == nullptr) {
        LOG_ERROR("GetAbilityContext failed.");
        return nullptr;
    }
    return std::make_shared<Context>(abilityContext);
}
} // namespace PreferencesJsKit
} // namespace OHOS
