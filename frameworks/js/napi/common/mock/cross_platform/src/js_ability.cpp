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

namespace OHOS {
namespace PreferencesJsKit {
Context::Context(std::shared_ptr<AbilityRuntime::Platform::Context> stageContext)
{
    preferencesDir_ = stageContext->GetPreferencesDir();
}

std::string Context::GetPreferencesDir()
{
    return preferencesDir_;
}

std::shared_ptr<Context> JSAbility::GetContext(napi_env env, napi_value value)
{
    auto stageContext = AbilityRuntime::Platform::GetStageModeContext(env, value);
    if (stageContext == nullptr) {
        LOG_ERROR("GetStageModeContext failed.");
        return nullptr;
    }
    return std::make_shared<Context>(stageContext);
}
} // namespace PreferencesJsKit
} // namespace OHOS
