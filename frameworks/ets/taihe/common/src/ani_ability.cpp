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

#include "ani_ability.h"

#include <atomic>
#include "ani_base_context.h"
#include "log_print.h"
namespace OHOS {
namespace PreferencesEtsKit {
namespace EtsAbility {
using JSError = PreferencesJsKit::JSError;
using ParamTypeError = PreferencesJsKit::ParamTypeError;
using InnerError = PreferencesJsKit::InnerError;

ContextMode GetContextMode(ani_env* env, ani_object context)
{
    if (gContextNode == ContextMode::INIT) {
        ani_boolean isStageMode;
        ani_status status = OHOS::AbilityRuntime::IsStageContext(env, context, isStageMode);
        LOG_INFO("isStageMode:%{public}d, status:%{public}d", static_cast<bool>(isStageMode),
            static_cast<int32_t>(status));
        if (status == ANI_OK) {
            gContextNode = isStageMode ? ContextMode::STAGE : ContextMode::FA;
        }
    }
    return gContextNode;
}

std::shared_ptr<JSError> GetContextInfo(ani_env* env, ani_object context,
    const std::string &dataGroupId, ContextInfo &contextInfo)
{
    if (GetContextMode(env, context) != ContextMode::STAGE) {
        LOG_ERROR("Not supporting fa mode");
        return nullptr;
    }
    auto stageContext = OHOS::AbilityRuntime::GetStageModeContext(env, context);
    if (stageContext != nullptr) {
        int errcode = stageContext->GetSystemPreferencesDir(dataGroupId, false, contextInfo.preferencesDir);
        if (errcode != 0) {
            LOG_ERROR("GetSystemPreferencesDir failed, err = %{public}d", errcode);
            return std::make_shared<InnerError>(PreferencesJsKit::E_DATA_GROUP_ID_INVALID);
        }
        contextInfo.bundleName = stageContext->GetBundleName();
        return nullptr;
    } else {
        LOG_INFO("Failed to get the context of the stage model.");
        return std::make_shared<ParamTypeError>("The context is invalid.");
    }
}
} // namespace EtsAbility
} // namespace PreferencesEtsKit
} // namespace OHOS
