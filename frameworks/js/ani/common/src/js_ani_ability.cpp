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
#include "ani_base_context.h"
#include "extension_context.h"
#include "log_print.h"
namespace OHOS {
namespace PreferencesJsKit {
namespace JSAbility {
static CONTEXT_MODE gContextNode = CONTEXT_MODE::INIT;

CONTEXT_MODE GetContextMode(ani_env* env, ani_object context)
{
    if (gContextNode == CONTEXT_MODE::INIT) {
        ani_boolean isStageMode;
        ani_status status = OHOS::AbilityRuntime::IsStageContext(env, context, isStageMode);
        LOG_INFO("GetContextMode is %{public}d", static_cast<bool>(isStageMode));
        if (status == ANI_OK) {
            gContextNode = isStageMode ? CONTEXT_MODE::STAGE : CONTEXT_MODE::FA;
        }
    }
    LOG_INFO("gContextNode is: %{public}d", gContextNode);
    return gContextNode;
}

std::shared_ptr<JSError> GetContextInfo(ani_env* env, ani_object context,
    const std::string &dataGroupId, ContextInfo &contextInfo)
{
    if (GetContextMode(env, context) == CONTEXT_MODE::STAGE) {
        auto stageContext = OHOS::AbilityRuntime::GetStageModeContext(env, context);
        if (stageContext != nullptr) {
            int errcode = stageContext->GetSystemPreferencesDir(dataGroupId, false, contextInfo.preferencesDir);
            LOG_INFO("after GetContextMode, in stage. errcode is %{public}d.", errcode);
            if (errcode != 0) {
                return std::make_shared<InnerError>(E_DATA_GROUP_ID_INVALID);
            }
            contextInfo.bundleName = stageContext->GetBundleName();
            return nullptr;
        } else {
            LOG_INFO("The context is invalid.");
            return std::make_shared<ParamTypeError>("The context is invalid.");
        }
    }

    if (!dataGroupId.empty()) {
        return std::make_shared<InnerError>(E_NOT_STAGE_MODE);
    }

    return nullptr;
}
} // namespace JSAbility
} // namespace PreferencesJsKit
} // namespace OHOS
