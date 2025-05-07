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

#ifndef PREFERENCES_FRAMEWORKS_ANI_ABILITY_H
#define PREFERENCES_FRAMEWORKS_ANI_ABILITY_H

#include <string>

#include "ability.h"
#include "taihe_preferences_error.h"

namespace OHOS {
namespace PreferencesEtsKit {
namespace EtsAbility {
enum CONTEXT_MODE { INIT = -1, FA = 0, STAGE = 1 };
struct ContextInfo {
    std::string bundleName;
    std::string preferencesDir;
};
static CONTEXT_MODE gContextNode = INIT;

CONTEXT_MODE GetContextMode(ani_env* env, ani_object object);

std::shared_ptr<EtsError> GetContextInfo(ani_env* env, ani_object value,
    const std::string &dataGroupId, ContextInfo &contextInfo);
} // namespace EtsAbility
} // namespace PreferencesEtsKit
} // namespace OHOS

#endif // PREFERENCES_FRAMEWORKS_ANI_ABILITY_H
