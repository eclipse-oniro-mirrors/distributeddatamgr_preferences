/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "mock_napi_base_context.h"
#include "napi_base_context/napi_base_context.h"
#include "appkit/ability_runtime/context/context.h"

namespace OHOS {
namespace AbilityRuntime {
MockNapiBaseContext::MockNapiBaseContext() {}

MockNapiBaseContext::~MockNapiBaseContext() {}

napi_status IsStageContext(napi_env env, napi_value value, bool &mode)
{
    mode = false;
    return napi_ok;
}

std::shared_ptr<Context> GetStageModeContext(napi_env env, napi_value value)
{
    return nullptr;
}

std::shared_ptr<AppExecFwk::Ability> GetCurrentAbility(napi_env env)
{
    return nullptr;
}
}
}