/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "application_context.h"
#include <string>

namespace OHOS {
namespace AbilityRuntime {

std::shared_ptr<ApplicationContext> Context::applicationContext_ = nullptr;

std::shared_ptr<ApplicationContext> Context::GetApplicationContext()
{
    printf("mock Context success.\n");
    applicationContext_ = std::make_shared<ApplicationContext>();
    return applicationContext_;
}

std::string ApplicationContext::GetPreferencesDir()
{
    return std::string("/data/test");
}

int32_t ApplicationContext::GetSystemPreferencesDir(const std::string &groupId, bool checkExist,
    std::string &preferencesDir)
{
    preferencesDir = "/data/test";
    return 0;
}

}  // namespace AbilityRuntime
}  // namespace OHOS