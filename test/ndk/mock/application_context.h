/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_ABILITY_RUNTIME_APPLICATION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_APPLICATION_CONTEXT_H

#include <memory>

namespace OHOS {
namespace AbilityRuntime {
class ApplicationContext;
// mock Context from ablity
class Context : public std::enable_shared_from_this<Context> {
public:
    Context() = default;
    virtual ~Context() = default;
    static std::shared_ptr<ApplicationContext> GetApplicationContext();
    virtual std::string GetPreferencesDir() = 0;
    virtual int32_t GetSystemPreferencesDir(const std::string &groupId, bool checkExist,
        std::string &preferencesDir) = 0;
    static std::shared_ptr<ApplicationContext> applicationContext_;
};

class ApplicationContext : public Context {
public:
    ApplicationContext() = default;
    ~ApplicationContext() override = default;
    std::string GetPreferencesDir() override;
    int32_t GetSystemPreferencesDir(const std::string &groupId, bool checkExist, std::string &preferencesDir) override;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_APPLICATION_CONTEXT_H
