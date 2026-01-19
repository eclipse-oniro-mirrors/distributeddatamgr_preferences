/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#ifndef PREFERENCES_TASK_PROCESSOR_H
#define PREFERENCES_TASK_PROCESSOR_H
 
#include <functional>
 
namespace OHOS {
namespace NativePreferences {
using Task = std::function<void()>;
class PreferencesTaskProcessor {
public:
    static PreferencesTaskProcessor *GetInstance();
     ~PreferencesTaskProcessor() = default;
    virtual bool Execute(const Task &task) = 0;
    static bool RegisterTaskProcessor(PreferencesTaskProcessor *instance);
private:
    static PreferencesTaskProcessor *instance_;
};
} // namespace NativePreferences
} // namespace OHOS
#endif