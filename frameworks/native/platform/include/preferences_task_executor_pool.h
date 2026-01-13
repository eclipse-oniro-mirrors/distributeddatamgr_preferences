/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef PREFERENCES_TASK_EXECUTOR_POOL_H
#define PREFERENCES_TASK_EXECUTOR_POOL_H

#include <functional>

#include "executor_pool.h"
#include "preferences_task_adapter.h"

namespace OHOS {
namespace NativePreferences {
class PreferencesTaskExecutorPool final : public PreferencesTaskAdapter {
public:
    bool Execute(const Task &task) override;
    static bool Init();

private:
    static ExecutorPool executorPool_;
};
} // namespace NativePreferences
} // namespace OHOS
#endif