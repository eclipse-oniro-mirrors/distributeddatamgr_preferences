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

#include "preferences_task_executor_pool.h"

namespace OHOS {
namespace NativePreferences {
__attribute__((used)) static bool g_isInit = PreferencesTaskExecutorPool::Init();
ExecutorPool PreferencesTaskExecutorPool::executorPool_ = ExecutorPool(1, 0);

bool PreferencesTaskExecutorPool::Execute(std::function<void()> task)
{
    return (executorPool_.Execute(std::move(task)) == ExecutorPool::INVALID_TASK_ID) ? false : true;
}

bool PreferencesTaskExecutorPool::Init()
{
    static PreferencesTaskExecutorPool instance;
    static std::once_flag onceFlag;
    std::call_once(onceFlag, [&]() { PreferencesTaskAdapter::RegisterTaskInstance(&instance); });
    return true;
}
}
}