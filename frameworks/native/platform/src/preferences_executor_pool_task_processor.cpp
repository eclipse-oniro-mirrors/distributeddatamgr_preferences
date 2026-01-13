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

#include "preferences_executor_pool_task_processor.h"

namespace OHOS {
namespace NativePreferences {
__attribute__((used)) static bool g_isInit = PreferencesExecutorPoolTaskProcessor::Init();
constexpr int32_t MAX_THREADS = 1;
constexpr int32_t MIN_THREADS = 0;
ExecutorPool PreferencesExecutorPoolTaskProcessor::executorPool_ = ExecutorPool(MAX_THREADS, MIN_THREADS);

bool PreferencesExecutorPoolTaskProcessor::Execute(const Task &task)
{
    return !(executorPool_.Execute(std::move(task)) == ExecutorPool::INVALID_TASK_ID);
}

bool PreferencesExecutorPoolTaskProcessor::Init()
{
    static PreferencesExecutorPoolTaskProcessor instance;
    static std::once_flag onceFlag;
    std::call_once(onceFlag, [&]() { PreferencesTaskProcessor::RegisterTaskProcessor(&instance); });
    return true;
}
} // namespace NativePreferences
} // namespace OHOS