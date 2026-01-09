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

#include "preferences_task_mgr.h"

#if !defined(CROSS_PLATFORM)
#include "ffrt.h"
#endif

namespace OHOS {
namespace NativePreferences {
#if !defined(CROSS_PLATFORM)
constexpr int32_t FFRT_QOS_USER_INTERACTIVE = 5;
constexpr const char *FFRT_FLAG = "PreferencesFFRTFlag";
#else
ExecutorPool PreferencesTaskMgr::executorPool_ = ExecutorPool(1, 0);
#endif

bool PreferencesTaskMgr::Submit(std::function<void()> task)
{
#if !defined(CROSS_PLATFORM)
    ffrt::submit(task, {}, { FFRT_FLAG }, ffrt::task_attr().qos(FFRT_QOS_USER_INTERACTIVE));
    return true;
#else
    return (executorPool_.Execute(std::move(task)) == ExecutorPool::INVALID_TASK_ID) ? false : true;
#endif
}
} // End of namespace NativePreferences
} // End of namespace OHOS