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

#include "preferences_task_ffrt.h"

namespace OHOS {
namespace NativePreferences {
constexpr int32_t FFRT_QOS_USER_INTERACTIVE = 5;
constexpr const char *FFRT_FLAG = "PreferencesFFRTFlag";
__attribute__((used)) static bool g_isInit = PreferencesTaskFfrt::Init();
bool PreferencesTaskFfrt::Execute(const Task &task)
{
    ffrt::submit(task, {}, { FFRT_FLAG }, ffrt::task_attr().qos(FFRT_QOS_USER_INTERACTIVE));
    return true;
}

bool PreferencesTaskFfrt::Init()
{
    static PreferencesTaskFfrt instance;
    static std::once_flag onceFlag;
    std::call_once(onceFlag, [&]() { PreferencesTaskAdapter::RegisterTaskInstance(&instance); });
    return true;
}
} // namespace NativePreferences
} // namespace OHOS