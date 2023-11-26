/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef PREFERENCES_FRAMEWORKS_BASE64_HELPER_H
#define PREFERENCES_FRAMEWORKS_BASE64_HELPER_H

#include <string>
#include <vector>

namespace OHOS {
namespace NativePreferences {
class Base64Helper {
public:
    static std::string Encode(const std::vector<uint8_t> &input);
    static bool Decode(const std::string &input, std::vector<uint8_t> &output);
};
} // namespace NativePreferences
} // namespace OHOS

#endif // PREFERENCES_FRAMEWORKS_EXECUTOR_POOL_H