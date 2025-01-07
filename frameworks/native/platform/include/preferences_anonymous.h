/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_PREFERENCES_ANONYMOUS_H
#define OHOS_PREFERENCES_ANONYMOUS_H

#include <string>

namespace OHOS {
namespace NativePreferences {
class Anonymous {
public:
    static std::string ToBeAnonymous(const std::string &data)
    {
        if (data.size() <= HEAD_SIZE) {
            return DEFAULT_ANONYMOUS;
        }
        if (data.size() < MIN_SIZE) {
            return (data.substr(0, HEAD_SIZE) + REPLACE_CHAIN);
        }
        if (data.size() < MEDIAN_SIZE) {
            return (data.substr(0, HEAD_SIZE) + REPLACE_CHAIN + data.substr(data.size() - END_SIZE, END_SIZE));
        }
        return (data.substr(0, DATA_HEAD) + REPLACE_CHAIN + data.substr(data.size() - DATA_END, DATA_END));
    }

private:
    static constexpr size_t HEAD_SIZE = 3;
    static constexpr size_t END_SIZE = 3;
    static constexpr size_t DATA_HEAD = 4;
    static constexpr size_t DATA_END = 4;
    static constexpr size_t MIN_SIZE = HEAD_SIZE + END_SIZE + 3;
    static constexpr size_t MEDIAN_SIZE = DATA_HEAD + DATA_END + 3;
    static constexpr const char *REPLACE_CHAIN = "***";
    static constexpr const char *DEFAULT_ANONYMOUS = "******";
};
} // namespace NativePreferences
} // namespace OHOS
#endif // OHOS_PREFERENCES_ANONYMOUS_H

