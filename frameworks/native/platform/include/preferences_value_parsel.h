/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef PREFERENCES_VALUE_PARSEL_H
#define PREFERENCES_VALUE_PARSEL_H

#include <vector>
#include <cstdint>
#include <string>
#include <type_traits>

#include "preferences_value.h"
namespace OHOS {
namespace NativePreferences {

class PreferencesValueParcel {
public:
    static uint32_t CalSize(PreferencesValue value);
    static int SerializePreferenceValue(const PreferencesValue &value, std::vector<uint8_t> &data);
    static std::pair<int, PreferencesValue> DeSerializePreferenceValue(const std::vector<uint8_t> &data);
};
} // namespace NativePreferences
} // namespace OHOS
#endif