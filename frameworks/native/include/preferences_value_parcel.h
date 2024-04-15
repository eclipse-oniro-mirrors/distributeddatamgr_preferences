/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef PREFERENCES_VALUE_PARCEL_H
#define PREFERENCES_VALUE_PARCEL_H

#include <vector>
#include <cstdint>
#include <string>
#include <type_traits>

#include "preferences_value.h"
namespace OHOS {
namespace NativePreferences {

class PreferencesValueParcel {
public:
    static uint8_t GetTypeIndex(const PreferencesValue &value);
    static uint32_t CalSize(PreferencesValue value);
    static int MarshallingPreferenceValue(const PreferencesValue &value, std::vector<uint8_t> &data);
    static std::pair<int, PreferencesValue> UnmarshallingPreferenceValue(const std::vector<uint8_t> &data);

private:
    enum ParcelTypeIndex {
        INT_TYPE = 0,
        LONG_TYPE = 1,
        FLOAT_TYPE = 2,
        DOUBLE_TYPE = 3,
        BOOL_TYPE = 4,
        STRING_TYPE = 5,
        STRING_ARRAY_TYPE = 6,
        BOOL_ARRAY_TYPE = 7,
        DOUBLE_ARRAY_TYPE = 8,
        UINT8_ARRAY_TYPE = 9,
        OBJECT_TYPE = 10,
        BIG_INT_TYPE = 11
    };
    static int MarshallingBasicValue(const PreferencesValue &value, const uint8_t type, std::vector<uint8_t> &data);
    static int MarshallingStringValue(const PreferencesValue &value, const uint8_t type, std::vector<uint8_t> &data);
    static int MarshallingStringArrayValue(const PreferencesValue &value, const uint8_t type,
        std::vector<uint8_t> &data);
    static int MarshallingVecUInt8AfterType(const PreferencesValue &value, uint8_t *startAddr);
    static int MarshallingVecBigIntAfterType(const PreferencesValue &value, uint8_t *startAddr);
    static int MarshallingVecDoubleAfterType(const PreferencesValue &value, uint8_t *startAddr);
    static int MarshallingVecBoolAfterType(const PreferencesValue &value, uint8_t *startAddr);
    static int MarshallingBasicArrayValue(const PreferencesValue &value, const uint8_t type,
        std::vector<uint8_t> &data);
    static std::pair<int, PreferencesValue> UnmarshallingBasicValue(const uint8_t type,
        const std::vector<uint8_t> &data);
    static std::pair<int, PreferencesValue> UnmarshallingStringValue(const uint8_t type,
        const std::vector<uint8_t> &data);
    static std::pair<int, PreferencesValue> UnmarshallingStringArrayValue(const uint8_t type,
        const std::vector<uint8_t> &data);
    static std::pair<int, PreferencesValue> UnmarshallingVecUInt8(const std::vector<uint8_t> &data);
    static std::pair<int, PreferencesValue> UnmarshallingVecDouble(const std::vector<uint8_t> &data);
    static std::pair<int, PreferencesValue> UnmarshallingVecBool(const std::vector<uint8_t> &data);
    static std::pair<int, PreferencesValue> UnmarshallingVecBigInt(const std::vector<uint8_t> &data);
    static std::pair<int, PreferencesValue> UnmarshallingBasicArrayValue(const uint8_t type,
        const std::vector<uint8_t> &data);
    static int MarshallingBasicValueInner(const PreferencesValue &value, const uint8_t type,
        std::vector<uint8_t> &data);
};
} // namespace NativePreferences
} // namespace OHOS
#endif