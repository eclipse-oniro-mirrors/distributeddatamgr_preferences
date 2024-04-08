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

#include "preferences_value_parsel.h"


#include "preferences_errno.h"
namespace OHOS {
namespace NativePreferences {

int GetTypeIndex(const PreferencesValue &value)
{
    if (value.IsInt()) {
        return 0;
    } else if (value.IsLong()){
        return 1;
    } else if (value.IsFloat()) {
        return 2;
    } else if (value.IsDouble()) {
        return 3;
    } else if (value.IsBool()) {
        return 4;
    } else if (value.IsString()) {
        return 5;
    } else if (value.IsStringArray()) {
        return 6;
    } else if (value.IsBoolArray()) {
        return 7;
    } else if (value.IsDoubleArray()) {
        return 8;
    } else if (value.IsUint8Array()) {
        return 9;
    } else if (value.IsObject()) {
        return 10;
    } else {
        return 11; // bigInt
    }
}

uint32_t PreferencesValueParcel::CalSize(PreferencesValue value)
{
    return 0;
}

int PreferencesValueParcel::SerializePreferenceValue(const PreferencesValue &value, std::vector<uint8_t> &data)
{
    return E_OK;
}

std::pair<int, PreferencesValue> PreferencesValueParcel::DeSerializePreferenceValue(const std::vector<uint8_t> &data)
{
    PreferencesValue value(0);
    return std::make_pair(E_OK, value);
}
} // namespace NativePreferences
} // namespace OHOS