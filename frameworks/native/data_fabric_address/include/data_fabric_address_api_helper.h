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

#ifndef DATA_FABRIC_ADDRESS_API_HELPER_H
#define DATA_FABRIC_ADDRESS_API_HELPER_H

#include <cstdint>
#include <stddef.h>

#include "preferences_visibility.h"

namespace OHOS {
namespace NativePreferences {

class DataFabricAddressApiHelper {
public:
    static PREF_API_EXPORT bool IsValidIntEnumValue(int32_t value, int32_t minValue, int32_t maxValue);
    static PREF_API_EXPORT bool IsValidLatLng(double latitude, double longitude);
    static PREF_API_EXPORT bool IsPointsCountExceeds(uint32_t pointCount);
    static PREF_API_EXPORT bool IsStringLengthExceeds(size_t stringLen);
private:
    DataFabricAddressApiHelper() = default;
    ~DataFabricAddressApiHelper() = default;
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_API_HELPER_H
