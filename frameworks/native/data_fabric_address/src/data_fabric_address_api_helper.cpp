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

#include "data_fabric_address_api_helper.h"

#include "log_print.h"

#undef LOG_TAG
#define LOG_TAG "DataFabricAddressApiHelper"

namespace OHOS {
namespace NativePreferences {
constexpr uint32_t REFERENCE_POINTS_MAX_COUNT {128};
constexpr uint32_t INPUT_STRING_MAX_COUNT {128};
constexpr double LNG_MIN_VALUE = -180.0;
constexpr double LNG_MAX_VALUE = 180.0;
constexpr double LAT_MIN_VALUE = -90.0;
constexpr double LAT_MAX_VALUE = 90.0;

bool DataFabricAddressApiHelper::IsValidIntEnumValue(int32_t value, int32_t minValue, int32_t maxValue)
{
    if (value < minValue || value > maxValue) {
        return false;
    }
    return true;
}

bool DataFabricAddressApiHelper::IsValidLatLng(double latitude, double longitude)
{
    if (std::isnan(latitude) || std::isnan(longitude)) {
        return false;
    }

    if (latitude < LAT_MIN_VALUE || latitude > LAT_MAX_VALUE || longitude < LNG_MIN_VALUE ||
        longitude > LNG_MAX_VALUE) {
        return false;
    }
    return true;
}

bool DataFabricAddressApiHelper::IsPointsCountExceeds(uint32_t pointCount)
{
    if (pointCount > REFERENCE_POINTS_MAX_COUNT) {
        LOG_ERROR("The input reference points count %{public}u exceeds %{public}u", pointCount,
            REFERENCE_POINTS_MAX_COUNT);
        return true;
    }
    return false;
}

bool DataFabricAddressApiHelper::IsStringLengthExceeds(size_t stringLen)
{
    if (stringLen > INPUT_STRING_MAX_COUNT) {
        LOG_ERROR("The input string length %{public}zu exceeds %{public}u", stringLen, INPUT_STRING_MAX_COUNT);
        return true;
    }
    return false;
}
} // End of namespace NativePreferences
} // End of namespace OHOS
