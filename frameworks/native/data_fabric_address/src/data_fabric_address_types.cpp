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

#include "data_fabric_address_types.h"

#include "log_print.h"

#undef LOG_TAG
#define LOG_TAG "DataFabricAddressTypes"

namespace OHOS {
namespace NativePreferences {

const std::unordered_map<std::string, int32_t> labelMap = {
    { HOME_LABEL_NAME, static_cast<int32_t>(LabelType::HOME) },
    { COMPANY_LABEL_NAME, static_cast<int32_t>(LabelType::COMPANY) }
};

const std::unordered_map<std::string, int32_t> coordinateSystemMap = {
    { WGS84_NAME, static_cast<int32_t>(CoordinateSystemType::WGS84) },
    { GCJ02_NAME, static_cast<int32_t>(CoordinateSystemType::GCJ02) }
};

bool DataFabricAddressTypes::LabelNameToType(const std::string& strValue, LabelType& labelType)
{
    int32_t intValue;
    if (!StringEnumToInteger(labelMap, strValue, intValue)) {
        return false;
    }
    labelType = static_cast<LabelType>(intValue);
    return true;
}

bool DataFabricAddressTypes::CoordinateSystemNameToType(const std::string& strValue,
    CoordinateSystemType& coordinateSystemType)
{
    int32_t intValue;
    if (!StringEnumToInteger(coordinateSystemMap, strValue, intValue)) {
        return false;
    }
    coordinateSystemType = static_cast<CoordinateSystemType>(intValue);
    return true;
}

bool DataFabricAddressTypes::StringEnumToInteger(std::unordered_map<std::string, int32_t> map,
    const std::string& strValue, int32_t& intValue)
{
    if (map.find(strValue) == map.end()) {
        return false;
    }

    intValue = map[strValue];
    return true;
}
} // End of namespace NativePreferences
} // End of namespace OHOS
