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
#include "message_parcel.h"

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

bool LocationPoint::Marshal(MessageParcel &parcel) const
{
    return parcel.WriteDouble(latitude) && parcel.WriteDouble(longitude);
}

bool LocationPoint::Unmarshal(MessageParcel &parcel)
{
    return parcel.ReadDouble(latitude) && parcel.ReadDouble(longitude);
}

bool LocationInfo::Marshal(MessageParcel &parcel) const
{
    return parcel.WriteInt32(static_cast<int32_t>(labelType)) &&
        parcel.WriteInt32(static_cast<int32_t>(coordinateSystemType)) && locationPoint.Marshal(parcel);
}

bool LocationInfo::Unmarshal(MessageParcel &parcel)
{
    int32_t labelValue = 0;
    int32_t coordinateSystemValue = 0;
    if (!parcel.ReadInt32(labelValue) || !parcel.ReadInt32(coordinateSystemValue)) {
        return false;
    }
    labelType = static_cast<LabelType>(labelValue);
    coordinateSystemType = static_cast<CoordinateSystemType>(coordinateSystemValue);
    return locationPoint.Unmarshal(parcel);
}

bool ReferenceLocationInfo::Marshal(MessageParcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(actionType)) ||
        !parcel.WriteInt32(static_cast<int32_t>(points.size()))) {
        return false;
    }
    for (const auto &point : points) {
        if (!point.Marshal(parcel)) {
            return false;
        }
    }
    return true;
}

bool ReferenceLocationInfo::Unmarshal(MessageParcel &parcel)
{
    int32_t actionValue = 0;
    int32_t pointsCount = 0;
    if (!parcel.ReadInt32(actionValue) || !parcel.ReadInt32(pointsCount)) {
        return false;
    }
    actionType = static_cast<ActionType>(actionValue);
    points.clear();
    for (int32_t i = 0; i < pointsCount; ++i) {
        LocationInfo point;
        if (!point.Unmarshal(parcel)) {
            return false;
        }
        points.push_back(point);
    }
    return true;
}

bool DataFabricAddressParams::Marshal(MessageParcel &parcel) const
{
    return parcel.WriteInt32(static_cast<int32_t>(scenarioType)) && locationInfo.Marshal(parcel);
}

bool DataFabricAddressParams::Unmarshal(MessageParcel &parcel)
{
    int32_t scenarioValue = 0;
    if (!parcel.ReadInt32(scenarioValue)) {
        return false;
    }
    scenarioType = static_cast<BusinessScenario>(scenarioValue);
    return locationInfo.Unmarshal(parcel);
}
} // End of namespace NativePreferences
} // End of namespace OHOS
