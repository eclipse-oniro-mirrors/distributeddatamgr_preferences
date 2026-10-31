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

#ifndef DATA_FABRIC_ADDRESS_TYPES_H
#define DATA_FABRIC_ADDRESS_TYPES_H

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "preferences_visibility.h"

namespace OHOS {
class MessageParcel;
} // namespace OHOS

namespace OHOS {
namespace NativePreferences {

constexpr double DEFAULT_INVALID_LAT_VALUE = 100.0;
constexpr double DEFAULT_INVALID_LNG_VALUE = 200.0;
const std::string HOME_LABEL_NAME = "HOME";
const std::string COMPANY_LABEL_NAME = "COMPANY";
const std::string WGS84_NAME = "WGS84";
const std::string GCJ02_NAME = "GCJ02";

enum BusinessScenario : int32_t {
    SCENARIO_NAVIGATION_COMMUTE = 0,
    OTHERS = 1,
};

enum ActionType : int32_t {
    SUBSCRIPTION = 0,
    UPDATE = 1,
};

enum LabelType : int32_t {
    HOME = 0,
    COMPANY = 1,
};

enum CoordinateSystemType : int32_t {
    WGS84 = 0,
    GCJ02 = 1,
};

enum StatusCode : int32_t {
    SUCCESS = 0,
    FAILURE = 1,
};

struct LocationPoint {
    double latitude = DEFAULT_INVALID_LAT_VALUE;
    double longitude = DEFAULT_INVALID_LNG_VALUE;

    PREF_API_EXPORT bool Marshal(MessageParcel &parcel) const;
    PREF_API_EXPORT bool Unmarshal(MessageParcel &parcel);
};

struct LocationInfo {
    LabelType labelType;
    CoordinateSystemType coordinateSystemType;
    LocationPoint locationPoint;

    PREF_API_EXPORT bool Marshal(MessageParcel &parcel) const;
    PREF_API_EXPORT bool Unmarshal(MessageParcel &parcel);
};

struct ReferenceLocationInfo {
    ActionType actionType;
    std::vector<LocationInfo> points;

    PREF_API_EXPORT bool Marshal(MessageParcel &parcel) const;
    PREF_API_EXPORT bool Unmarshal(MessageParcel &parcel);
};

struct DataFabricAddressParams {
    BusinessScenario scenarioType;
    ReferenceLocationInfo locationInfo;

    PREF_API_EXPORT bool Marshal(MessageParcel &parcel) const;
    PREF_API_EXPORT bool Unmarshal(MessageParcel &parcel);

    bool operator<(const DataFabricAddressParams& other) const
    {
        if (locationInfo.actionType != other.locationInfo.actionType) {
            return locationInfo.actionType < other.locationInfo.actionType;
        }
        if (locationInfo.points.size() != other.locationInfo.points.size()) {
            return locationInfo.points.size() < other.locationInfo.points.size();
        }
        for (size_t i = 0; i < locationInfo.points.size(); ++i) {
            if (locationInfo.points[i].labelType != other.locationInfo.points[i].labelType) {
                return locationInfo.points[i].labelType < other.locationInfo.points[i].labelType;
            }
            if (locationInfo.points[i].coordinateSystemType != other.locationInfo.points[i].coordinateSystemType) {
                return locationInfo.points[i].coordinateSystemType < other.locationInfo.points[i].coordinateSystemType;
            }
            if (locationInfo.points[i].locationPoint.latitude != other.locationInfo.points[i].locationPoint.latitude) {
                return locationInfo.points[i].locationPoint.latitude <
                    other.locationInfo.points[i].locationPoint.latitude;
            }
            if (locationInfo.points[i].locationPoint.longitude !=
                other.locationInfo.points[i].locationPoint.longitude) {
                return locationInfo.points[i].locationPoint.longitude <
                    other.locationInfo.points[i].locationPoint.longitude;
            }
        }
        return scenarioType < other.scenarioType;
    }

    bool operator==(const DataFabricAddressParams& other) const
    {
        if (scenarioType != other.scenarioType || locationInfo.actionType != other.locationInfo.actionType ||
            locationInfo.points.size() != other.locationInfo.points.size()) {
            return false;
        }
        for (size_t i = 0; i < locationInfo.points.size(); ++i) {
            if (locationInfo.points[i].labelType != other.locationInfo.points[i].labelType ||
                locationInfo.points[i].coordinateSystemType != other.locationInfo.points[i].coordinateSystemType ||
                locationInfo.points[i].locationPoint.latitude != other.locationInfo.points[i].locationPoint.latitude ||
                locationInfo.points[i].locationPoint.longitude !=
                other.locationInfo.points[i].locationPoint.longitude) {
                return false;
            }
        }
        return true;
    }
};

struct DataProcessingResponse {
    StatusCode code = StatusCode::FAILURE;
    std::string result;
};

class DataFabricAddressTypes {
public:
    static PREF_API_EXPORT bool LabelNameToType(const std::string& strValue, LabelType& labelType);
    static PREF_API_EXPORT bool CoordinateSystemNameToType(const std::string& strValue,
        CoordinateSystemType& coordinateSystemType);
private:
    DataFabricAddressTypes() = default;
    ~DataFabricAddressTypes() = default;
    static bool StringEnumToInteger(std::unordered_map<std::string, int32_t> map,
        const std::string& strValue, int32_t& intValue);
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_TYPES_H
