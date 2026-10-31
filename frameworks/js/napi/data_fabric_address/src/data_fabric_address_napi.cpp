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

#include "data_fabric_address_napi.h"

#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
#include "data_fabric_address_api_helper.h"
#include "data_fabric_address_client.h"
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE

#include "data_fabric_address_errors.h"

#undef LOG_TAG
#define LOG_TAG "DataFabricAddressNapi"

namespace OHOS {
namespace DataFabricAddress {
#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
std::mutex DataFabricAddressNapi::g_instancesMutex;
std::unordered_map<napi_env, std::weak_ptr<DataFabricAddressNapi>> DataFabricAddressNapi::g_napiInstances;

constexpr size_t NAPI_ARG_COUNT_NO_CALLBACK = 1;
constexpr size_t NAPI_ARG_COUNT_WITH_CALLBACK = 2;
constexpr double DEFAULT_DOUBLE_ZERO_VALUE = 0.0;
constexpr const char* ARGS_ATTR_SCENARIO_TYPE = "scenarioType";
constexpr const char* ARGS_ATTR_REFERENCE_LOCATION_INFO = "locationInfo";
constexpr const char* ARGS_ATTR_ACTION_TYPE = "actionType";
constexpr const char* ARGS_ATTR_REFERENCE_POINTS = "points";
constexpr const char* ARGS_ATTR_LABEL_NAME = "label";
constexpr const char* ARGS_ATTR_COORDINATE_SYSTEM_NAME = "coordinateSystemName";
constexpr const char* ARGS_ATTR_LOCATION_POINT = "locationPoint";
constexpr const char* ARGS_ATTR_LATITUDE = "latitude";
constexpr const char* ARGS_ATTR_LONGITUDE = "longitude";
const std::vector<std::string> EXPECTED_STATIC_ARG_TYPES_R1 = { "object", "function" };
const std::vector<std::string> EXPECTED_STATIC_ARG_TYPES_R2 = { "object" };
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE

constexpr const char* ENUM_ATTR_SCENARIO_NAVIGATION_COMMUTE = "SCENARIO_NAVIGATION_COMMUTE";
constexpr const char* ENUM_ATTR_SCENARIO_OTHERS = "OTHERS";
constexpr const char* ENUM_ATTR_ACTION_SUBSCRIPTION = "SUBSCRIPTION";
constexpr const char* ENUM_ATTR_ACTION_UPDATE = "UPDATE";
constexpr const char* ENUM_ATTR_LABEL_HOME = "HOME";
constexpr const char* ENUM_ATTR_LABEL_COMPANY = "COMPANY";
constexpr const char* ENUM_ATTR_COORDINATE_SYSTEM_WGS84 = "WGS84";
constexpr const char* ENUM_ATTR_COORDINATE_SYSTEM_GCJ02 = "GCJ02";
constexpr const char* ENUM_ATTR_STATUS_CODE_SUCCESS = "SUCCESS";
constexpr const char* ENUM_ATTR_STATUS_CODE_FAILURE = "FAILURE";

napi_value DataFabricAddressNapi::Init(napi_env env, napi_value exports)
{
    LOG_INFO("DataFabricAddressNapi Init enter.");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("onDataFabricAddress", OnDataFabricAddress),
        DECLARE_NAPI_STATIC_FUNCTION("offDataFabricAddress", OffDataFabricAddress),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
    if (GetOrCreateInstance(env, exports) == nullptr) {
        LOG_ERROR("Failed to create napi instance in Init.");
    }
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
    DefineBusinessScenario(env, exports);
    DefineActionType(env, exports);
    DefineLabelName(env, exports);
    DefineCoordinateSystemName(env, exports);
    DefineStatusCode(env, exports);
    return exports;
}

napi_value DataFabricAddressNapi::OnDataFabricAddress(napi_env env, napi_callback_info info)
{
    LOG_INFO("OnDataFabricAddress enter.");
#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
    size_t argc = NAPI_ARG_COUNT_WITH_CALLBACK;
    napi_value args[NAPI_ARG_COUNT_WITH_CALLBACK] = { nullptr };
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, nullptr, &data));
    if (argc != NAPI_ARG_COUNT_WITH_CALLBACK) {
        ThrowErr(env, NativePreferences::PARAMETER_EXCEPTION, "Wrong number of arguments.");
        return nullptr;
    }
    if (!ValidateArgsType(env, args, argc, EXPECTED_STATIC_ARG_TYPES_R1)) {
        ThrowErr(env, NativePreferences::PARAMETER_EXCEPTION, "Valid arguments type failed.");
        return nullptr;
    }
    DataFabricAddressParams inputParams;
    if (!CheckInputParams(env, args[0], inputParams)) {
        ThrowErr(env, NativePreferences::PARAMETER_EXCEPTION, "Check input params failed.");
        return nullptr;
    }
    if (!DoSubscribe(env, args[1], inputParams)) {
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    LOG_INFO("OnDataFabricAddress exit.");
    return result;
#else
    ThrowErr(env, NativePreferences::DEVICE_EXCEPTION, "Device not supported the interface OnDataFabricAddress.");
    return nullptr;
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
}

napi_value DataFabricAddressNapi::OffDataFabricAddress(napi_env env, napi_callback_info info)
{
    LOG_INFO("OffDataFabricAddress enter.");
#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
    size_t argc = NAPI_ARG_COUNT_WITH_CALLBACK;
    napi_value args[NAPI_ARG_COUNT_WITH_CALLBACK] = { nullptr };
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, nullptr, &data));
    LOG_INFO("OffDataFabricAddress argc=%{public}zu", argc);
    if (argc < NAPI_ARG_COUNT_NO_CALLBACK || argc > NAPI_ARG_COUNT_WITH_CALLBACK) {
        ThrowErr(env, NativePreferences::PARAMETER_EXCEPTION, "Wrong number of arguments.");
        return nullptr;
    }
    std::vector<std::string> expectedTypes;
    if (argc == NAPI_ARG_COUNT_WITH_CALLBACK) {
        expectedTypes = EXPECTED_STATIC_ARG_TYPES_R1;
    } else {
        expectedTypes = EXPECTED_STATIC_ARG_TYPES_R2;
    }
    if (!ValidateArgsType(env, args, argc, expectedTypes)) {
        ThrowErr(env, NativePreferences::PARAMETER_EXCEPTION, "Valid arguments type failed.");
        return nullptr;
    }
    DataFabricAddressParams inputParams;
    if (!CheckInputParams(env, args[0], inputParams)) {
        ThrowErr(env, NativePreferences::PARAMETER_EXCEPTION, "Check input params failed..");
        return nullptr;
    }
    napi_value callback = (argc == NAPI_ARG_COUNT_WITH_CALLBACK) ? args[1] : nullptr;
    if (!DoUnsubscribe(env, callback, inputParams)) {
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    LOG_INFO("OffDataFabricAddress exit.");
    return result;
#else
    ThrowErr(env, NativePreferences::DEVICE_EXCEPTION, "Device not supported the interface OffDataFabricAddress.");
    return nullptr;
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
}

void DataFabricAddressNapi::DefineBusinessScenario(napi_env env, napi_value exports)
{
    napi_value scenarioType = nullptr;
    napi_status status = napi_create_object(env, &scenarioType);
    if (status != napi_ok) {
        LOG_ERROR("Failed to create scenarioType object.");
        return;
    }
    SetInt32Property(env, scenarioType, static_cast<int32_t>(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE),
        ENUM_ATTR_SCENARIO_NAVIGATION_COMMUTE);
    SetInt32Property(env, scenarioType, static_cast<int32_t>(BusinessScenario::OTHERS), ENUM_ATTR_SCENARIO_OTHERS);
    SetPropertyName(env, exports, "BusinessScenario", scenarioType);
}

void DataFabricAddressNapi::DefineActionType(napi_env env, napi_value exports)
{
    napi_value actionType = nullptr;
    napi_status status = napi_create_object(env, &actionType);
    if (status != napi_ok) {
        LOG_ERROR("Failed to create actionType object.");
        return;
    }
    SetInt32Property(env, actionType, static_cast<int32_t>(ActionType::SUBSCRIPTION), ENUM_ATTR_ACTION_SUBSCRIPTION);
    SetInt32Property(env, actionType, static_cast<int32_t>(ActionType::UPDATE), ENUM_ATTR_ACTION_UPDATE);
    SetPropertyName(env, exports, "ActionType", actionType);
}

void DataFabricAddressNapi::DefineLabelName(napi_env env, napi_value exports)
{
    napi_value labelName = nullptr;
    napi_status status = napi_create_object(env, &labelName);
    if (status != napi_ok) {
        LOG_ERROR("Failed to create labelName object.");
        return;
    }
    SetStringProperty(env, labelName, ENUM_ATTR_LABEL_HOME, ENUM_ATTR_LABEL_HOME);
    SetStringProperty(env, labelName, ENUM_ATTR_LABEL_COMPANY, ENUM_ATTR_LABEL_COMPANY);
    SetPropertyName(env, exports, "LabelName", labelName);
}

void DataFabricAddressNapi::DefineCoordinateSystemName(napi_env env, napi_value exports)
{
    napi_value coordinateSystemName = nullptr;
    napi_status status = napi_create_object(env, &coordinateSystemName);
    if (status != napi_ok) {
        LOG_ERROR("Failed to create coordinateSystemName object.");
        return;
    }
    SetStringProperty(env, coordinateSystemName, ENUM_ATTR_COORDINATE_SYSTEM_WGS84, ENUM_ATTR_COORDINATE_SYSTEM_WGS84);
    SetStringProperty(env, coordinateSystemName, ENUM_ATTR_COORDINATE_SYSTEM_GCJ02, ENUM_ATTR_COORDINATE_SYSTEM_GCJ02);
    SetPropertyName(env, exports, "CoordinateSystemName", coordinateSystemName);
}

void DataFabricAddressNapi::DefineStatusCode(napi_env env, napi_value exports)
{
    napi_value statusCode = nullptr;
    napi_status status = napi_create_object(env, &statusCode);
    if (status != napi_ok) {
        LOG_ERROR("Failed to create statusCode object.");
        return;
    }
    SetInt32Property(env, statusCode, static_cast<int32_t>(StatusCode::SUCCESS), ENUM_ATTR_STATUS_CODE_SUCCESS);
    SetInt32Property(env, statusCode, static_cast<int32_t>(StatusCode::FAILURE), ENUM_ATTR_STATUS_CODE_FAILURE);
    SetPropertyName(env, exports, "StatusCode", statusCode);
}

void DataFabricAddressNapi::SetPropertyName(napi_env env, napi_value targetObj,
    const char *propName, napi_value propValue)
{
    napi_status status = napi_set_named_property(env, targetObj, propName, propValue);
    if (status != napi_ok) {
        LOG_ERROR("Failed to call napi_set_named_property.");
    }
}

void DataFabricAddressNapi::SetInt32Property(napi_env env, napi_value targetObj,
    int32_t value, const char *propName)
{
    napi_value prop = nullptr;
    napi_status status = napi_create_int32(env, value, &prop);
    if (status != napi_ok) {
        LOG_ERROR("Failed to call napi_create_int32.");
        return;
    }
    SetPropertyName(env, targetObj, propName, prop);
}

void DataFabricAddressNapi::SetStringProperty(napi_env env, napi_value targetObj,
    const std::string &value, const char *propName)
{
    napi_value prop = nullptr;
    napi_status status = napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &prop);
    if (status != napi_ok) {
        LOG_ERROR("Failed to call napi_create_string_utf8.");
        return;
    }
    SetPropertyName(env, targetObj, propName, prop);
}

void DataFabricAddressNapi::ThrowErr(napi_env env, int32_t errorCode, const std::string& printMsg)
{
    LOG_ERROR("Business error, error code=%{public}d, error message=%{public}s", errorCode, printMsg.c_str());
    std::optional<std::string> msg = NativePreferences::DataFabricAddressErrors::GetErrMsg(errorCode);
    if (!msg) {
        LOG_ERROR("The error code=%{public}d is invalid, use default internal code.", errorCode);
        errorCode = NativePreferences::INTERNAL_EXCEPTION;
        msg = "Internal error in the API.";
    }
    napi_value error = CreateNapiError(env, errorCode, msg.value());
    napi_throw(env, error);
}

napi_value DataFabricAddressNapi::CreateNapiError(napi_env env, int32_t errorCode, const std::string& errorMsg)
{
    napi_value code = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errorCode, &code));
    napi_value msg = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, errorMsg.c_str(), NAPI_AUTO_LENGTH, &msg));
    napi_value businessError = nullptr;
    napi_create_error(env, nullptr, msg, &businessError);
    napi_set_named_property(env, businessError, "code", code);
    return businessError;
}

#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
bool DataFabricAddressNapi::ValidateArgsType(napi_env env, napi_value *args, size_t argc,
    const std::vector<std::string> &expectedTypes)
{
    napi_valuetype valueType = napi_undefined;
    if (argc != expectedTypes.size()) {
        LOG_ERROR("Wrong number of the input arguments, the input number=%{public}zu, "
            "the expected number=%{public}zu.", argc, expectedTypes.size());
        return false;
    }

    for (size_t i = 0; i < argc; ++i) {
        napi_status status = napi_typeof(env, args[i], &valueType);
        if (status != napi_ok) {
            LOG_ERROR("Failed to call napi_typeof.");
            return false;
        }
        std::string expectedType = expectedTypes[i];
        if ((expectedType == "object" && valueType != napi_object) ||
            (expectedType == "function" && valueType != napi_function)) {
            LOG_ERROR("Failed to check the input argument type.");
            return false;
        }
    }
    return true;
}

bool DataFabricAddressNapi::CheckInputParams(napi_env env, napi_value jsParams, DataFabricAddressParams& inputParams)
{
    int32_t scenarioType = 0;
    if (!ReadIntValueFromJs(env, jsParams, ARGS_ATTR_SCENARIO_TYPE, scenarioType)) {
        LOG_ERROR("Get scenario type from napi failed.");
        return false;
    }
    if (!NativePreferences::DataFabricAddressApiHelper::IsValidIntEnumValue(scenarioType,
        static_cast<int32_t>(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE),
        static_cast<int32_t>(BusinessScenario::OTHERS))) {
        LOG_ERROR("The scenario type is out of range for enum 'BusinessScenario'.");
        return false;
    }
    inputParams.scenarioType = static_cast<BusinessScenario>(scenarioType);
    if (!ReadReferenceLocationInfo(env, jsParams, inputParams.locationInfo)) {
        LOG_ERROR("Get reference location info failed.");
        return false;
    }
    return true;
}

bool DataFabricAddressNapi::ReadReferenceLocationInfo(napi_env env, napi_value jsParams,
    ReferenceLocationInfo& locationInfo)
{
    napi_value jsLocationInfo;
    napi_status status = napi_get_named_property(env, jsParams, ARGS_ATTR_REFERENCE_LOCATION_INFO, &jsLocationInfo);
    if (status != napi_ok) {
        LOG_ERROR("Get reference location info from napi failed.");
        return false;
    }
    int32_t actionValue = 0;
    if (!ReadIntValueFromJs(env, jsLocationInfo, ARGS_ATTR_ACTION_TYPE, actionValue)) {
        LOG_ERROR("Get action type from napi failed.");
        return false;
    }
    if (!NativePreferences::DataFabricAddressApiHelper::IsValidIntEnumValue(actionValue,
        static_cast<int32_t>(ActionType::SUBSCRIPTION), static_cast<int32_t>(ActionType::UPDATE))) {
        LOG_ERROR("The action type is out of range for enum 'ActionType'.");
        return false;
    }
    locationInfo.actionType = static_cast<ActionType>(actionValue);
    if (!ReadReferencePoints(env, jsLocationInfo, locationInfo.points)) {
        LOG_ERROR("Get reference points from napi failed.");
        return false;
    }
    return true;
}

bool DataFabricAddressNapi::ReadReferencePoints(napi_env env, napi_value jsLocationInfo,
    std::vector<LocationInfo>& points)
{
    napi_value jsReferencePoints;
    napi_status status = napi_get_named_property(env, jsLocationInfo, ARGS_ATTR_REFERENCE_POINTS, &jsReferencePoints);
    if (status != napi_ok) {
        LOG_ERROR("Get reference points info from napi failed.");
        return false;
    }
    bool isArray = false;
    status = napi_is_array(env, jsReferencePoints, &isArray);
    if (status != napi_ok || !isArray) {
        LOG_ERROR("Get reference points type from napi failed or the type is not array, isArray=%{public}s.",
            isArray ? "true" : "false");
        return false;
    }
    uint32_t pointCount = 0;
    status = napi_get_array_length(env, jsReferencePoints, &pointCount);
    if (status != napi_ok) {
        LOG_ERROR("Get reference points count from napi failed.");
        return false;
    }
    if (NativePreferences::DataFabricAddressApiHelper::IsPointsCountExceeds(pointCount)) {
        LOG_ERROR("The reference points count %{public}d exceeds max count.", pointCount);
        return false;
    }
    for (uint32_t i = 0; i < pointCount; i++) {
        napi_value jsLocationPointInfo;
        status = napi_get_element(env, jsReferencePoints, i, &jsLocationPointInfo);
        if (status != napi_ok) {
            LOG_ERROR("Get reference points element from napi failed.");
            return false;
        }
        LocationInfo locationPointInfo;
        if (!ReadReferencePointInfo(env, jsLocationPointInfo, locationPointInfo)) {
            LOG_ERROR("Read index %{public}d reference point failed.", i);
            return false;
        }
        points.push_back(locationPointInfo);
    }
    return true;
}

bool DataFabricAddressNapi::ReadReferencePointInfo(napi_env env, napi_value jsLocationInfo,
    LocationInfo& locationPointInfo)
{
    std::string labelName;
    if (!ReadStringValueFromJs(env, jsLocationInfo, ARGS_ATTR_LABEL_NAME, labelName)) {
        LOG_ERROR("Get label from napi failed.");
        return false;
    }
    if (!NativePreferences::DataFabricAddressTypes::LabelNameToType(labelName, locationPointInfo.labelType)) {
        LOG_ERROR("The label name is out of range for enum 'LabelName'.");
        return false;
    }
    std::string coordinateSystemName;
    if (!ReadStringValueFromJs(env, jsLocationInfo, ARGS_ATTR_COORDINATE_SYSTEM_NAME, coordinateSystemName)) {
        LOG_ERROR("Get coordinate system name from napi failed.");
        return false;
    }
    if (!NativePreferences::DataFabricAddressTypes::CoordinateSystemNameToType(coordinateSystemName,
        locationPointInfo.coordinateSystemType)) {
        LOG_ERROR("The coordinate system name is out of range for enum 'CoordinateSystemName'.");
        return false;
    }
    if (!ReadLocationPoint(env, jsLocationInfo, locationPointInfo.locationPoint)) {
        LOG_ERROR("Get location point failed.");
        return false;
    }
    return true;
}

bool DataFabricAddressNapi::ReadLocationPoint(napi_env env, napi_value jsParams, LocationPoint& locationPoint)
{
    napi_value jsLocationPoint;
    napi_status status = napi_get_named_property(env, jsParams, ARGS_ATTR_LOCATION_POINT, &jsLocationPoint);
    if (status != napi_ok) {
        LOG_ERROR("Get %{public}s from napi failed.", ARGS_ATTR_LOCATION_POINT);
        return false;
    }
    double latitude = DEFAULT_DOUBLE_ZERO_VALUE;
    if (!ReadDoubleValueFromJs(env, jsLocationPoint, ARGS_ATTR_LATITUDE, latitude)) {
        LOG_ERROR("Get latitude from napi failed.");
        return false;
    }
    double longitude = DEFAULT_DOUBLE_ZERO_VALUE;
    if (!ReadDoubleValueFromJs(env, jsLocationPoint, ARGS_ATTR_LONGITUDE, longitude)) {
        LOG_ERROR("Get longitude from napi failed.");
        return false;
    }
    if (!NativePreferences::DataFabricAddressApiHelper::IsValidLatLng(latitude, longitude)) {
        LOG_ERROR("Check the input latitude=%{public}.6f or longitude=%{public}.6f failed.", latitude, longitude);
        return false;
    }
    locationPoint.latitude = latitude;
    locationPoint.longitude = longitude;
    return true;
}

bool DataFabricAddressNapi::ReadIntValueFromJs(napi_env env, napi_value jsParams,
    const std::string& paramKey, int32_t& value)
{
    napi_value jsParam = nullptr;
    napi_status status = napi_get_named_property(env, jsParams, paramKey.c_str(), &jsParam);
    if (status != napi_ok) {
        LOG_ERROR("Get %{public}s from napi failed.", paramKey.c_str());
        return false;
    }
    status = napi_get_value_int32(env, jsParam, &value);
    if (status != napi_ok) {
        LOG_ERROR("Get %{public}s int value from napi failed.", paramKey.c_str());
        return false;
    }
    return true;
}

bool DataFabricAddressNapi::ReadDoubleValueFromJs(napi_env env, napi_value jsParams,
    const std::string& paramKey, double& value)
{
    napi_value jsParam = nullptr;
    napi_status status = napi_get_named_property(env, jsParams, paramKey.c_str(), &jsParam);
    if (status != napi_ok) {
        LOG_ERROR("Get %{public}s from napi failed.", paramKey.c_str());
        return false;
    }
    status = napi_get_value_double(env, jsParam, &value);
    if (status != napi_ok) {
        LOG_ERROR("Get %{public}s double value from napi failed.", paramKey.c_str());
        return false;
    }
    return true;
}

bool DataFabricAddressNapi::ReadStringValueFromJs(napi_env env, napi_value jsParams,
    const std::string& paramKey, std::string& value)
{
    napi_value jsParam = nullptr;
    napi_status status = napi_get_named_property(env, jsParams, paramKey.c_str(), &jsParam);
    if (status != napi_ok) {
        LOG_ERROR("Get %{public}s from napi failed.", paramKey.c_str());
        return false;
    }
    size_t strLen = 0;
    status = napi_get_value_string_utf8(env, jsParam, nullptr, 0, &strLen);
    if (status != napi_ok) {
        LOG_ERROR("Get %{public}s string length from napi failed.", paramKey.c_str());
        return false;
    }
    if (strLen == 0) {
        LOG_WARN("The %{public}s string length is zero.", paramKey.c_str());
        return true;
    }
    if (NativePreferences::DataFabricAddressApiHelper::IsStringLengthExceeds(strLen)) {
        LOG_ERROR("The %{public}s string length exceeds max length.", paramKey.c_str());
        return false;
    }
    std::vector<char> buf(strLen + 1);
    status = napi_get_value_string_utf8(env, jsParam, buf.data(), buf.size(), &strLen);
    if (status != napi_ok) {
        LOG_ERROR("Get %{public}s string value from napi failed.", paramKey.c_str());
        return false;
    }
    value = std::string(buf.data());
    return true;
}

bool DataFabricAddressNapi::DoSubscribe(napi_env env, napi_value callback,
    const DataFabricAddressParams& inputParams)
{
    LOG_INFO("DoSubscribe enter.");
    auto instance = TryGetExistingInstance(env);
    if (instance == nullptr) {
        ThrowErr(env, NativePreferences::SUBSCRIBE_EXCEPTION, "Get napi instance failed.");
        return false;
    }
    if (!instance->AddCallback(env, callback, inputParams)) {
        ThrowErr(env, NativePreferences::SUBSCRIBE_EXCEPTION, "Add callback to cache failed.");
        return false;
    }
    auto listener = std::make_shared<DataFabricAddressListener>(env, inputParams);
    int32_t result = DataFabricAddressClient::GetInstance().Subscribe(inputParams, listener);
    if (result != NativePreferences::RUN_OK) {
        if (!instance->RollbackCallback(env, inputParams)) {
            ThrowErr(env, NativePreferences::SUBSCRIBE_EXCEPTION, "Rollback callback from cache failed.");
            return false;
        }
        ThrowErr(env, result, "Subscribe service failed.");
        return false;
    }
    LOG_INFO("DoSubscribe exit.");
    return true;
}

bool DataFabricAddressNapi::DoUnsubscribe(napi_env env, napi_value callback,
    const DataFabricAddressParams& inputParams)
{
    LOG_INFO("DoUnsubscribe enter.");
    auto instance = TryGetExistingInstance(env);
    if (instance == nullptr) {
        ThrowErr(env, NativePreferences::UNSUBSCRIBE_EXCEPTION, "Get napi instance failed.");
        return false;
    }
    if (!instance->HasCallback(inputParams)) {
        ThrowErr(env, NativePreferences::UNSUBSCRIBE_EXCEPTION, "No callback in the cache.");
        return false;
    }
    int32_t result = DataFabricAddressClient::GetInstance().Unsubscribe(inputParams);
    if (result != NativePreferences::RUN_OK) {
        ThrowErr(env, result, "Unsubscribe service failed.");
        return false;
    }
    if (!instance->RemoveCallback(env, callback, inputParams)) {
        ThrowErr(env, NativePreferences::UNSUBSCRIBE_EXCEPTION, "Remove callback from cache failed.");
        return false;
    }
    LOG_INFO("DoSubscribe exit.");
    return true;
}

std::shared_ptr<DataFabricAddressNapi> DataFabricAddressNapi::GetOrCreateInstance(napi_env env, napi_value wrapTarget)
{
    LOG_INFO("GetOrCreateInstance enter.");
    auto instance = TryGetExistingInstance(env);
    if (instance != nullptr) {
        LOG_INFO("Has instance in g_napiInstances.");
        return instance;
    }

    auto sp = std::make_shared<DataFabricAddressNapi>();
    {
        std::lock_guard<std::mutex> lock(g_instancesMutex);
        auto it = g_napiInstances.find(env);
        if (it != g_napiInstances.end()) {
            auto exist = it->second.lock();
            if (exist) {
                LOG_INFO("The cache instance has been add by other thread.");
                return exist;
            }
            LOG_INFO("Update cache instance.");
            it->second = sp;
        } else {
            LOG_INFO("Add cache instance.");
            g_napiInstances.emplace(env, sp);
        }
    }

    auto *holder = new (std::nothrow) InstanceHolder{sp};
    if (holder == nullptr) {
        LOG_ERROR("Failed to alloc InstanceHolder.");
        RollbackSaveInstances(env, sp);
        return nullptr;
    }
    if (!CallNapiWrap(env, wrapTarget, holder)) {
        LOG_ERROR("Failed to call napi_warp.");
        delete holder;
        RollbackSaveInstances(env, sp);
        return nullptr;
    }
    LOG_INFO("GetOrCreateInstance exit.");
    return sp;
}

bool DataFabricAddressNapi::CallNapiWrap(napi_env env, napi_value wrapTarget, InstanceHolder *holder)
{
    napi_status status = napi_wrap(env, wrapTarget, reinterpret_cast<void *>(holder),
        [](napi_env env, void *data, void *hint) {
            (void)hint;
            LOG_INFO(" enter.");
            InstanceHolder *holder = static_cast<InstanceHolder *>(data);
            {
                std::lock_guard<std::mutex> lock(g_instancesMutex);
                auto it = g_napiInstances.find(env);
                if (it != g_napiInstances.end()) {
                    g_napiInstances.erase(env);
                    LOG_INFO("Remove instance from g_napiInstances.");
                }
            }
            delete holder;
        }, nullptr, nullptr);
    if (status != napi_ok) {
        LOG_ERROR("Failed to call napi_warp.");
        return false;
    }
    return true;
}

std::shared_ptr<DataFabricAddressNapi> DataFabricAddressNapi::TryGetExistingInstance(napi_env env)
{
    LOG_INFO("TryGetExistingInstance enter, g_napiInstances size=%{public}zu", g_napiInstances.size());
    std::lock_guard<std::mutex> lock(g_instancesMutex);
    auto it = g_napiInstances.find(env);
    if (it == g_napiInstances.end()) {
        LOG_INFO("No instance in g_napiInstances.");
        return nullptr;
    }
    LOG_INFO("The g_napiInstances instance use_count=%{public}ld", it->second.use_count());
    return it->second.lock();
}

void DataFabricAddressNapi::RollbackSaveInstances(napi_env env, const std::shared_ptr<DataFabricAddressNapi> &sp)
{
    LOG_INFO("RollbackSaveInstances enter.");
    std::lock_guard<std::mutex> lock(g_instancesMutex);
    auto it = g_napiInstances.find(env);
    if (it == g_napiInstances.end()) {
        LOG_INFO("No instance in g_napiInstances.");
        return;
    }
    auto current = it->second.lock();
    if (current && current.get() == sp.get()) {
        g_napiInstances.erase(it);
        LOG_INFO("Remove instance from g_napiInstances.");
    }
    LOG_INFO("RollbackSaveInstances exit.");
}

bool DataFabricAddressNapi::AddCallback(napi_env env, napi_value refHandler,
    const DataFabricAddressParams& inputParams)
{
    LOG_INFO("AddCallback enter.");
    if (inputParams.locationInfo.actionType == ActionType::UPDATE) {
        LOG_INFO("The update action do not need to add callback.");
        return true;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = jsCbMap_.find(inputParams);
    if (iter != jsCbMap_.end()) {
        LOG_ERROR("Subscribe callback is already registered.");
        return false;
    }
    napi_ref newHandlerRef = nullptr;
    napi_status status = napi_create_reference(env, refHandler, 1, &newHandlerRef);
    if (status != napi_ok || newHandlerRef == nullptr) {
        LOG_ERROR("napi_create_reference failed.");
        return false;
    }
    auto listener = std::make_shared<DataFabricAddressListenerNapi>();
    listener->env = env;
    listener->handlerRef = newHandlerRef;
    jsCbMap_.emplace(inputParams, listener);
    LOG_INFO("AddCallback exit.");
    return true;
}

bool DataFabricAddressNapi::RollbackCallback(napi_env env, const DataFabricAddressParams& inputParams)
{
    LOG_INFO("RollbackCallback enter.");
    if (inputParams.locationInfo.actionType == ActionType::UPDATE) {
        LOG_INFO("The update action do not need to rollback callback.");
        return true;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = jsCbMap_.find(inputParams);
    if (iter == jsCbMap_.end()) {
        LOG_ERROR("The inputParams not found in the jsCbMap_.");
        return false;
    }
    jsCbMap_.erase(iter);
    LOG_INFO("RollbackCallback exit.");
    return true;
}

bool DataFabricAddressNapi::RemoveCallback(napi_env env, napi_value refHandler,
    const DataFabricAddressParams& inputParams)
{
    LOG_INFO("RemoveCallback enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = jsCbMap_.find(inputParams);
    if (iter == jsCbMap_.end()) {
        LOG_ERROR("The inputParams not found in the jsCbMap_.");
        return false;
    }
    if (refHandler == nullptr) {
        LOG_INFO("The refHandler is null, remove cache callback.");
        jsCbMap_.erase(iter);
        return true;
    }

    napi_value onHandler = nullptr;
    napi_status status = napi_get_reference_value(env, iter->second->handlerRef, &onHandler);
    if (status != napi_ok) {
        LOG_ERROR("napi_get_reference_value failed.");
        return false;
    }
    if (!IsSameValue(env, refHandler, onHandler)) {
        LOG_ERROR("The input callback is not equal with cache callback.");
        return false;
    }
    jsCbMap_.erase(iter);
    LOG_INFO("RemoveCallback exit.");
    return true;
}

bool DataFabricAddressNapi::HasCallback(const DataFabricAddressParams& inputParams)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = jsCbMap_.find(inputParams);
    if (iter == jsCbMap_.end()) {
        LOG_ERROR("The inputParams not found in the jsCbMap_.");
        return false;
    }
    return true;
}

bool DataFabricAddressNapi::IsSameValue(napi_env env, napi_value lhs, napi_value rhs)
{
    bool isEqual = false;
    napi_status status = napi_strict_equals(env, lhs, rhs, &isEqual);
    if (status != napi_ok) {
        LOG_ERROR("Failed to call napi_strict_equals.");
        return false;
    }
    return isEqual;
}

void DataFabricAddressNapi::SendToJs(napi_env env, napi_value handler, const DataProcessingResponse& response)
{
    LOG_INFO("SendToJs enter, code=%{public}d", static_cast<int32_t>(response.code));
    if (handler == nullptr) {
        LOG_ERROR("The input handler is null.");
        return;
    }
    napi_value jsValue = nullptr;
    napi_status status = napi_create_object(env, &jsValue);
    if (status != napi_ok) {
        LOG_ERROR("Failed to create object.");
        return;
    }

    SetInt32Value(env, "code", static_cast<int32_t>(response.code), jsValue);
    SetUtf8StringValue(env, "result", response.result, jsValue);

    napi_value callResult = nullptr;
    if (napi_call_function(env, nullptr, handler, 1, &jsValue, &callResult) != napi_ok) {
        LOG_ERROR("Failed to call function.");
        napi_value exception = nullptr;
        if (napi_get_and_clear_last_exception(env, &exception) != napi_ok) {
            LOG_WARN("Failed to get and clear last napi excaption.");
        }
    }
    LOG_INFO("SendToJs exit");
}

bool DataFabricAddressNapi::DispatchToCallback(napi_env env, const DataFabricAddressParams& params,
    const DataProcessingResponse& response)
{
    LOG_INFO("DispatchToCallback enter.");
    napi_value handler = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto iter = jsCbMap_.find(params);
        if (iter == jsCbMap_.end()) {
            LOG_ERROR("Dispatch to callback failed, no callback found.");
            return false;
        }
        if (napi_get_reference_value(env, iter->second->handlerRef, &handler) != napi_ok || handler == nullptr) {
            LOG_ERROR("Get napi reference value failed.");
            return false;
        }
    }
    SendToJs(env, handler, response);
    LOG_INFO("DispatchToCallback exit.");
    return true;
}

void DataFabricAddressNapi::SetInt32Value(napi_env env, const std::string &fieldStr,
    int32_t intValue, napi_value &result)
{
    napi_handle_scope scope = nullptr;
    napi_status status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok || scope == nullptr) {
        LOG_ERROR("Failed to open scope, error: %{public}d", status);
        return;
    }
    napi_value value = nullptr;
    status = napi_create_int32(env, intValue, &value);
    if (status != napi_ok) {
        LOG_ERROR("Failed to create int32 value for field: %{public}s, error: %{public}d",
            fieldStr.c_str(), status);
        napi_close_handle_scope(env, scope);
        return;
    }
    if (napi_set_named_property(env, result, fieldStr.c_str(), value) != napi_ok) {
        LOG_ERROR("Failed to set named property for field: %{public}s", fieldStr.c_str());
    }
    napi_close_handle_scope(env, scope);
}

void DataFabricAddressNapi::SetUtf8StringValue(napi_env env, const std::string &fieldStr,
    const std::string strValue, napi_value &result)
{
    napi_handle_scope scope = nullptr;
    napi_status status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok || scope == nullptr) {
        LOG_ERROR("Failed to open scope, error: %{public}d", status);
        return;
    }
    napi_value value = nullptr;
    status = napi_create_string_utf8(env, strValue.c_str(), NAPI_AUTO_LENGTH, &value);
    if (status != napi_ok) {
        LOG_ERROR("Failed to create UTF-8 string for field: %{public}s, error: %{public}d", fieldStr.c_str(), status);
        napi_close_handle_scope(env, scope);
        return;
    }
    if (napi_set_named_property(env, result, fieldStr.c_str(), value) != napi_ok) {
        LOG_ERROR("Failed to set named property for field: %{public}s", fieldStr.c_str());
    }
    napi_close_handle_scope(env, scope);
}

void DataFabricAddressListener::OnDataFabricAddressChanged(const DataProcessingResponse& response)
{
    LOG_INFO("NAPI callback enter, code:%{public}d, result:%{public}s", static_cast<int32_t>(response.code),
        response.result.c_str());
    napi_env env = env_;
    DataFabricAddressParams params = inputParams_;
    auto task = [env, params, response]() {
        LOG_INFO("NAPI asyn task enter.");
        napi_handle_scope scope = nullptr;
        napi_status status = napi_open_handle_scope(env, &scope);
        if (status != napi_ok || scope == nullptr) {
            LOG_ERROR("Failed to open scope, error: %{public}d", status);
            return;
        }
        auto instance = DataFabricAddressNapi::TryGetExistingInstance(env);
        if (instance == nullptr) {
            LOG_ERROR("Get napi instance failed.");
            napi_close_handle_scope(env, scope);
            return;
        }
        instance->DispatchToCallback(env, params, response);
        napi_close_handle_scope(env, scope);
    };
    if (napi_ok != napi_send_event(env, task, napi_eprio_immediate, "DataFabricAddressChanged")) {
        LOG_ERROR("Failed to send napi event.");
        return;
    }
    LOG_INFO("NAPI callback exit");
}
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
} // End of namespace NativePreferences
} // End of namespace OHOS
