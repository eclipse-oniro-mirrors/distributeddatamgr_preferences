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

#include "data_fabric_address_ani.h"

#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
#include "data_fabric_address_api_helper.h"
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
#include "data_fabric_address_errors.h"

#undef LOG_TAG
#define LOG_TAG "DataFabricAddressAni"

namespace OHOS {
namespace DataFabricAddress {

std::shared_ptr<DataFabricAddressAni> DataFabricAddressAni::GetInstance()
{
    static std::once_flag flag;
    static std::shared_ptr<DataFabricAddressAni> instance_;

    std::call_once(flag, []() {
        instance_ = std::make_shared<DataFabricAddressAni>();
    });
    return instance_;
}

void DataFabricAddressAni::OnDataFabricAddress(const JsDataFabricAddressParams &jsParams,
    callback_view<void(JsDataProcessingResponse const&)> callback, uintptr_t opq)
{
    LOG_INFO("OnDataFabricAddress enter.");
#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
    DataFabricAddressParams inputParams;
    if (!CheckInputParams(jsParams, inputParams)) {
        ThrowErr(NativePreferences::PARAMETER_EXCEPTION, "Check inputParams failed.");
        return;
    }
    if (inputParams.locationInfo.actionType == ActionType::SUBSCRIPTION) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto iter = jsCbMap_.find(inputParams);
        if (iter != jsCbMap_.end()) {
            ThrowErr(NativePreferences::SUBSCRIBE_EXCEPTION, "Subscribe callback already registered.");
            return;
        }
        ani_object callbackObj = reinterpret_cast<ani_object>(opq);
        ani_ref callbackRef;
        ani_env *env = get_env();
        if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
            ThrowErr(NativePreferences::SUBSCRIBE_EXCEPTION, "Create global reference failed.");
            return;
        }
        jsCbMap_.emplace(inputParams, std::make_shared<CallbackObject>(callback, callbackRef));
    }
    LOG_INFO("Subscribe add callback success.");

    auto listener = std::make_shared<DataFabricAddressListener>(inputParams);
    int32_t result = DataFabricAddressClient::GetInstance().Subscribe(inputParams, listener);
    if (result != NativePreferences::RUN_OK) {
        if (!RollbackCallback(inputParams)) {
            ThrowErr(NativePreferences::SUBSCRIBE_EXCEPTION, "Rollback callback from cache failed.");
            return;
        }
        ThrowErr(result, "Subscribe service failed.");
        return;
    }
    LOG_INFO("OnDataFabricAddress exit.");
#else
    ThrowErr(NativePreferences::DEVICE_EXCEPTION, "Device not supported the interface OnDataFabricAddress.");
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
}

void DataFabricAddressAni::OffDataFabricAddress(const JsDataFabricAddressParams &jsParams,
    optional_view<uintptr_t> opq)
{
    LOG_INFO("OffDataFabricAddress enter.");
#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
    DataFabricAddressParams inputParams;
    if (!CheckInputParams(jsParams, inputParams)) {
        ThrowErr(NativePreferences::PARAMETER_EXCEPTION, "Check inputParams failed.");
        return;
    }
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto iter = jsCbMap_.find(inputParams);
        if (iter == jsCbMap_.end()) {
            ThrowErr(NativePreferences::UNSUBSCRIBE_EXCEPTION, "The inputParams not found in the jsCbMap_.");
            return;
        }
    }
    LOG_INFO("Unsubscribe service is ready to run.");
    int32_t result = DataFabricAddressClient::GetInstance().Unsubscribe(inputParams);
    if (result != NativePreferences::RUN_OK) {
        ThrowErr(result, "Unsubscribe service failed.");
        return;
    }
    LOG_INFO("Unsubscribe service success.");
    if (!RemoveCallback(inputParams, opq)) {
        ThrowErr(NativePreferences::UNSUBSCRIBE_EXCEPTION, "Remove callback from cache failed.");
        return;
    }
    LOG_INFO("OffDataFabricAddress exit.");
#else
    ThrowErr(NativePreferences::DEVICE_EXCEPTION, "Device not supported the interface OffDataFabricAddress.");
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
}

void DataFabricAddressAni::ThrowErr(int32_t errorCode, const std::string& printMsg)
{
    LOG_ERROR("Business error, error code=%{public}d, error message=%{public}s", errorCode, printMsg.c_str());
    std::optional<std::string> msg = NativePreferences::DataFabricAddressErrors::GetErrMsg(errorCode);
    if (!msg) {
        LOG_ERROR("The error code:%{public}d is invalid, use default internal code.", errorCode);
        errorCode = NativePreferences::INTERNAL_EXCEPTION;
        msg = "Internal error in the API.";
    }
    taihe::set_business_error(errorCode, msg.value());
}

#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
bool DataFabricAddressAni::CheckInputParams(const JsDataFabricAddressParams &jsParams,
    DataFabricAddressParams &inputParams)
{
    // 校验并获取 scenarioType
    int32_t scenarioType = static_cast<int32_t>(jsParams.scenarioType);
    if (!NativePreferences::DataFabricAddressApiHelper::IsValidIntEnumValue(scenarioType,
        static_cast<int32_t>(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE),
        static_cast<int32_t>(BusinessScenario::OTHERS))) {
        LOG_ERROR("The scenario type is out of range for enum 'BusinessScenario'.");
        return false;
    }
    inputParams.scenarioType = static_cast<BusinessScenario>(scenarioType);
    // 获取并校验参考坐标信息
    if (!ReadReferenceLocationInfo(jsParams.locationInfo, inputParams.locationInfo)) {
        LOG_ERROR("Get reference location info failed.");
        return false;
    }
    return true;
}

bool DataFabricAddressAni::ReadReferenceLocationInfo(const JsReferenceLocationInfo &jsLocationInfo,
    ReferenceLocationInfo& locationInfo)
{
    int32_t actionValue = static_cast<int32_t>(jsLocationInfo.actionType);
    if (!NativePreferences::DataFabricAddressApiHelper::IsValidIntEnumValue(actionValue,
        static_cast<int32_t>(ActionType::SUBSCRIPTION), static_cast<int32_t>(ActionType::UPDATE))) {
        LOG_ERROR("The action type is out of range for enum 'ActionType'.");
        return false;
    }
    locationInfo.actionType = static_cast<ActionType>(actionValue);

    uint32_t pointCount = jsLocationInfo.points.size();
    if (NativePreferences::DataFabricAddressApiHelper::IsPointsCountExceeds(pointCount)) {
        LOG_ERROR("The reference points count %{public}d exceeds max count.", pointCount);
        return false;
    }
    // 遍历参考点信息
    for (uint32_t i = 0; i < pointCount; i++) {
        JsLocationInfo jsLocationPointInfo = jsLocationInfo.points[i];
        LocationInfo locationPointInfo;
        if (!ReadReferencePointInfo(jsLocationPointInfo, locationPointInfo)) {
            LOG_ERROR("Read index %{public}d reference point failed.", i);
            return false;
        }
        locationInfo.points.push_back(locationPointInfo);
    }
    return true;
}

bool DataFabricAddressAni::ReadReferencePointInfo(const JsLocationInfo &jsLocationPointInfo,
    LocationInfo& locationPointInfo)
{
    std::string labelName = static_cast<std::string>(jsLocationPointInfo.label);
    if (!NativePreferences::DataFabricAddressTypes::LabelNameToType(labelName, locationPointInfo.labelType)) {
        LOG_ERROR("The label name is out of range for enum 'LabelName'.");
        return false;
    }
    std::string coordinateSystemName = static_cast<std::string>(jsLocationPointInfo.coordinateSystemName);
    if (!NativePreferences::DataFabricAddressTypes::CoordinateSystemNameToType(coordinateSystemName,
        locationPointInfo.coordinateSystemType)) {
        LOG_ERROR("The coordinate system name is out of range for enum 'CoordinateSystemName'.");
        return false;
    }
    if (!ReadLocationPoint(jsLocationPointInfo.locationPoint, locationPointInfo.locationPoint)) {
        LOG_ERROR("Get location point failed.");
        return false;
    }
    return true;
}

bool DataFabricAddressAni::ReadLocationPoint(const  JsLocationPoint& jsLocationPoint,
    LocationPoint& locationPoint)
{
    double latitude = jsLocationPoint.latitude;
    double longitude = jsLocationPoint.longitude;
    if (!NativePreferences::DataFabricAddressApiHelper::IsValidLatLng(latitude, longitude)) {
        LOG_ERROR("Check the input latitude=%{public}.6f or longitude=%{public}.6f failed.", latitude, longitude);
        return false;
    }
    locationPoint.latitude = latitude;
    locationPoint.longitude = longitude;
    return true;
}

bool DataFabricAddressAni::RollbackCallback(const DataFabricAddressParams &inputParams)
{
    LOG_INFO("RollbackCallback enter.");
    if (inputParams.locationInfo.actionType == ActionType::UPDATE) {
        LOG_ERROR("The update action do not need to rollback callback.");
        return true;
    }

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto iter = jsCbMap_.find(inputParams);
    if (iter == jsCbMap_.end()) {
        LOG_ERROR("The inputParams not found in the jsCbMap_.");
        return false;
    }
    jsCbMap_.erase(iter);
    LOG_INFO("RollbackCallback exit.");
    return true;
}

bool DataFabricAddressAni::RemoveCallback(const DataFabricAddressParams &inputParams, optional_view<uintptr_t> opq)
{
    LOG_INFO("RemoveCallback enter.");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto iter = jsCbMap_.find(inputParams);
    if (iter == jsCbMap_.end()) {
        LOG_ERROR("The inputParams not found in the jsCbMap_.");
        return false;
    }
    if (!opq.has_value()) {
        LOG_INFO("The input callback is null, remove cache callback.");
        jsCbMap_.erase(iter);
        return true;
    }
    auto env = get_env();
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return false;
    }
    GlobalRefGuard guard(env, reinterpret_cast<ani_object>(opq.value()));
    if (!guard) {
        LOG_ERROR("GlobalRefGuard is false!");
        return false;
    }
    ani_boolean isEqual = false;
    if (ANI_OK != env->Reference_StrictEquals(guard.get(), iter->second->ref, &isEqual)) {
        LOG_ERROR("Failed to call Reference_StrictEquals.");
        return false;
    }
    if (!isEqual) {
        LOG_ERROR("The input callback is not equal with cache callback.");
        return false;
    }
    jsCbMap_.erase(iter);
    LOG_INFO("RemoveCallback exit.");
    return true;
}

std::optional<callbackType> DataFabricAddressAni::GetCallback(const DataFabricAddressParams &inputParams)
{
    LOG_INFO("GetCallback enter.");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto iter = jsCbMap_.find(inputParams);
    if (iter == jsCbMap_.end()) {
        LOG_ERROR("The inputParams not found in the jsCbMap_.");
        return std::nullopt;
    }
    LOG_INFO("GetCallback exit.");
    return iter->second->callback;
}

void DataFabricAddressListener::OnDataFabricAddressChanged(const DataProcessingResponse& response)
{
    LOG_INFO("ANI callback enter, code:%{public}d, result:%{public}s", static_cast<int32_t>(response.code),
        response.result.c_str());
    auto callback = DataFabricAddressAni::GetInstance()->GetCallback(inputParams_);
    if (!callback.has_value()) {
        LOG_ERROR("Get callback failed.");
        return;
    }
    auto &func = callback.value();
    JsDataProcessingResponse rsp = {
        .code = JsStatusCode::from_value(response.code),
        .result = response.result
    };
    func(rsp);
    LOG_INFO("API callback exit.");
}
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
} // End of namespace NativePreferences
} // End of namespace OHOS