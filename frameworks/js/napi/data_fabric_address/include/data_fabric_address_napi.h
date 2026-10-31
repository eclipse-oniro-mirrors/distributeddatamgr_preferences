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

#ifndef DATA_FABRIC_ADDRESS_NAPI_H
#define DATA_FABRIC_ADDRESS_NAPI_H

#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
#include <map>
#include <vector>

#include "data_fabric_address_client.h"
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE

#include "data_fabric_address_types.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "log_print.h"

namespace OHOS {
namespace DataFabricAddress {
using namespace PreferencesJsKit;
using BusinessScenario = NativePreferences::BusinessScenario;
using ActionType = NativePreferences::ActionType;
using LabelType = NativePreferences::LabelType;
using CoordinateSystemType = NativePreferences::CoordinateSystemType;
using StatusCode = NativePreferences::StatusCode;

#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
using LocationPoint = NativePreferences::LocationPoint;
using LocationInfo = NativePreferences::LocationInfo;
using ReferenceLocationInfo = NativePreferences::ReferenceLocationInfo;
using DataFabricAddressParams = NativePreferences::DataFabricAddressParams;
using DataProcessingResponse = NativePreferences::DataProcessingResponse;
using IDataFabricAddressListener = NativePreferences::IDataFabricAddressListener;
using DataFabricAddressClient = NativePreferences::DataFabricAddressClient;

struct DataFabricAddressListenerNapi {
    napi_env env { nullptr };
    napi_ref handlerRef { nullptr };
    ~DataFabricAddressListenerNapi()
    {
        if (env != nullptr && handlerRef != nullptr) {
            napi_status status = napi_delete_reference(env, handlerRef);
            if (status != napi_ok) {
                LOG_ERROR("napi_delete_reference failed in DataFabricAddressListenerNapi destroyed");
                return;
            }
            handlerRef = nullptr;
        }
    }
};

class DataFabricAddressListener : public IDataFabricAddressListener {
public:
    explicit DataFabricAddressListener(napi_env env, const DataFabricAddressParams& params)
        : env_(env), inputParams_(params) {}
    ~DataFabricAddressListener() override = default;
    void OnDataFabricAddressChanged(const DataProcessingResponse& response) override;
private:
    napi_env env_;
    DataFabricAddressParams inputParams_;
};
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE

class DataFabricAddressNapi {
public:
    explicit DataFabricAddressNapi() = default;
    ~DataFabricAddressNapi() = default;

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value OnDataFabricAddress(napi_env env, napi_callback_info info);
    static napi_value OffDataFabricAddress(napi_env env, napi_callback_info info);
#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
    static std::shared_ptr<DataFabricAddressNapi> TryGetExistingInstance(napi_env env);
    bool DispatchToCallback(napi_env env, const DataFabricAddressParams& params,
        const DataProcessingResponse& response);
    void SendToJs(napi_env env, napi_value handler, const DataProcessingResponse& response);
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE

private:
    static void DefineBusinessScenario(napi_env env, napi_value exports);
    static void DefineActionType(napi_env env, napi_value exports);
    static void DefineLabelName(napi_env env, napi_value exports);
    static void DefineCoordinateSystemName(napi_env env, napi_value exports);
    static void DefineStatusCode(napi_env env, napi_value exports);
    static void SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue);
    static void SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName);
    static void SetStringProperty(napi_env env, napi_value targetObj, const std::string &value, const char *propName);
    static void ThrowErr(napi_env env, int32_t errorCode, const std::string& printMsg);
    static napi_value CreateNapiError(napi_env env, int32_t errorCode, const std::string& errorMsg);
#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
    struct InstanceHolder {
        std::shared_ptr<DataFabricAddressNapi> sp;
    };
    static bool ValidateArgsType(napi_env env, napi_value *args, size_t argc,
        const std::vector<std::string> &expectedTypes);
    static bool CheckInputParams(napi_env env, napi_value jsParams, DataFabricAddressParams& inputParams);
    static bool ReadReferenceLocationInfo(napi_env env, napi_value jsParams, ReferenceLocationInfo& locationInfo);
    static bool ReadReferencePoints(napi_env env, napi_value jsLocationInfo, std::vector<LocationInfo>& points);
    static bool ReadReferencePointInfo(napi_env env, napi_value jsLocationInfo, LocationInfo& locationPointInfo);
    static bool ReadLocationPoint(napi_env env, napi_value jsParams, LocationPoint& locationPoint);
    static bool ReadIntValueFromJs(napi_env env, napi_value jsParams, const std::string& paramKey, int32_t& value);
    static bool ReadDoubleValueFromJs(napi_env env, napi_value jsParams, const std::string& paramKey, double& value);
    static bool ReadStringValueFromJs(napi_env env, napi_value jsParams, const std::string& paramKey,
        std::string& value);
    static bool DoSubscribe(napi_env env, napi_value callback, const DataFabricAddressParams& inputParams);
    static bool DoUnsubscribe(napi_env env, napi_value callback, const DataFabricAddressParams& inputParams);
    static std::shared_ptr<DataFabricAddressNapi> GetOrCreateInstance(napi_env env, napi_value wrapTarget);
    static bool CallNapiWrap(napi_env env, napi_value wrapTarget, InstanceHolder *holder);
    static void RollbackSaveInstances(napi_env env, const std::shared_ptr<DataFabricAddressNapi> &sp);

    bool AddCallback(napi_env env, napi_value refHandler, const DataFabricAddressParams& inputParams);
    bool RollbackCallback(napi_env env, const DataFabricAddressParams& inputParams);
    bool RemoveCallback(napi_env env, napi_value refHandler, const DataFabricAddressParams& inputParams);
    bool HasCallback(const DataFabricAddressParams& inputParams);
    bool IsSameValue(napi_env env, napi_value lhs, napi_value rhs);
    void SetInt32Value(napi_env env, const std::string &fieldStr, int32_t intValue, napi_value &result);
    void SetUtf8StringValue(napi_env env, const std::string &fieldStr, const std::string strValue, napi_value &result);

    static std::mutex g_instancesMutex;
    static std::unordered_map<napi_env, std::weak_ptr<DataFabricAddressNapi>> g_napiInstances;
    std::mutex mutex_;
    std::map<DataFabricAddressParams, std::shared_ptr<DataFabricAddressListenerNapi>> jsCbMap_;
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_NAPI_H
