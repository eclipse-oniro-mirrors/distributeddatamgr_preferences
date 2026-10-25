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

#ifndef DATA_FABRIC_ADDRESS_ANI_H
#define DATA_FABRIC_ADDRESS_ANI_H

#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
#include "data_fabric_address_client.h"

#include <iterator>
#include <map>
#include <optional>
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE

#include "data_fabric_address_types.h"
#include "log_print.h"
#include "ohos.data.dataFabricAddress.proj.hpp"
#include "ohos.data.dataFabricAddress.impl.hpp"
#include "taihe/runtime.hpp"

namespace OHOS {
namespace DataFabricAddress {
using namespace taihe;
using namespace PreferencesEtsKit;
// 与 js 交互类型
using JsBusinessScenario = ohos::data::dataFabricAddress::BusinessScenario;
using JsActionType = ohos::data::dataFabricAddress::ActionType;
using JsLabelName = ohos::data::dataFabricAddress::LabelName;
using JsCoordinateSystemName = ohos::data::dataFabricAddress::CoordinateSystemName;
using JsStatusCode = ohos::data::dataFabricAddress::StatusCode;
using JsLocationPoint = ohos::data::dataFabricAddress::LocationPoint;
using JsLocationInfo = ohos::data::dataFabricAddress::LocationInfo;
using JsReferenceLocationInfo = ohos::data::dataFabricAddress::ReferenceLocationInfo;
using JsDataFabricAddressParams = ohos::data::dataFabricAddress::DataFabricAddressParams;
using JsDataProcessingResponse = ohos::data::dataFabricAddress::DataProcessingResponse;
using callbackType = callback<void(JsDataProcessingResponse const&)>;

// 内部使用类型
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

struct CallbackObject {
    CallbackObject(callbackType cb, ani_ref ref) : callback(cb), ref(ref) {}
    ~CallbackObject()
    {
        auto *env = get_env();
        if (env == nullptr) {
            LOG_ERROR("Get taihe env failed when destroy CallbackObject");
            return;
        }
        if (env->GlobalReference_Delete(ref) != ANI_OK) {
            LOG_ERROR("Failed to delete global reference.");
        }
    }

    callbackType callback;
    ani_ref ref;
};

class GlobalRefGuard {
    ani_env *env_ = nullptr;
    ani_ref ref_ = nullptr;

public:
    GlobalRefGuard(ani_env *env, ani_object obj) : env_(env)
    {
        if (!env_) {
            return;
        }
        if (ANI_OK != env_->GlobalReference_Create(obj, &ref_)) {
            ref_ = nullptr;
        }
    }

    explicit operator bool() const
    {
        return ref_ != nullptr;
    }

    ani_ref get() const
    {
        return ref_;
    }

    ~GlobalRefGuard()
    {
        if (env_ && ref_) {
            if (env_->GlobalReference_Delete(ref_) != ANI_OK) {
                LOG_ERROR("Failed to delete global reference.");
            }
        }
    }

    GlobalRefGuard(const GlobalRefGuard &) = delete;
    GlobalRefGuard &operator=(const GlobalRefGuard &) = delete;
};

class DataFabricAddressListener : public IDataFabricAddressListener {
public:
    explicit DataFabricAddressListener(const DataFabricAddressParams& params) : inputParams_(params) {}
    virtual ~DataFabricAddressListener() = default;
    void OnDataFabricAddressChanged(const DataProcessingResponse& response);
private:
    DataFabricAddressParams inputParams_;
};
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE

class DataFabricAddressAni {
public:
    DataFabricAddressAni() = default;
    ~DataFabricAddressAni() = default;
    void OnDataFabricAddress(const JsDataFabricAddressParams &jsParams,
        callback_view<void(JsDataProcessingResponse const&)> callback, uintptr_t opq);
    void OffDataFabricAddress(const JsDataFabricAddressParams &jsParams, optional_view<uintptr_t> opq);
#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
    std::optional<callbackType> GetCallback(const DataFabricAddressParams &inputParams);
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
    static std::shared_ptr<DataFabricAddressAni> GetInstance();

private:
    void ThrowErr(int32_t errorCode, const std::string& printMsg);

#ifdef ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
    bool CheckInputParams(const JsDataFabricAddressParams &jsParams, DataFabricAddressParams &inputParams);
    bool ReadReferenceLocationInfo(const JsReferenceLocationInfo &jsLocationInfo, ReferenceLocationInfo& locationInfo);
    bool ReadReferencePointInfo(const JsLocationInfo &jsLocationPointInfo, LocationInfo& locationPointInfo);
    bool ReadLocationPoint(const JsLocationPoint& jsLocationPoint, LocationPoint& locationPoint);
    bool RollbackCallback(const DataFabricAddressParams &inputParams);
    bool RemoveCallback(const DataFabricAddressParams &inputParams, optional_view<uintptr_t> opq);

    std::recursive_mutex mutex_;
    std::map<DataFabricAddressParams, std::shared_ptr<CallbackObject>> jsCbMap_;
#endif // ARKDATA_DATA_FABRIC_ADDRESS_ENABLE
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_ANI_H
