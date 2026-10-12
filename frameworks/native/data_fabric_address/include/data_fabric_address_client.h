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

#ifndef DATA_FABRIC_ADDRESS_CLIENT_H
#define DATA_FABRIC_ADDRESS_CLIENT_H

#include <atomic>
#include <mutex>

#include "data_fabric_address_callback.h"
#include "data_fabric_address_callback_stub.h"
#include "i_data_fabric_address.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "preferences_visibility.h"
#include "singleton.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace NativePreferences {

class IDataFabricAddressListener {
public:
    IDataFabricAddressListener() = default;
    virtual ~IDataFabricAddressListener() = default;
    virtual void OnDataFabricAddressChanged(const DataProcessingResponse& response);
};

class DataFabricAddressCallback : public DataFabricAddressListenerCallbackStub {
public:
    DataFabricAddressCallback(std::shared_ptr<IDataFabricAddressListener> listener)
    {
        dataFabricAddressListener_ = listener;
    }
    virtual ~DataFabricAddressCallback() = default;
private:
    std::shared_ptr<IDataFabricAddressListener> dataFabricAddressListener_;
    void OnDataFabricAddressChanged(const DataProcessingResponse& response);
};

class PREF_API_EXPORT DataFabricAddressClient final : public DelayedRefSingleton<DataFabricAddressClient> {
    DECLARE_DELAYED_REF_SINGLETON(DataFabricAddressClient)
public:
    DISALLOW_COPY_AND_MOVE(DataFabricAddressClient);
    int32_t Subscribe(const DataFabricAddressParams& inputParams,
        std::shared_ptr<IDataFabricAddressListener> listener);
    int32_t Unsubscribe(const DataFabricAddressParams& inputParams);
private:
    class ServiceDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        ServiceDeathRecipient() = default;
        ~ServiceDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote);
    private:
        DISALLOW_COPY_AND_MOVE(ServiceDeathRecipient);
    };
    class SAStatusChange : public SystemAbilityStatusChangeStub {
    public:
        void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
        void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    };
    bool Connect();
    bool ConnectProxy();
    void ResetProxy(const wptr<IRemoteObject>& remote);

    enum class ConnectState : int32_t {
        DISCONNECTED = 0,
        CONNECTED = 1,
    };

    std::mutex mutex_;
    std::mutex callbackMutex_;
    std::atomic<ConnectState> connectState_ { ConnectState::DISCONNECTED };
    sptr<IDataFabricAddressService> proxy_ { nullptr };
    sptr<SAStatusChange> SAStatusCallback_ { nullptr };
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ { nullptr };
    std::map<DataFabricAddressParams, sptr<DataFabricAddressCallback>> clientCbMap_;
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_CLIENT_H
