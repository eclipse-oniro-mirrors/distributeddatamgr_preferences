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

#include "data_fabric_address_client.h"

#include "data_fabric_address_callback.h"
#include "data_fabric_address_errors.h"
#include "data_fabric_address_proxy.h"
#include "ikvstore_data_service.h"
#include "iservice_registry.h"
#include "log_print.h"
#include "system_ability_definition.h"

#undef LOG_TAG
#define LOG_TAG "DataFabricAddressClient"

namespace OHOS {
namespace NativePreferences {

constexpr int32_t LOAD_SA_TIMEOUT_MS = 2000;

DataFabricAddressClient::DataFabricAddressClient()
{
}

DataFabricAddressClient::~DataFabricAddressClient()
{
    if (proxy_ != nullptr) {
        auto remoteObject = proxy_->AsObject();
        if (remoteObject != nullptr) {
            remoteObject->RemoveDeathRecipient(deathRecipient_);
        }
    }
}

bool DataFabricAddressClient::Connect()
{
    LOG_INFO("Client connect enter.");
    if (connectState_.load() == ConnectState::CONNECTED) {
        LOG_INFO("proxy has been created");
        return true;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (connectState_.load() == ConnectState::CONNECTED) {
        LOG_INFO("proxy has been created in lock.");
        return true;
    }

    bool connectResult = ConnectProxy();
    connectState_.store(connectResult ? ConnectState::CONNECTED : ConnectState::DISCONNECTED);
    LOG_INFO("Connect exit.");
    return connectResult;
}

bool DataFabricAddressClient::ConnectProxy()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        LOG_ERROR("GetSystemAbilityManager failed");
        return false;
    }

    sptr<IRemoteObject> remote = sam->CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    if (remote == nullptr || remote->IsObjectDead()) {
        LOG_WARN("Check system ability failed, the result is null or dead, preparing to reload.");
        remote = sam->LoadSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, LOAD_SA_TIMEOUT_MS);
        if (remote == nullptr || remote->IsObjectDead()) {
            LOG_ERROR("Reload system ability failed.");
            return false;
        }
    }

    sptr<DistributedKv::IKvStoreDataService> ability = iface_cast<DistributedKv::IKvStoreDataService>(remote);
    if (ability == nullptr) {
        LOG_ERROR("Create service ability failed.");
        return false;
    }

    deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new ServiceDeathRecipient());
    if (deathRecipient_ == nullptr) {
        LOG_ERROR("Create service death recipient failed.");
        return false;
    }

    if (remote->IsProxyObject() && (!remote->AddDeathRecipient(deathRecipient_))) {
        LOG_ERROR("Add death recipient failed.");
        return false;
    }

    auto service = ability->GetFeatureInterface("data_fabric_address");
    if (service == nullptr) {
        LOG_ERROR("Get data fabric address service object failed.");
        return false;
    }

    proxy_ = new (std::nothrow) DataFabricAddressProxy(service);
    if (proxy_ == nullptr) {
        LOG_ERROR("Get data fabric address service proxy failed.");
        return false;
    }
    LOG_INFO("ConnectProxy exit.");
    return true;
}

int32_t DataFabricAddressClient::Subscribe(const DataFabricAddressParams& inputParams,
    std::shared_ptr<IDataFabricAddressListener> listener)
{
    LOG_INFO("Client subscribe enter.");
    if (!Connect()) {
        LOG_ERROR("Client subscribe failed, because connect service error.");
        return INTERNAL_EXCEPTION;
    }
    auto callback = sptr<DataFabricAddressCallback>(new DataFabricAddressCallback(listener));
    if (inputParams.locationInfo.actionType == ActionType::SUBSCRIPTION) {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        clientCbMap_.emplace(inputParams, callback);
    }
    LOG_INFO("Before proxy subscribe.");
    int32_t ret = proxy_->Subscribe(inputParams, callback);
    if (ret != RUN_OK && inputParams.locationInfo.actionType == ActionType::SUBSCRIPTION) {
        LOG_ERROR("Proxy subscribe failed, result=%{public}d", ret);
        std::lock_guard<std::mutex> lock(callbackMutex_);
        clientCbMap_.erase(inputParams);
    }
    LOG_INFO("Client subscribe exit.");
    return ret;
}

int32_t DataFabricAddressClient::Unsubscribe(const DataFabricAddressParams& inputParams)
{
    LOG_INFO("Client Unsubscribe enter.");
    if (!Connect()) {
        LOG_ERROR("Client unsubscribe failed, because connect service error.");
        return INTERNAL_EXCEPTION;
    }
    LOG_INFO("Before proxy unsubscribe.");
    int32_t ret = proxy_->Unsubscribe(inputParams);
    if (ret == RUN_OK) {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        auto iter = clientCbMap_.find(inputParams);
        if (iter != clientCbMap_.end()) {
            clientCbMap_.erase(iter);
        }
    }
    LOG_INFO("Client unsubscribe exit.");
    return ret;
}

void DataFabricAddressClient::ResetProxy(const wptr<IRemoteObject>& remote)
{
    LOG_INFO("Client ResetProxy enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (remote == nullptr || proxy_ == nullptr) {
        LOG_WARN("ResetProxy input remote is null or the proxy_ is null.");
        return;
    }
    auto remoteObject = proxy_->AsObject();
    if (remoteObject == nullptr || remoteObject != remote.promote()) {
        LOG_WARN("ResetProxy the remoteObject is null or the remoteObject not equal to the input remote.");
        return;
    }
    remoteObject->RemoveDeathRecipient(deathRecipient_);
    proxy_ = nullptr;
    connectState_.store(ConnectState::DISCONNECTED);
    LOG_INFO("subscription info exists on the client, start subscribe SA status.");
    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        LOG_ERROR("Get system ability manager failed.");
        return;
    }
    SAStatusCallback_ = new SAStatusChange();
    sam->SubscribeSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, SAStatusCallback_);
    LOG_INFO("Client ResetProxy exit.");
}

void DataFabricAddressClient::ServiceDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    LOG_INFO("Client OnRemoteDied enter.");
    DataFabricAddressClient::GetInstance().ResetProxy(remote);
}

void DataFabricAddressClient::SAStatusChange::OnAddSystemAbility(int32_t systemAbilityId,
    const std::string& deviceId)
{
    LOG_INFO("SA: %{public}d loaded.", systemAbilityId);
    if (DataFabricAddressClient::GetInstance().SAStatusCallback_ == nullptr) {
        LOG_ERROR("OnAddSystemAbility SAStatusCallback_ is null.");
        return;
    }
    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        LOG_ERROR("OnAddSystemAbility sam is null.");
        return;
    }
    sam->UnSubscribeSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID,
        DataFabricAddressClient::GetInstance().SAStatusCallback_);
    LOG_INFO("Client OnAddSystemAbility exit.");
}

void DataFabricAddressClient::SAStatusChange::OnRemoveSystemAbility(int32_t systemAbilityId,
    const std::string& deviceId)
{
    LOG_INFO("SA: %{public}d removed.", systemAbilityId);
}

void DataFabricAddressCallback::OnDataFabricAddressChanged(const DataProcessingResponse& response)
{
    LOG_INFO("Client OnDataFabricAddressChanged code:%{public}d, result:%{public}s",
        static_cast<int32_t>(response.code), response.result.c_str());
    if (dataFabricAddressListener_ == nullptr) {
        LOG_ERROR("OnDataFabricAddressChanged dataFabricAddressListener_is null.");
        return;
    }
    dataFabricAddressListener_->OnDataFabricAddressChanged(response);
    LOG_INFO("Client OnDataFabricAddressChanged exit.");
}
} // End of namespace NativePreferences
} // End of namespace OHOS
