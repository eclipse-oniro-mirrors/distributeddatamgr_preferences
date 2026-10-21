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

#ifndef DATA_FABRIC_ADDRESS_MOCK_H
#define DATA_FABRIC_ADDRESS_MOCK_H

#include <vector>

#include "data_fabric_address_callback.h"
#include "data_fabric_address_client.h"
#include "data_fabric_address_proxy.h"
#include "data_fabric_address_types.h"
#include "iremote_object.h"
#include "message_option.h"
#include "message_parcel.h"

#ifdef DATA_FABRIC_ADDRESS_KVSTORE_MOCK_ENABLE
#include <string>

#include "ikvstore_data_service.h"
#include "iremote_broker.h"
#endif // DATA_FABRIC_ADDRESS_KVSTORE_MOCK_ENABLE

namespace OHOS {

#ifdef DATA_FABRIC_ADDRESS_KVSTORE_MOCK_ENABLE
namespace DistributedKv {

class MockIKvStoreDataService : public IKvStoreDataService {
public:
    explicit MockIKvStoreDataService(const sptr<IRemoteObject> &remote) : remote_(remote) {}
    ~MockIKvStoreDataService() override = default;

    sptr<IRemoteObject> GetFeatureInterface(const std::string &name) override
    {
        lastFeatureName_ = name;
        return featureRemote_;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return remote_;
    }

    void SetFeatureRemote(const sptr<IRemoteObject> &remote)
    {
        featureRemote_ = remote;
    }

    std::string lastFeatureName_;
    sptr<IRemoteObject> featureRemote_;
    sptr<IRemoteObject> remote_;
};
} // End of namespace NativePreferences
#endif // DATA_FABRIC_ADDRESS_KVSTORE_MOCK_ENABLE

namespace NativePreferences {

class MockDataFabricAddressListener : public IDataFabricAddressListener {
public:
    MockDataFabricAddressListener() = default;
    ~MockDataFabricAddressListener() override = default;

    void OnDataFabricAddressChanged(const DataProcessingResponse& response) override
    {
        lastResponse_ = response;
        ++changedCount_;
    }

    DataProcessingResponse lastResponse_;
    int changedCount_ = 0;
};

class FakeDataFabricAddressCallback : public IDataFabricAddressCallback {
public:
    FakeDataFabricAddressCallback() = default;
    ~FakeDataFabricAddressCallback() override = default;

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }

    void OnDataFabricAddressChanged(const DataProcessingResponse& response) override
    {
        (void)response;
    }
};

class MockRemoteObject : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject(u"OHOS.Test.DataFabricAddress.MockRemoteObject")
    {
    }

    ~MockRemoteObject() override = default;

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    bool IsProxyObject() const override
    {
        return isProxy_;
    }

    bool IsObjectDead() const override
    {
        return isDead_;
    }

    int SendRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override
    {
        (void)option;
        requestCode_ = code;
        data.ReadInterfaceToken();
        scenarioType_ = data.ReadInt32();
        actionType_ = data.ReadInt32();
        pointsCount_ = data.ReadInt32();
        points_.clear();
        for (int32_t i = 0; i < pointsCount_; ++i) {
            LocationInfo locationInfo;
            locationInfo.labelType = static_cast<LabelType>(data.ReadInt32());
            locationInfo.coordinateSystemType = static_cast<CoordinateSystemType>(data.ReadInt32());
            locationInfo.locationPoint.latitude = data.ReadDouble();
            locationInfo.locationPoint.longitude = data.ReadDouble();
            points_.push_back(locationInfo);
        }
        if (code == static_cast<uint32_t>(IDataFabricAddressService::RemoteOperation::SUBSCRIBE)) {
            remoteObject_ = data.ReadRemoteObject();
        }
        if (writeReplyResult_) {
            reply.WriteInt32(replyResult_);
        }
        return sendRequestResult_;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient>& recipient) override
    {
        deathRecipient_ = recipient;
        return addDeathRecipientResult_;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient>& recipient) override
    {
        if (recipient != nullptr) {
            removedDeathRecipient_ = true;
        }
        return true;
    }

    int Dump(int fd, const std::vector<std::u16string>& args) override
    {
        (void)fd;
        (void)args;
        return 0;
    }

    int32_t sendRequestResult_ = 0;
    int32_t replyResult_ = 0;
    bool writeReplyResult_ = true;
    bool isProxy_ = false;
    bool isDead_ = false;
    bool addDeathRecipientResult_ = true;
    bool removedDeathRecipient_ = false;
    uint32_t requestCode_ = 0;
    int32_t scenarioType_ = 0;
    int32_t actionType_ = 0;
    int32_t pointsCount_ = 0;
    std::vector<LocationInfo> points_;
    sptr<IRemoteObject> remoteObject_;
    sptr<DeathRecipient> deathRecipient_;
};

class TestDataFabricAddressCallback : public DataFabricAddressListenerCallbackStub {
public:
    TestDataFabricAddressCallback() = default;
    ~TestDataFabricAddressCallback() override = default;

    void OnDataFabricAddressChanged(const DataProcessingResponse& response) override
    {
        response_ = response;
        ++changedCount_;
    }

    DataProcessingResponse response_;
    int changedCount_ = 0;
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_MOCK_H
