/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "system_ability_definition.h"
#include "data_fabric_address_client.h"
#include "data_fabric_address_errors.h"
#include "data_fabric_address_mock.h"
#include "system_ability_manager_mock.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::NativePreferences;

namespace {
using ::testing::_;
using ::testing::An;
using ::testing::NiceMock;
using ::testing::Return;

sptr<DistributedKv::MockIKvStoreDataService> g_mockKvService;

sptr<IRemoteBroker> MockKvStoreDataServiceCreator(const sptr<IRemoteObject>& object)
{
    (void)object;
    return g_mockKvService;
}

struct KvStoreDataServiceRegistrar {
    KvStoreDataServiceRegistrar()
    {
        static BrokerDelegatorBase delegator;
        BrokerRegistration::Get().Register(DistributedKv::MockIKvStoreDataService::GetDescriptor(),
            MockKvStoreDataServiceCreator, &delegator);
    }
};
static KvStoreDataServiceRegistrar g_kvStoreDataServiceRegistrar;

class DataFabricAddressClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;

    void ExpectSuccessConnect(const sptr<MockRemoteObject>& remote);
    static DataFabricAddressParams CreateParams(const BusinessScenario scenario, const ActionType action,
        const std::vector<LocationInfo>& points);

    std::shared_ptr<NiceMock<SystemAbilityMock>> sam_;
    sptr<NiceMock<SystemAbilityManagerMock>> samgr_;
    sptr<MockRemoteObject> featureRemote_;
    std::shared_ptr<MockDataFabricAddressListener> listener_;
};

void DataFabricAddressClientTest::SetUpTestCase(void)
{
}

void DataFabricAddressClientTest::TearDownTestCase(void)
{
}

void DataFabricAddressClientTest::SetUp(void)
{
    sam_ = std::make_shared<NiceMock<SystemAbilityMock>>();
    ISystemAbilityBase::sab = sam_;
    samgr_ = new NiceMock<SystemAbilityManagerMock>();
    featureRemote_ = new MockRemoteObject();
    featureRemote_->isProxy_ = true;
    featureRemote_->sendRequestResult_ = 0;
    featureRemote_->replyResult_ = RUN_OK;
    listener_ = std::make_shared<MockDataFabricAddressListener>();
    ON_CALL(*sam_, GetSystemAbilityManager()).WillByDefault(Return(samgr_));
    ON_CALL(*samgr_, CheckSystemAbility(_)).WillByDefault(Return(sptr<IRemoteObject>()));
    ON_CALL(*samgr_, LoadSystemAbility(_, An<int32_t>())).WillByDefault(Return(sptr<IRemoteObject>()));
    ON_CALL(*samgr_, SubscribeSystemAbility(_, _)).WillByDefault(Return(0));
    ON_CALL(*samgr_, UnSubscribeSystemAbility(_, _)).WillByDefault(Return(0));
    g_mockKvService = new DistributedKv::MockIKvStoreDataService(new MockRemoteObject());
    g_mockKvService->SetFeatureRemote(featureRemote_);
}

void DataFabricAddressClientTest::TearDown(void)
{
    DataFabricAddressClient& client = DataFabricAddressClient::GetInstance();
    client.proxy_ = nullptr;
    client.SAStatusCallback_ = nullptr;
    client.deathRecipient_ = nullptr;
    client.clientCbMap_.clear();
    client.connectState_.store(DataFabricAddressClient::ConnectState::DISCONNECTED);
    ISystemAbilityBase::sab = nullptr;
    sam_ = nullptr;
    samgr_ = nullptr;
    featureRemote_ = nullptr;
    listener_ = nullptr;
    g_mockKvService = nullptr;
}

void DataFabricAddressClientTest::ExpectSuccessConnect(const sptr<MockRemoteObject>& remote)
{
    remote->isProxy_ = true;
    remote->isDead_ = false;
    remote->addDeathRecipientResult_ = true;
    EXPECT_CALL(*samgr_, CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID)).WillOnce(Return(remote));
}

DataFabricAddressParams DataFabricAddressClientTest::CreateParams(const BusinessScenario scenario,
    const ActionType action, const std::vector<LocationInfo>& points)
{
    DataFabricAddressParams params;
    params.scenarioType = scenario;
    params.locationInfo.actionType = action;
    params.locationInfo.points = points;
    return params;
}

static LocationInfo CreateLocationInfo(LabelType label, CoordinateSystemType coord, double latitude, double longitude)
{
    LocationInfo locationInfo;
    locationInfo.labelType = label;
    locationInfo.coordinateSystemType = coord;
    locationInfo.locationPoint.latitude = latitude;
    locationInfo.locationPoint.longitude = longitude;
    return locationInfo;
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_001
 * @tc.desc: testcase of DataFabricAddressClient::Subscribe when Connect succeeds and proxy subscribe succeeds
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_001, TestSize.Level0)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ExpectSuccessConnect(remote);
    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 39.9, 116.4) });
    int32_t ret = DataFabricAddressClient::GetInstance().Subscribe(params, listener_);

    DataFabricAddressClient& client = DataFabricAddressClient::GetInstance();
    EXPECT_EQ(ret, RUN_OK);
    EXPECT_TRUE(client.proxy_ != nullptr);
    EXPECT_EQ(client.clientCbMap_.size(), 1u);
    EXPECT_TRUE(remote->deathRecipient_ != nullptr);
    EXPECT_EQ(client.deathRecipient_, remote->deathRecipient_);
    EXPECT_FALSE(remote->removedDeathRecipient_);
    EXPECT_EQ(featureRemote_->requestCode_,
        static_cast<uint32_t>(IDataFabricAddressService::RemoteOperation::SUBSCRIBE));
    EXPECT_TRUE(featureRemote_->remoteObject_ != nullptr);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_002
 * @tc.desc: testcase of DataFabricAddressClient::Subscribe when proxy is already created
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_002, TestSize.Level0)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ExpectSuccessConnect(remote);
    const DataFabricAddressParams first = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    ASSERT_EQ(DataFabricAddressClient::GetInstance().Subscribe(first, listener_), RUN_OK);

    auto& client = DataFabricAddressClient::GetInstance();
    ASSERT_TRUE(client.proxy_ != nullptr);
    const DataFabricAddressParams second = CreateParams(BusinessScenario::OTHERS, ActionType::UPDATE,
        { CreateLocationInfo(LabelType::COMPANY, CoordinateSystemType::GCJ02, 3.0, 4.0) });
    EXPECT_EQ(client.Subscribe(second, listener_), RUN_OK);
    EXPECT_EQ(client.clientCbMap_.size(), 1u);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_003
 * @tc.desc: testcase of Connect after reload when CheckSystemAbility returns a dead object
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_003, TestSize.Level0)
{
    sptr<MockRemoteObject> deadRemote = new MockRemoteObject();
    deadRemote->isProxy_ = true;
    deadRemote->isDead_ = true;
    sptr<MockRemoteObject> aliveRemote = new MockRemoteObject();
    aliveRemote->isProxy_ = true;
    aliveRemote->isDead_ = false;
    EXPECT_CALL(*samgr_, CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID)).WillOnce(Return(deadRemote));
    EXPECT_CALL(*samgr_, LoadSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, An<int32_t>()))
        .WillOnce(Return(aliveRemote));

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    int32_t ret = DataFabricAddressClient::GetInstance().Subscribe(params, listener_);

    EXPECT_EQ(ret, RUN_OK);
    auto& client = DataFabricAddressClient::GetInstance();
    EXPECT_TRUE(client.proxy_ != nullptr);
    EXPECT_TRUE(aliveRemote->deathRecipient_ != nullptr);
    EXPECT_EQ(client.deathRecipient_, aliveRemote->deathRecipient_);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_004
 * @tc.desc: testcase of Connect when CheckSystemAbility and reload both fail
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_004, TestSize.Level0)
{
    EXPECT_CALL(*samgr_, CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID))
        .WillOnce(Return(sptr<IRemoteObject>()));
    EXPECT_CALL(*samgr_, LoadSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, An<int32_t>()))
        .WillOnce(Return(sptr<IRemoteObject>()));

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    int32_t ret = DataFabricAddressClient::GetInstance().Subscribe(params, listener_);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
    EXPECT_TRUE(DataFabricAddressClient::GetInstance().proxy_ == nullptr);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_005
 * @tc.desc: testcase of Connect when reload returns a dead object
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_005, TestSize.Level0)
{
    sptr<MockRemoteObject> exceptRemote = new MockRemoteObject();
    exceptRemote->isProxy_ = true;
    exceptRemote->isDead_ = true;
    sptr<MockRemoteObject> reloadDeadRemote = new MockRemoteObject();
    reloadDeadRemote->isProxy_ = true;
    reloadDeadRemote->isDead_ = true;
    EXPECT_CALL(*samgr_, CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID))
        .WillOnce(Return(exceptRemote));
    EXPECT_CALL(*samgr_, LoadSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, An<int32_t>()))
        .WillOnce(Return(reloadDeadRemote));

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    int32_t ret = DataFabricAddressClient::GetInstance().Subscribe(params, listener_);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
    EXPECT_TRUE(DataFabricAddressClient::GetInstance().proxy_ == nullptr);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_006
 * @tc.desc: testcase of Connect when iface_cast returns null (remote is not a proxy and descriptor mismatched)
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_006, TestSize.Level0)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    remote->isProxy_ = false;
    remote->isDead_ = false;
    EXPECT_CALL(*samgr_, CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID)).WillOnce(Return(remote));

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    int32_t ret = DataFabricAddressClient::GetInstance().Subscribe(params, listener_);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
    EXPECT_TRUE(DataFabricAddressClient::GetInstance().proxy_ == nullptr);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_007
 * @tc.desc: testcase of Connect when GetSystemAbilityManager returns null
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_007, TestSize.Level0)
{
    ON_CALL(*sam_, GetSystemAbilityManager()).WillByDefault(Return(sptr<ISystemAbilityManager>()));

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    int32_t ret = DataFabricAddressClient::GetInstance().Subscribe(params, listener_);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
    EXPECT_TRUE(DataFabricAddressClient::GetInstance().proxy_ == nullptr);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_008
 * @tc.desc: testcase of Connect when GetFeatureInterface returns null
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_008, TestSize.Level0)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ExpectSuccessConnect(remote);
    g_mockKvService->SetFeatureRemote(nullptr);

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    int32_t ret = DataFabricAddressClient::GetInstance().Subscribe(params, listener_);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
    EXPECT_TRUE(DataFabricAddressClient::GetInstance().proxy_ == nullptr);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_009
 * @tc.desc: testcase of Connect when AddDeathRecipient fails
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_009, TestSize.Level0)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    remote->isProxy_ = true;
    remote->isDead_ = false;
    remote->addDeathRecipientResult_ = false;
    EXPECT_CALL(*samgr_, CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID)).WillOnce(Return(remote));

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    int32_t ret = DataFabricAddressClient::GetInstance().Subscribe(params, listener_);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
    EXPECT_TRUE(DataFabricAddressClient::GetInstance().proxy_ == nullptr);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_010
 * @tc.desc: testcase of DataFabricAddressClient::Unsubscribe success
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_010, TestSize.Level0)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ExpectSuccessConnect(remote);
    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    auto& client = DataFabricAddressClient::GetInstance();
    ASSERT_EQ(client.Subscribe(params, listener_), RUN_OK);
    ASSERT_EQ(client.clientCbMap_.size(), 1u);

    int32_t ret = client.Unsubscribe(params);

    EXPECT_EQ(ret, RUN_OK);
    EXPECT_EQ(client.clientCbMap_.size(), 0u);
    EXPECT_EQ(featureRemote_->requestCode_,
        static_cast<uint32_t>(IDataFabricAddressService::RemoteOperation::UNSUBSCRIBE));
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_011
 * @tc.desc: testcase of DataFabricAddressClient::Unsubscribe when the params is not subscribed
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_011, TestSize.Level0)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ExpectSuccessConnect(remote);
    const DataFabricAddressParams subscribed = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    auto& client = DataFabricAddressClient::GetInstance();
    ASSERT_EQ(client.Subscribe(subscribed, listener_), RUN_OK);
    ASSERT_EQ(client.clientCbMap_.size(), 1u);

    const DataFabricAddressParams notSubscribed = CreateParams(BusinessScenario::OTHERS, ActionType::UPDATE, {});
    int32_t ret = client.Unsubscribe(notSubscribed);

    EXPECT_EQ(ret, RUN_OK);
    EXPECT_EQ(client.clientCbMap_.size(), 1u);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_012
 * @tc.desc: testcase of DataFabricAddressClient::Unsubscribe when proxy unsubscribe fails
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_012, TestSize.Level0)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ExpectSuccessConnect(remote);
    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    auto& client = DataFabricAddressClient::GetInstance();
    ASSERT_EQ(client.Subscribe(params, listener_), RUN_OK);
    ASSERT_EQ(client.clientCbMap_.size(), 1u);

    featureRemote_->sendRequestResult_ = -1;
    int32_t ret = client.Unsubscribe(params);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
    EXPECT_EQ(client.clientCbMap_.size(), 1u);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_013
 * @tc.desc: testcase of DataFabricAddressClient::Subscribe when proxy subscribe fails
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_013, TestSize.Level0)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ExpectSuccessConnect(remote);
    featureRemote_->sendRequestResult_ = -1;

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    int32_t ret = DataFabricAddressClient::GetInstance().Subscribe(params, listener_);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
    EXPECT_EQ(DataFabricAddressClient::GetInstance().clientCbMap_.size(), 0u);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_014
 * @tc.desc: testcase of ResetProxy when the input remote is null
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_014, TestSize.Level0)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ExpectSuccessConnect(remote);
    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    auto& client = DataFabricAddressClient::GetInstance();
    ASSERT_EQ(client.Subscribe(params, listener_), RUN_OK);
    ASSERT_TRUE(client.proxy_ != nullptr);

    wptr<IRemoteObject> nullRemote;
    client.ResetProxy(nullRemote);

    EXPECT_TRUE(client.proxy_ != nullptr);
    EXPECT_FALSE(featureRemote_->removedDeathRecipient_);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_015
 * @tc.desc: testcase of ResetProxy when proxy_ is null
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_015, TestSize.Level0)
{
    auto& client = DataFabricAddressClient::GetInstance();
    ASSERT_TRUE(client.proxy_ == nullptr);

    wptr<IRemoteObject> remote(featureRemote_);
    client.ResetProxy(remote);

    EXPECT_TRUE(client.proxy_ == nullptr);
    EXPECT_FALSE(featureRemote_->removedDeathRecipient_);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_016
 * @tc.desc: testcase of ResetProxy when the remoteObject not equal to the input remote
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_016, TestSize.Level0)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ExpectSuccessConnect(remote);
    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    auto& client = DataFabricAddressClient::GetInstance();
    ASSERT_EQ(client.Subscribe(params, listener_), RUN_OK);
    ASSERT_TRUE(client.proxy_ != nullptr);

    client.ResetProxy(wptr<IRemoteObject>(remote));

    EXPECT_TRUE(client.proxy_ != nullptr);
    EXPECT_FALSE(featureRemote_->removedDeathRecipient_);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_017
 * @tc.desc: testcase of ResetProxy success when GetSystemAbilityManager returns null
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_017, TestSize.Level0)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ExpectSuccessConnect(remote);
    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    auto& client = DataFabricAddressClient::GetInstance();
    ASSERT_EQ(client.Subscribe(params, listener_), RUN_OK);
    ASSERT_TRUE(client.proxy_ != nullptr);

    ON_CALL(*sam_, GetSystemAbilityManager()).WillByDefault(Return(sptr<ISystemAbilityManager>()));
    client.ResetProxy(wptr<IRemoteObject>(featureRemote_));

    EXPECT_TRUE(client.proxy_ == nullptr);
    EXPECT_TRUE(featureRemote_->removedDeathRecipient_);
    EXPECT_TRUE(client.SAStatusCallback_ == nullptr);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_018
 * @tc.desc: testcase of ResetProxy success and subscribe SA status
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_018, TestSize.Level0)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ExpectSuccessConnect(remote);
    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    auto& client = DataFabricAddressClient::GetInstance();
    ASSERT_EQ(client.Subscribe(params, listener_), RUN_OK);
    ASSERT_TRUE(client.proxy_ != nullptr);

    EXPECT_CALL(*samgr_, SubscribeSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, _)).WillOnce(Return(0));
    client.ResetProxy(wptr<IRemoteObject>(featureRemote_));

    EXPECT_TRUE(client.proxy_ == nullptr);
    EXPECT_TRUE(featureRemote_->removedDeathRecipient_);
    EXPECT_TRUE(client.SAStatusCallback_ != nullptr);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_019
 * @tc.desc: testcase of ServiceDeathRecipient::OnRemoteDied
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_019, TestSize.Level0)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ExpectSuccessConnect(remote);
    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    auto& client = DataFabricAddressClient::GetInstance();
    ASSERT_EQ(client.Subscribe(params, listener_), RUN_OK);
    ASSERT_TRUE(client.proxy_ != nullptr);

    DataFabricAddressClient::ServiceDeathRecipient deathRecipient;
    deathRecipient.OnRemoteDied(wptr<IRemoteObject>(featureRemote_));

    EXPECT_TRUE(client.proxy_ == nullptr);
    EXPECT_TRUE(featureRemote_->removedDeathRecipient_);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_020
 * @tc.desc: testcase of SAStatusChange::OnAddSystemAbility when SAStatusCallback_ is null
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_020, TestSize.Level0)
{
    DataFabricAddressClient::SAStatusChange statusChange;
    EXPECT_TRUE(DataFabricAddressClient::GetInstance().SAStatusCallback_ == nullptr);

    statusChange.OnAddSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, "");

    DataFabricAddressClient& client = DataFabricAddressClient::GetInstance();
    EXPECT_TRUE(client.SAStatusCallback_ == nullptr);
    EXPECT_TRUE(client.proxy_ == nullptr);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_021
 * @tc.desc: testcase of SAStatusChange::OnAddSystemAbility when GetSystemAbilityManager returns null
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_021, TestSize.Level0)
{
    auto& client = DataFabricAddressClient::GetInstance();
    client.SAStatusCallback_ = new DataFabricAddressClient::SAStatusChange();
    EXPECT_CALL(*sam_, GetSystemAbilityManager()).WillOnce(Return(sptr<ISystemAbilityManager>()));

    DataFabricAddressClient::SAStatusChange statusChange;
    statusChange.OnAddSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, "");
    EXPECT_TRUE(client.SAStatusCallback_ != nullptr);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_022
 * @tc.desc: testcase of SAStatusChange::OnAddSystemAbility success
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_022, TestSize.Level0)
{
    sptr<MockRemoteObject> remote = new MockRemoteObject();
    ExpectSuccessConnect(remote);
    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    auto& client = DataFabricAddressClient::GetInstance();
    ASSERT_EQ(client.Subscribe(params, listener_), RUN_OK);
    ASSERT_TRUE(client.proxy_ != nullptr);

    client.ResetProxy(wptr<IRemoteObject>(featureRemote_));
    ASSERT_TRUE(client.SAStatusCallback_ != nullptr);

    EXPECT_CALL(*samgr_, UnSubscribeSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, _)).WillOnce(Return(0));
    DataFabricAddressClient::SAStatusChange statusChange;
    statusChange.OnAddSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, "");
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_023
 * @tc.desc: testcase of SAStatusChange::OnRemoveSystemAbility
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_023, TestSize.Level0)
{
    DataFabricAddressClient::SAStatusChange statusChange;
    statusChange.OnRemoveSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, "");

    auto& client = DataFabricAddressClient::GetInstance();
    EXPECT_TRUE(client.SAStatusCallback_ == nullptr);
    EXPECT_TRUE(client.proxy_ == nullptr);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_024
 * @tc.desc: testcase of DataFabricAddressClient destructor removes the death recipient
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_024, TestSize.Level0)
{
    sptr<MockRemoteObject> service = new MockRemoteObject();
    service->isProxy_ = true;

    DataFabricAddressClient* client = new DataFabricAddressClient();
    client->proxy_ = new DataFabricAddressProxy(service);
    client->deathRecipient_ = new DataFabricAddressClient::ServiceDeathRecipient();
    delete client;

    EXPECT_TRUE(service->removedDeathRecipient_);
}

/**
 * @tc.name: NativeDataFabricAddressClientTest_025
 * @tc.desc: testcase of DataFabricAddressClient destructor when proxy_ is null
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressClientTest, NativeDataFabricAddressClientTest_025, TestSize.Level0)
{
    DataFabricAddressClient* client = new DataFabricAddressClient();
    ASSERT_TRUE(client != nullptr);
    EXPECT_TRUE(client->proxy_ == nullptr);
    EXPECT_TRUE(client->clientCbMap_.empty());
    delete client;
}
} // namespace
