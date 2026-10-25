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

#include "data_fabric_address_api_helper.h"
#include "data_fabric_address_errors.h"
#include "data_fabric_address_mock.h"
#include "data_fabric_address_types.h"
#include "message_parcel.h"

#include <gtest/gtest.h>

#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "log_print.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::NativePreferences;

namespace {
class DataFabricAddressTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DataFabricAddressTest::SetUpTestCase(void)
{
}

void DataFabricAddressTest::TearDownTestCase(void)
{
}

void DataFabricAddressTest::SetUp(void)
{
}

void DataFabricAddressTest::TearDown(void)
{
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

static DataFabricAddressParams CreateParams(BusinessScenario scenario, ActionType action,
    std::vector<LocationInfo> points)
{
    DataFabricAddressParams params;
    params.scenarioType = scenario;
    params.locationInfo.actionType = action;
    params.locationInfo.points = std::move(points);
    return params;
}

static void WriteInt32s(MessageParcel &parcel, const std::vector<int32_t> &values)
{
    for (int32_t value : values) {
        parcel.WriteInt32(value);
    }
}

/**
 * @tc.name: NativeDataFabricAddressTest_001
 * @tc.desc: testcase of IsValidIntEnumValue
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_001, TestSize.Level0)
{
    const int32_t minValue = static_cast<int32_t>(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE);
    const int32_t maxValue = static_cast<int32_t>(BusinessScenario::OTHERS);
    EXPECT_FALSE(DataFabricAddressApiHelper::IsValidIntEnumValue(minValue - 1, minValue, maxValue));
    EXPECT_FALSE(DataFabricAddressApiHelper::IsValidIntEnumValue(maxValue + 1, minValue, maxValue));
    EXPECT_TRUE(DataFabricAddressApiHelper::IsValidIntEnumValue(minValue, minValue, maxValue));
    EXPECT_TRUE(DataFabricAddressApiHelper::IsValidIntEnumValue(maxValue, minValue, maxValue));

    constexpr int32_t generalMinValue = 5;
    constexpr int32_t generalMaxValue = 10;
    EXPECT_FALSE(DataFabricAddressApiHelper::IsValidIntEnumValue(generalMinValue - 1, generalMinValue,
        generalMaxValue));
    EXPECT_TRUE(DataFabricAddressApiHelper::IsValidIntEnumValue((generalMinValue + generalMaxValue) / 2,
        generalMinValue, generalMaxValue));
    EXPECT_FALSE(DataFabricAddressApiHelper::IsValidIntEnumValue(generalMaxValue + 1, generalMinValue,
        generalMaxValue));
}

/**
 * @tc.name: NativeDataFabricAddressTest_002
 * @tc.desc: testcase of IsValidLatLng
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_002, TestSize.Level0)
{
    const double nan = std::numeric_limits<double>::quiet_NaN();
    EXPECT_FALSE(DataFabricAddressApiHelper::IsValidLatLng(nan, 0.0));
    EXPECT_FALSE(DataFabricAddressApiHelper::IsValidLatLng(0.0, nan));

    EXPECT_FALSE(DataFabricAddressApiHelper::IsValidLatLng(-90.1, 0.0));
    EXPECT_FALSE(DataFabricAddressApiHelper::IsValidLatLng(90.1, 0.0));
    EXPECT_FALSE(DataFabricAddressApiHelper::IsValidLatLng(0.0, -180.1));
    EXPECT_FALSE(DataFabricAddressApiHelper::IsValidLatLng(0.0, 180.1));

    EXPECT_TRUE(DataFabricAddressApiHelper::IsValidLatLng(-90.0, -180.0));
    EXPECT_TRUE(DataFabricAddressApiHelper::IsValidLatLng(0.0, 0.0));
    EXPECT_TRUE(DataFabricAddressApiHelper::IsValidLatLng(90.0, 180.0));
}

/**
 * @tc.name: NativeDataFabricAddressTest_003
 * @tc.desc: testcase of IsPointsCountExceeds
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_003, TestSize.Level0)
{
    EXPECT_FALSE(DataFabricAddressApiHelper::IsPointsCountExceeds(0));
    EXPECT_FALSE(DataFabricAddressApiHelper::IsPointsCountExceeds(1));
    EXPECT_FALSE(DataFabricAddressApiHelper::IsPointsCountExceeds(128));
    EXPECT_TRUE(DataFabricAddressApiHelper::IsPointsCountExceeds(129));
    EXPECT_TRUE(DataFabricAddressApiHelper::IsPointsCountExceeds(130));
}

/**
 * @tc.name: NativeDataFabricAddressTest_004
 * @tc.desc: testcase of IsStringLengthExceeds
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_004, TestSize.Level0)
{
    EXPECT_FALSE(DataFabricAddressApiHelper::IsStringLengthExceeds(0));
    EXPECT_FALSE(DataFabricAddressApiHelper::IsStringLengthExceeds(1));
    EXPECT_FALSE(DataFabricAddressApiHelper::IsStringLengthExceeds(128));
    EXPECT_TRUE(DataFabricAddressApiHelper::IsStringLengthExceeds(129));
    EXPECT_TRUE(DataFabricAddressApiHelper::IsStringLengthExceeds(130));
}

/**
 * @tc.name: NativeDataFabricAddressTest_005
 * @tc.desc: testcase of LabelNameToType and CoordinateSystemNameToType
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_005, TestSize.Level0)
{
    LabelType labelType = LabelType::HOME;
    EXPECT_FALSE(DataFabricAddressTypes::LabelNameToType("", labelType));
    EXPECT_FALSE(DataFabricAddressTypes::LabelNameToType("home", labelType));
    EXPECT_FALSE(DataFabricAddressTypes::LabelNameToType("INVALID", labelType));
    EXPECT_TRUE(DataFabricAddressTypes::LabelNameToType(HOME_LABEL_NAME, labelType));
    EXPECT_EQ(labelType, LabelType::HOME);
    EXPECT_TRUE(DataFabricAddressTypes::LabelNameToType(COMPANY_LABEL_NAME, labelType));
    EXPECT_EQ(labelType, LabelType::COMPANY);

    CoordinateSystemType coordType = CoordinateSystemType::WGS84;
    EXPECT_FALSE(DataFabricAddressTypes::CoordinateSystemNameToType("", coordType));
    EXPECT_FALSE(DataFabricAddressTypes::CoordinateSystemNameToType("wgs84", coordType));
    EXPECT_FALSE(DataFabricAddressTypes::CoordinateSystemNameToType("INVALID", coordType));
    EXPECT_TRUE(DataFabricAddressTypes::CoordinateSystemNameToType(WGS84_NAME, coordType));
    EXPECT_EQ(coordType, CoordinateSystemType::WGS84);
    EXPECT_TRUE(DataFabricAddressTypes::CoordinateSystemNameToType(GCJ02_NAME, coordType));
    EXPECT_EQ(coordType, CoordinateSystemType::GCJ02);
}

/**
 * @tc.name: NativeDataFabricAddressTest_006
 * @tc.desc: testcase of DataFabricAddressParams operator==
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_006, TestSize.Level0)
{
    const DataFabricAddressParams base = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    DataFabricAddressParams other = CreateParams(BusinessScenario::OTHERS, ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    EXPECT_FALSE(base == other);

    other = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE, ActionType::UPDATE,
        { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    EXPECT_FALSE(base == other);

    other = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE, ActionType::SUBSCRIPTION, {});
    EXPECT_FALSE(base == other);

    other = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE, ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::COMPANY, CoordinateSystemType::WGS84, 1.0, 2.0) });
    EXPECT_FALSE(base == other);

    other = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE, ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::GCJ02, 1.0, 2.0) });
    EXPECT_FALSE(base == other);

    other = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE, ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 3.0, 2.0) });
    EXPECT_FALSE(base == other);

    other = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE, ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 4.0) });
    EXPECT_FALSE(base == other);

    other = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE, ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    EXPECT_EQ(base, other);
}

/**
 * @tc.name: NativeDataFabricAddressTest_007
 * @tc.desc: testcase of DataFabricAddressParams operator<
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_007, TestSize.Level0)
{
    const DataFabricAddressParams lhs = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    DataFabricAddressParams rhs = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    EXPECT_FALSE(lhs < rhs);
    EXPECT_FALSE(rhs < lhs);

    rhs = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE, ActionType::UPDATE,
        { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    EXPECT_TRUE(lhs < rhs);
    EXPECT_FALSE(rhs < lhs);

    rhs = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE, ActionType::SUBSCRIPTION, {});
    EXPECT_FALSE(lhs < rhs);
    EXPECT_TRUE(rhs < lhs);

    rhs = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE, ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0),
            CreateLocationInfo(LabelType::COMPANY, CoordinateSystemType::WGS84, 1.0, 2.0) });
    EXPECT_TRUE(lhs < rhs);

    rhs = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE, ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::COMPANY, CoordinateSystemType::WGS84, 1.0, 2.0) });
    EXPECT_TRUE(lhs < rhs);

    rhs = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE, ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::GCJ02, 1.0, 2.0) });
    EXPECT_TRUE(lhs < rhs);

    rhs = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE, ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 0.5, 2.0) });
    EXPECT_FALSE(lhs < rhs);
    EXPECT_TRUE(rhs < lhs);

    rhs = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE, ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 1.5) });
    EXPECT_FALSE(lhs < rhs);
    EXPECT_TRUE(rhs < lhs);

    rhs = CreateParams(BusinessScenario::OTHERS, ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    EXPECT_TRUE(lhs < rhs);
}

/**
 * @tc.name: NativeDataFabricAddressTest_008
 * @tc.desc: testcase of GetErrMsg
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_008, TestSize.Level0)
{
    for (const auto& entry : ERROR_MESSAGES) {
        auto msg = DataFabricAddressErrors::GetErrMsg(entry.first);
        ASSERT_TRUE(msg.has_value());
        EXPECT_EQ(*msg, entry.second);
    }
    EXPECT_FALSE(DataFabricAddressErrors::GetErrMsg(RUN_OK).has_value());
    EXPECT_FALSE(DataFabricAddressErrors::GetErrMsg(12345678).has_value());
}

/**
 * @tc.name: NativeDataFabricAddressTest_009
 * @tc.desc: testcase of DataFabricAddressProxy::Subscribe
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_009, TestSize.Level0)
{
    sptr<MockRemoteObject> mockRemote = new MockRemoteObject();
    mockRemote->sendRequestResult_ = 0;
    mockRemote->replyResult_ = RUN_OK;
    DataFabricAddressProxy proxy(mockRemote);

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 39.9, 116.4) });
    sptr<IDataFabricAddressCallback> callback = new DataFabricAddressListenerCallbackStub();
    int32_t ret = proxy.Subscribe(params, callback);

    EXPECT_EQ(ret, RUN_OK);
    EXPECT_EQ(mockRemote->requestCode_,
        static_cast<uint32_t>(IDataFabricAddressService::RemoteOperation::SUBSCRIBE));
    EXPECT_EQ(mockRemote->scenarioType_, static_cast<int32_t>(params.scenarioType));
    EXPECT_EQ(mockRemote->actionType_, static_cast<int32_t>(params.locationInfo.actionType));
    EXPECT_EQ(mockRemote->pointsCount_, 1);
    ASSERT_EQ(mockRemote->points_.size(), 1);
    EXPECT_EQ(mockRemote->points_[0].labelType, LabelType::HOME);
    EXPECT_EQ(static_cast<int32_t>(mockRemote->points_[0].coordinateSystemType),
        static_cast<int32_t>(CoordinateSystemType::WGS84));
    EXPECT_DOUBLE_EQ(mockRemote->points_[0].locationPoint.latitude, 39.9);
    EXPECT_DOUBLE_EQ(mockRemote->points_[0].locationPoint.longitude, 116.4);
    EXPECT_TRUE(mockRemote->remoteObject_ != nullptr);
}

/**
 * @tc.name: NativeDataFabricAddressTest_010
 * @tc.desc: testcase of DataFabricAddressProxy::Subscribe when SendRequest failed
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_010, TestSize.Level0)
{
    sptr<MockRemoteObject> mockRemote = new MockRemoteObject();
    mockRemote->sendRequestResult_ = -1;
    mockRemote->replyResult_ = RUN_OK;
    DataFabricAddressProxy proxy(mockRemote);

    const DataFabricAddressParams params = CreateParams(BusinessScenario::OTHERS, ActionType::UPDATE, {});
    sptr<IDataFabricAddressCallback> callback = new DataFabricAddressListenerCallbackStub();
    int32_t ret = proxy.Subscribe(params, callback);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: NativeDataFabricAddressTest_011
 * @tc.desc: testcase of DataFabricAddressProxy::Unsubscribe
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_011, TestSize.Level0)
{
    sptr<MockRemoteObject> mockRemote = new MockRemoteObject();
    mockRemote->sendRequestResult_ = 0;
    mockRemote->replyResult_ = RUN_OK;
    DataFabricAddressProxy proxy(mockRemote);

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::COMPANY, CoordinateSystemType::GCJ02, 31.2, 121.5) });
    int32_t ret = proxy.Unsubscribe(params);

    EXPECT_EQ(ret, RUN_OK);
    EXPECT_EQ(mockRemote->requestCode_,
        static_cast<uint32_t>(IDataFabricAddressService::RemoteOperation::UNSUBSCRIBE));
    EXPECT_EQ(mockRemote->scenarioType_, static_cast<int32_t>(params.scenarioType));
    EXPECT_EQ(mockRemote->pointsCount_, 1);
    ASSERT_EQ(mockRemote->points_.size(), 1);
    EXPECT_EQ(mockRemote->points_[0].labelType, LabelType::COMPANY);
    EXPECT_EQ(static_cast<int32_t>(mockRemote->points_[0].coordinateSystemType),
        static_cast<int32_t>(CoordinateSystemType::GCJ02));
    EXPECT_DOUBLE_EQ(mockRemote->points_[0].locationPoint.latitude, 31.2);
    EXPECT_DOUBLE_EQ(mockRemote->points_[0].locationPoint.longitude, 121.5);
}

/**
 * @tc.name: NativeDataFabricAddressTest_012
 * @tc.desc: testcase of DataFabricAddressProxy::Unsubscribe when SendRequest failed
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_012, TestSize.Level0)
{
    sptr<MockRemoteObject> mockRemote = new MockRemoteObject();
    mockRemote->sendRequestResult_ = -1;
    mockRemote->replyResult_ = RUN_OK;
    DataFabricAddressProxy proxy(mockRemote);

    const DataFabricAddressParams params = CreateParams(BusinessScenario::OTHERS, ActionType::UPDATE, {});
    int32_t ret = proxy.Unsubscribe(params);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: NativeDataFabricAddressTest_013
 * @tc.desc: testcase of DataFabricAddressListenerCallbackStub OnRemoteRequest with matched code
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_013, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallback> callback = new TestDataFabricAddressCallback();

    MessageParcel data;
    EXPECT_TRUE(data.WriteInterfaceToken(TestDataFabricAddressCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(static_cast<int32_t>(StatusCode::SUCCESS)));
    EXPECT_TRUE(data.WriteString("changed result"));
    MessageParcel reply;
    MessageOption option;
    int ret = callback->OnRemoteRequest(
        static_cast<uint32_t>(IDataFabricAddressCallback::CMD_DATA_CHANGED), data, reply, option);

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(callback->changedCount_, 1);
    EXPECT_EQ(callback->response_.code, StatusCode::SUCCESS);
    EXPECT_EQ(callback->response_.result, "changed result");
}

/**
 * @tc.name: NativeDataFabricAddressTest_014
 * @tc.desc: testcase of DataFabricAddressListenerCallbackStub OnRemoteRequest with mismatched descriptor
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_014, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallback> callback = new TestDataFabricAddressCallback();

    MessageParcel data;
    EXPECT_TRUE(data.WriteInterfaceToken(u"OHOS.Wrong.Descriptor"));
    MessageParcel reply;
    MessageOption option;
    int ret = callback->OnRemoteRequest(
        static_cast<uint32_t>(IDataFabricAddressCallback::CMD_DATA_CHANGED), data, reply, option);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
    EXPECT_EQ(callback->changedCount_, 0);
}

/**
 * @tc.name: NativeDataFabricAddressTest_015
 * @tc.desc: testcase of DataFabricAddressListenerCallbackStub OnRemoteRequest with unknown code
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_015, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallback> callback = new TestDataFabricAddressCallback();

    MessageParcel data;
    EXPECT_TRUE(data.WriteInterfaceToken(TestDataFabricAddressCallback::GetDescriptor()));
    MessageParcel reply;
    MessageOption option;
    int ret = callback->OnRemoteRequest(9999, data, reply, option);

    EXPECT_NE(ret, 0);
    EXPECT_EQ(callback->changedCount_, 0);
}

/**
 * @tc.name: NativeDataFabricAddressTest_016
 * @tc.desc: testcase of DataFabricAddressCallback OnDataFabricAddressChanged
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_016, TestSize.Level0)
{
    std::shared_ptr<MockDataFabricAddressListener> listener = std::make_shared<MockDataFabricAddressListener>();
    sptr<DataFabricAddressCallback> callback = new DataFabricAddressCallback(listener);

    MessageParcel data;
    EXPECT_TRUE(data.WriteInterfaceToken(DataFabricAddressCallback::GetDescriptor()));
    EXPECT_TRUE(data.WriteInt32(static_cast<int32_t>(StatusCode::FAILURE)));
    EXPECT_TRUE(data.WriteString("client result"));
    MessageParcel reply;
    MessageOption option;
    int ret = callback->OnRemoteRequest(
        static_cast<uint32_t>(IDataFabricAddressCallback::CMD_DATA_CHANGED), data, reply, option);

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(listener->changedCount_, 1);
    EXPECT_EQ(listener->lastResponse_.code, StatusCode::FAILURE);
    EXPECT_EQ(listener->lastResponse_.result, "client result");

    sptr<DataFabricAddressCallback> nullListenerCallback = new DataFabricAddressCallback(nullptr);
    MessageParcel data2;
    EXPECT_TRUE(data2.WriteInterfaceToken(DataFabricAddressCallback::GetDescriptor()));
    EXPECT_TRUE(data2.WriteInt32(static_cast<int32_t>(StatusCode::SUCCESS)));
    EXPECT_TRUE(data2.WriteString("result"));
    MessageParcel reply2;
    int ret2 = nullListenerCallback->OnRemoteRequest(
        static_cast<uint32_t>(IDataFabricAddressCallback::CMD_DATA_CHANGED), data2, reply2, option);
    EXPECT_EQ(ret2, 0);
    EXPECT_EQ(listener->changedCount_, 1);
}

/**
 * @tc.name: NativeDataFabricAddressTest_017
 * @tc.desc: testcase of DataFabricAddressProxy::Subscribe when Remote() is null
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_017, TestSize.Level0)
{
    sptr<DataFabricAddressProxy> nullProxy = new DataFabricAddressProxy(nullptr);

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    sptr<IDataFabricAddressCallback> callback = new DataFabricAddressListenerCallbackStub();
    int32_t ret = nullProxy->Subscribe(params, callback);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: NativeDataFabricAddressTest_018
 * @tc.desc: testcase of DataFabricAddressProxy::Subscribe when WriteRemoteObject fails
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_018, TestSize.Level0)
{
    sptr<MockRemoteObject> mockRemote = new MockRemoteObject();
    mockRemote->sendRequestResult_ = 0;
    mockRemote->replyResult_ = RUN_OK;
    DataFabricAddressProxy proxy(mockRemote);

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    sptr<IDataFabricAddressCallback> nullAsObjectCallback = new FakeDataFabricAddressCallback();
    int32_t ret = proxy.Subscribe(params, nullAsObjectCallback);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: NativeDataFabricAddressTest_019
 * @tc.desc: testcase of DataFabricAddressProxy::Subscribe when reply ReadInt32 fails
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_019, TestSize.Level0)
{
    sptr<MockRemoteObject> mockRemote = new MockRemoteObject();
    mockRemote->sendRequestResult_ = 0;
    mockRemote->writeReplyResult_ = false;
    DataFabricAddressProxy proxy(mockRemote);

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    sptr<IDataFabricAddressCallback> callback = new DataFabricAddressListenerCallbackStub();
    int32_t ret = proxy.Subscribe(params, callback);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: NativeDataFabricAddressTest_020
 * @tc.desc: testcase of DataFabricAddressProxy::Unsubscribe when Remote() is null
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_020, TestSize.Level0)
{
    sptr<DataFabricAddressProxy> nullProxy = new DataFabricAddressProxy(nullptr);

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    int32_t ret = nullProxy->Unsubscribe(params);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: NativeDataFabricAddressTest_021
 * @tc.desc: testcase of DataFabricAddressProxy::Unsubscribe when reply ReadInt32 fails
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_021, TestSize.Level0)
{
    sptr<MockRemoteObject> mockRemote = new MockRemoteObject();
    mockRemote->sendRequestResult_ = 0;
    mockRemote->writeReplyResult_ = false;
    DataFabricAddressProxy proxy(mockRemote);

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION, { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 1.0, 2.0) });
    int32_t ret = proxy.Unsubscribe(params);

    EXPECT_EQ(ret, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: NativeDataFabricAddressTest_022
 * @tc.desc: testcase of DataFabricAddressProxy::Subscribe with multiple reference points
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_022, TestSize.Level0)
{
    sptr<MockRemoteObject> mockRemote = new MockRemoteObject();
    mockRemote->sendRequestResult_ = 0;
    mockRemote->replyResult_ = RUN_OK;
    DataFabricAddressProxy proxy(mockRemote);

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 39.9, 116.4),
            CreateLocationInfo(LabelType::COMPANY, CoordinateSystemType::GCJ02, 31.2, 121.5) });
    sptr<IDataFabricAddressCallback> callback = new DataFabricAddressListenerCallbackStub();
    int32_t ret = proxy.Subscribe(params, callback);

    EXPECT_EQ(ret, RUN_OK);
    EXPECT_EQ(mockRemote->pointsCount_, 2);
    ASSERT_EQ(mockRemote->points_.size(), 2);
    EXPECT_EQ(mockRemote->points_[0].labelType, LabelType::HOME);
    EXPECT_EQ(mockRemote->points_[0].coordinateSystemType, CoordinateSystemType::WGS84);
    EXPECT_DOUBLE_EQ(mockRemote->points_[0].locationPoint.latitude, 39.9);
    EXPECT_DOUBLE_EQ(mockRemote->points_[0].locationPoint.longitude, 116.4);
    EXPECT_EQ(mockRemote->points_[1].labelType, LabelType::COMPANY);
    EXPECT_EQ(mockRemote->points_[1].coordinateSystemType, CoordinateSystemType::GCJ02);
    EXPECT_DOUBLE_EQ(mockRemote->points_[1].locationPoint.latitude, 31.2);
    EXPECT_DOUBLE_EQ(mockRemote->points_[1].locationPoint.longitude, 121.5);
}

/**
 * @tc.name: NativeDataFabricAddressTest_023
 * @tc.desc: testcase of DataFabricAddressProxy::Unsubscribe with multiple reference points
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_023, TestSize.Level0)
{
    sptr<MockRemoteObject> mockRemote = new MockRemoteObject();
    mockRemote->sendRequestResult_ = 0;
    mockRemote->replyResult_ = RUN_OK;
    DataFabricAddressProxy proxy(mockRemote);

    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 39.9, 116.4),
            CreateLocationInfo(LabelType::COMPANY, CoordinateSystemType::GCJ02, 31.2, 121.5) });
    int32_t ret = proxy.Unsubscribe(params);

    EXPECT_EQ(ret, RUN_OK);
    EXPECT_EQ(mockRemote->pointsCount_, 2);
    ASSERT_EQ(mockRemote->points_.size(), 2);
    EXPECT_EQ(mockRemote->points_[0].labelType, LabelType::HOME);
    EXPECT_EQ(mockRemote->points_[0].coordinateSystemType, CoordinateSystemType::WGS84);
    EXPECT_EQ(mockRemote->points_[1].labelType, LabelType::COMPANY);
    EXPECT_EQ(mockRemote->points_[1].coordinateSystemType, CoordinateSystemType::GCJ02);
    EXPECT_DOUBLE_EQ(mockRemote->points_[0].locationPoint.latitude, 39.9);
    EXPECT_DOUBLE_EQ(mockRemote->points_[0].locationPoint.longitude, 116.4);
    EXPECT_DOUBLE_EQ(mockRemote->points_[1].locationPoint.latitude, 31.2);
    EXPECT_DOUBLE_EQ(mockRemote->points_[1].locationPoint.longitude, 121.5);
}

/**
 * @tc.name: NativeDataFabricAddressTest_024
 * @tc.desc: testcase of DataFabricAddressParams Marshal and Unmarshal round trip with multiple reference points
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_024, TestSize.Level0)
{
    const DataFabricAddressParams params = CreateParams(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE,
        ActionType::SUBSCRIPTION,
        { CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 39.9, 116.4),
            CreateLocationInfo(LabelType::COMPANY, CoordinateSystemType::GCJ02, 31.2, 121.5) });

    MessageParcel parcel;
    ASSERT_TRUE(params.Marshal(parcel));
    DataFabricAddressParams unmarshaled;
    ASSERT_TRUE(unmarshaled.Unmarshal(parcel));

    EXPECT_EQ(unmarshaled.scenarioType, params.scenarioType);
    EXPECT_EQ(unmarshaled.locationInfo.actionType, params.locationInfo.actionType);
    EXPECT_EQ(unmarshaled.locationInfo.points.size(), params.locationInfo.points.size());
    EXPECT_TRUE(unmarshaled == params);
}

/**
 * @tc.name: NativeDataFabricAddressTest_025
 * @tc.desc: testcase of DataFabricAddressParams Unmarshal fails when the parcel is truncated
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_025, TestSize.Level0)
{
    MessageParcel parcel;
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE)));
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(ActionType::SUBSCRIPTION)));
    ASSERT_TRUE(parcel.WriteInt32(1)); // pointsCount, but no point data follows

    DataFabricAddressParams inputParams;
    EXPECT_FALSE(inputParams.Unmarshal(parcel));
}

/**
 * @tc.name: NativeDataFabricAddressTest_026
 * @tc.desc: testcase of LocationPoint::Unmarshal fails when the parcel is truncated
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_026, TestSize.Level0)
{
    MessageParcel emptyParcel;
    LocationPoint point;
    EXPECT_FALSE(point.Unmarshal(emptyParcel));

    MessageParcel missingLongitude;
    ASSERT_TRUE(missingLongitude.WriteDouble(39.9));
    EXPECT_FALSE(point.Unmarshal(missingLongitude));
}

/**
 * @tc.name: NativeDataFabricAddressTest_027
 * @tc.desc: testcase of LocationInfo::Unmarshal fails when the parcel is truncated
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_027, TestSize.Level0)
{
    MessageParcel emptyParcel;
    LocationInfo info;
    EXPECT_FALSE(info.Unmarshal(emptyParcel));

    MessageParcel missingCoord;
    WriteInt32s(missingCoord, { static_cast<int32_t>(LabelType::HOME) });
    EXPECT_FALSE(info.Unmarshal(missingCoord));

    MessageParcel missingPoint;
    WriteInt32s(missingPoint, { static_cast<int32_t>(LabelType::HOME),
        static_cast<int32_t>(CoordinateSystemType::WGS84) });
    EXPECT_FALSE(info.Unmarshal(missingPoint));
}

/**
 * @tc.name: NativeDataFabricAddressTest_028
 * @tc.desc: testcase of ReferenceLocationInfo::Unmarshal succeeds with zero reference points
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_028, TestSize.Level0)
{
    MessageParcel parcel;
    WriteInt32s(parcel, { static_cast<int32_t>(ActionType::SUBSCRIPTION), 0 });

    ReferenceLocationInfo referenceInfo;
    ASSERT_TRUE(referenceInfo.Unmarshal(parcel));
    EXPECT_EQ(referenceInfo.actionType, ActionType::SUBSCRIPTION);
    EXPECT_TRUE(referenceInfo.points.empty());
}

/**
 * @tc.name: NativeDataFabricAddressTest_029
 * @tc.desc: testcase of ReferenceLocationInfo::Unmarshal fails when the parcel is truncated
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_029, TestSize.Level0)
{
    MessageParcel emptyParcel;
    ReferenceLocationInfo referenceInfo;
    EXPECT_FALSE(referenceInfo.Unmarshal(emptyParcel));

    MessageParcel missingCount;
    WriteInt32s(missingCount, { static_cast<int32_t>(ActionType::SUBSCRIPTION) });
    EXPECT_FALSE(referenceInfo.Unmarshal(missingCount));

    MessageParcel missingFirstPoint;
    WriteInt32s(missingFirstPoint, { static_cast<int32_t>(ActionType::SUBSCRIPTION), 1 });
    EXPECT_FALSE(referenceInfo.Unmarshal(missingFirstPoint));

    MessageParcel missingSecondPoint;
    WriteInt32s(missingSecondPoint, { static_cast<int32_t>(ActionType::SUBSCRIPTION), 2 });
    CreateLocationInfo(LabelType::HOME, CoordinateSystemType::WGS84, 39.9, 116.4).Marshal(missingSecondPoint);
    EXPECT_FALSE(referenceInfo.Unmarshal(missingSecondPoint));
}

/**
 * @tc.name: NativeDataFabricAddressTest_030
 * @tc.desc: testcase of DataFabricAddressParams::Unmarshal fails when the parcel is truncated
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressTest, NativeDataFabricAddressTest_030, TestSize.Level0)
{
    MessageParcel emptyParcel;
    DataFabricAddressParams inputParams;
    EXPECT_FALSE(inputParams.Unmarshal(emptyParcel));

    MessageParcel missingLocation;
    WriteInt32s(missingLocation, { static_cast<int32_t>(BusinessScenario::SCENARIO_NAVIGATION_COMMUTE) });
    EXPECT_FALSE(inputParams.Unmarshal(missingLocation));
}
} // namespace
