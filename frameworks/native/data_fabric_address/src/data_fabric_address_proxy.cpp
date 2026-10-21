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

#include "data_fabric_address_proxy.h"

#include "data_fabric_address_errors.h"
#include "log_print.h"

#undef LOG_TAG
#define LOG_TAG "DataFabricAddressErrors"

namespace OHOS {
namespace NativePreferences {

int32_t DataFabricAddressProxy::Subscribe(const DataFabricAddressParams& inputParams,
    sptr<IDataFabricAddressCallback> callback)
{
    LOG_INFO("Subscribe enter.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataFabricAddressProxy::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed.");
        return INTERNAL_EXCEPTION;
    }
    if (!MarshallingDataFabricAddressParams(inputParams, data)) {
        LOG_ERROR("Write params failed.");
        return INTERNAL_EXCEPTION;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        LOG_ERROR("Write remote object failed.");
        return INTERNAL_EXCEPTION;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERROR("Construct remote object failed.");
        return INTERNAL_EXCEPTION;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(
        static_cast<int>(IDataFabricAddressService::RemoteOperation::SUBSCRIBE), data, reply, option);
    if (ret != RUN_OK) {
        LOG_ERROR("Send ipc request faild, ret=%{public}d", ret);
        return INTERNAL_EXCEPTION;
    }
    int32_t result;
    if (!reply.ReadInt32(result)) {
        LOG_ERROR("Read ipc request result code failed.");
        return INTERNAL_EXCEPTION;
    }
    LOG_INFO("Subscribe exit, result code=%{public}d.", result);
    return result;
}

int32_t DataFabricAddressProxy::Unsubscribe(const DataFabricAddressParams& inputParams)
{
    LOG_INFO("Unsubscribe enter.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataFabricAddressProxy::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed.");
        return INTERNAL_EXCEPTION;
    }
    if (!MarshallingDataFabricAddressParams(inputParams, data)) {
        LOG_ERROR("Write params failed.");
        return INTERNAL_EXCEPTION;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERROR("Construct remote object failed.");
        return INTERNAL_EXCEPTION;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = remote->SendRequest(
        static_cast<int>(IDataFabricAddressService::RemoteOperation::UNSUBSCRIBE), data, reply, option);
    if (ret != RUN_OK) {
        LOG_ERROR("Send ipc request faild, ret=%{public}d", ret);
        return INTERNAL_EXCEPTION;
    }
    int32_t result;
    if (!reply.ReadInt32(result)) {
        LOG_ERROR("Read ipc request result code failed.");
        return INTERNAL_EXCEPTION;
    }
    LOG_INFO("Unsubscribe exit, result code=%{public}d.", result);
    return result;
}

bool DataFabricAddressProxy::MarshallingDataFabricAddressParams(const DataFabricAddressParams& inputParams,
    MessageParcel &parcel)
{
    if (!parcel.WriteInt32(static_cast<int32_t>(inputParams.scenarioType)) ||
        !parcel.WriteInt32(static_cast<int32_t>(inputParams.locationInfo.actionType))) {
        LOG_ERROR("Write scenario type or action type failed.");
        return false;
    }
    size_t pointsCount = inputParams.locationInfo.points.size();
    if (!parcel.WriteInt32(static_cast<int32_t>(pointsCount))) {
        LOG_ERROR("Write reference points count failed.");
        return false;
    }
    for (size_t i = 0; i < pointsCount; ++i) {
        if (!parcel.WriteInt32(static_cast<int32_t>(inputParams.locationInfo.points[i].labelType)) ||
            !parcel.WriteInt32(static_cast<int32_t>(inputParams.locationInfo.points[i].coordinateSystemType)) ||
            !parcel.WriteDouble(inputParams.locationInfo.points[i].locationPoint.latitude) ||
            !parcel.WriteDouble(inputParams.locationInfo.points[i].locationPoint.longitude)) {
            LOG_ERROR("Write reference point label type, coordinate system type, latitude or longitude failed.");
            return false;
        }
    }
    return true;
}
} // End of namespace NativePreferences
} // End of namespace OHOS
