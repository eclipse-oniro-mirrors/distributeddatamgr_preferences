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

#include "data_fabric_address_callback_stub.h"

#include "data_fabric_address_errors.h"
#include "log_print.h"
#include "message_parcel.h"
#include "string_ex.h"

#undef LOG_TAG
#define LOG_TAG "DataFabricAddressListenerCallbackStub"

namespace OHOS {
namespace NativePreferences {

int DataFabricAddressListenerCallbackStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    LOG_INFO("DataFabricAddressListenerCallbackStub OnRemoteRequest enter");
    std::u16string localDescriptor = DataFabricAddressListenerCallbackStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    LOG_INFO("OnRemoteRequest code:%{public}u, localDescriptor:%{public}s, remoteDescriptor:%{public}s",
        code, Str16ToStr8(localDescriptor).c_str(), Str16ToStr8(remoteDescriptor).c_str());
    if (localDescriptor != remoteDescriptor) {
        LOG_ERROR("DataFabricAddressListenerCallbackStub OnRemoteRequest failed, descriptor is not matched");
        return INTERNAL_EXCEPTION;
    }

    switch (code) {
        case static_cast<int>(IDataFabricAddressCallback::CMD_DATA_CHANGED): {
            return OnDataFabricAddressChangedStub(data);
        }
        default: {
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

int32_t DataFabricAddressListenerCallbackStub::OnDataFabricAddressChangedStub(MessageParcel &data)
{
    LOG_INFO("Enter");
    DataProcessingResponse response;
    response.code = static_cast<StatusCode>(data.ReadInt32());
    response.result = data.ReadString();
    LOG_INFO("OnDataFabricAddressChangedStub code:%{public}d, result:%{public}s",
        static_cast<int32_t>(response.code), response.result.c_str());
    OnDataFabricAddressChanged(response);
    LOG_INFO("Exit");
    return RUN_OK;
}
} // End of namespace NativePreferences
} // End of namespace OHOS
