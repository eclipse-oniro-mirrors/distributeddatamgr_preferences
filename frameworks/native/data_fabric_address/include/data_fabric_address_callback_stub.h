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

#ifndef DATA_FABRIC_ADDRESS_CALLBACK_STUB_H
#define DATA_FABRIC_ADDRESS_CALLBACK_STUB_H

#include <iremote_stub.h>
#include <nocopyable.h>

#include "data_fabric_address_callback.h"
#include "i_data_fabric_address.h"

namespace OHOS {
namespace NativePreferences {

class DataFabricAddressListenerCallbackStub : public IRemoteStub<IDataFabricAddressCallback> {
public:
    DISALLOW_COPY_AND_MOVE(DataFabricAddressListenerCallbackStub);
    DataFabricAddressListenerCallbackStub() = default;
    virtual ~DataFabricAddressListenerCallbackStub() = default;

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnDataFabricAddressChanged(const DataProcessingResponse& response) override {}
private:
    int32_t OnDataFabricAddressChangedStub(MessageParcel &data);
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_CALLBACK_STUB_H
