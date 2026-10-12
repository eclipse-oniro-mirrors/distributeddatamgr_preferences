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

#ifndef DATA_FABRIC_ADDRESS_PROXY_H
#define DATA_FABRIC_ADDRESS_PROXY_H

#include "data_fabric_address_callback.h"
#include "data_fabric_address_types.h"
#include "i_data_fabric_address.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace NativePreferences {

class DataFabricAddressProxy : public IRemoteProxy<IDataFabricAddressService> {
public:
    DISALLOW_COPY_AND_MOVE(DataFabricAddressProxy);
    explicit DataFabricAddressProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IDataFabricAddressService>(
        object) {}
    virtual ~DataFabricAddressProxy() = default;

    int32_t Subscribe(const DataFabricAddressParams& inputParams,
        sptr<IDataFabricAddressCallback> callback) override;
    int32_t Unsubscribe(const DataFabricAddressParams& inputParams) override;
private:
    bool MarshallingDataFabricAddressParams(const DataFabricAddressParams& inputParams,
        MessageParcel &parcel);
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_PROXY_H
