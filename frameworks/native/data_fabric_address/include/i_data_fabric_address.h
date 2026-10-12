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

#ifndef I_DATA_FABRIC_ADDRESS_H
#define I_DATA_FABRIC_ADDRESS_H

#include "data_fabric_address_callback.h"
#include "iremote_broker.h"

namespace OHOS {
namespace NativePreferences {

class IDataFabricAddressService : public IRemoteBroker {
public:
    enum RemoteOperation {
        SUBSCRIBE,
        UNSUBSCRIBE,
    };
    virtual int32_t Subscribe(const DataFabricAddressParams& inputParams,
        sptr<IDataFabricAddressCallback> callback) = 0;
    virtual int32_t Unsubscribe(const DataFabricAddressParams& inputParams) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DataFabricAddress.IDataFabricAddressService");
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // I_DATA_FABRIC_ADDRESS_H
