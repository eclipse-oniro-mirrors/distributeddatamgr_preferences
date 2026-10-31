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

#ifndef I_KV_STORE_DATA_SERVICE_H
#define I_KV_STORE_DATA_SERVICE_H

#include <string>

#include "iremote_broker.h"

namespace OHOS {
namespace DistributedKv {

class IKvStoreDataService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DistributedKv.IKvStoreDataService");

    virtual sptr<IRemoteObject> GetFeatureInterface(const std::string &name) = 0;
};
} // End of namespace DistributedKv
} // End of namespace OHOS
#endif // I_KV_STORE_DATA_SERVICE_H
