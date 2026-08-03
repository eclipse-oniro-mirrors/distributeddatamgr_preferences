/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_DATAOBS_MGR_CLIENT_H
#define OHOS_ABILITY_RUNTIME_DATAOBS_MGR_CLIENT_H

#include <memory>
#include "data_ability_observer_interface.h"
#include "errors.h"
#include "refbase.h"
#include "uri.h"

namespace OHOS {
namespace AAFwk {
struct DataObsOption {
    bool isSystem = false;
    bool isDataShare = false;
};

static constexpr int DATAOBS_DEFAULT_CURRENT_USER = -1;

class DataObsMgrClient {
public:
    DataObsMgrClient();
    virtual ~DataObsMgrClient();
    static std::shared_ptr<DataObsMgrClient> GetInstance();

    ErrCode RegisterObserver(const Uri &uri, sptr<IDataAbilityObserver> dataObserver,
        int32_t userId = DATAOBS_DEFAULT_CURRENT_USER, DataObsOption opt = DataObsOption());
    ErrCode UnregisterObserver(const Uri &uri, sptr<IDataAbilityObserver> dataObserver,
        int32_t userId = DATAOBS_DEFAULT_CURRENT_USER, DataObsOption opt = DataObsOption());
    ErrCode NotifyChange(const Uri &uri, int32_t userId = DATAOBS_DEFAULT_CURRENT_USER,
        DataObsOption opt = DataObsOption());
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_DATAOBS_MGR_CLIENT_H