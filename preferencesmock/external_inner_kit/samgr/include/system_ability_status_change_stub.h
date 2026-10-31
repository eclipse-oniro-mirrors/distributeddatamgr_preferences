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

#ifndef DATA_FABRIC_ADDRESS_MOCK_SYSTEM_ABILITY_STATUS_CHANGE_STUB_H
#define DATA_FABRIC_ADDRESS_MOCK_SYSTEM_ABILITY_STATUS_CHANGE_STUB_H

#include "if_system_ability_manager.h"
#include "iremote_stub.h"

namespace OHOS {
class SystemAbilityStatusChangeStub : public IRemoteStub<ISystemAbilityStatusChange> {
public:
    SystemAbilityStatusChangeStub() = default;
    virtual ~SystemAbilityStatusChangeStub() override = default;
};
} // namespace OHOS
#endif // DATA_FABRIC_ADDRESS_MOCK_SYSTEM_ABILITY_STATUS_CHANGE_STUB_H
