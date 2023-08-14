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

#ifndef PREFERENCES_DATA_PREFERENCES_OBSERVER_STUB_H
#define PREFERENCES_DATA_PREFERENCES_OBSERVER_STUB_H

#include "data_ability_observer_stub.h"
#include "dataobs_mgr_client.h"
#include "preferences_observer.h"

namespace OHOS {
namespace NativePreferences {
using DataObsMgrClient = AAFwk::DataObsMgrClient;
class DataPreferencesObserverStub : public AAFwk::DataAbilityObserverStub {
public:
    DataPreferencesObserverStub(const std::shared_ptr<PreferencesObserver> preferencesObserver)
        : preferencesObserver_(preferencesObserver)
    {}

    virtual ~DataPreferencesObserverStub() {}

    void OnChange() override {}

    void OnChangePreferences(const std::string &key) override
    {
        std::shared_ptr<PreferencesObserver> sharedPreferencesObserver = preferencesObserver_.lock();
        if (sharedPreferencesObserver != nullptr) {
            sharedPreferencesObserver->OnChange(key);
        }
    }

public:
    std::weak_ptr<PreferencesObserver> preferencesObserver_;
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_DATA_PREFERENCES_OBSERVER_STUB_H