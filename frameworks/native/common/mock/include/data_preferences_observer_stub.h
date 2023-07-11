/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef PREFERENCES_DATA_PREFERENCES_OBSERVER_STUB_H
#define PREFERENCES_DATA_PREFERENCES_OBSERVER_STUB_H

#include <memory>
#include <mutex>

#include "preferences_observer.h"

namespace OHOS {
class Uri {
public:
    Uri(const std::string str)
    {
    }
};
template <class T>
using sptr = std::shared_ptr<T>;
namespace NativePreferences {

class DataPreferencesObserverStub {
public:
    DataPreferencesObserverStub(const std::shared_ptr<PreferencesObserver> preferencesObserver);
    virtual ~DataPreferencesObserverStub();
    void OnChange();
    void OnChangePreferences(const std::string &key);
public:
    std::weak_ptr<PreferencesObserver> preferencesObserver_;
};

class DataObsMgrClient {
public:
    static std::shared_ptr<DataObsMgrClient> GetInstance();
    DataObsMgrClient();
    ~DataObsMgrClient();
    int RegisterObserver(const Uri &uri, sptr<DataPreferencesObserverStub> dataObserver);
    int UnregisterObserver(const Uri &uri, sptr<DataPreferencesObserverStub> dataObserver);
    int NotifyChange(const Uri &uri);
private:
    static std::mutex mutex_;
    static std::shared_ptr<DataObsMgrClient> instance_;
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_DATA_PREFERENCES_OBSERVER_STUB_H
