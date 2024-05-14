/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef PREFERENCES_OBSERVER_H
#define PREFERENCES_OBSERVER_H

#include <map>
#include <string>

#include "preferences_value.h"
#include "preferences_visibility.h"

namespace OHOS {
namespace NativePreferences {
/**
 * The observer class of preferences.
 */

class PREF_API_EXPORT PreferencesObserver {
public:
    enum RegisterMode { LOCAL_CHANGE = 0, MULTI_PRECESS_CHANGE, DATA_CHANGE, CHANGE_BUTT };
    PREF_API_EXPORT virtual ~PreferencesObserver();

    /**
     * @brief  A callback function when the data changes.
     *
     * This function is the callback when the value corresponding to key in the preferences changes.
     *
     * @param key Indicates the key of the preferences. It cannot be empty.
     */
    virtual void OnChange(const std::string &key) = 0;

    virtual void OnChange(const std::map<std::string, NativePreferences::PreferencesValue> &records) {};
};
} // End of namespace NativePreferences
} // End of namespace OHOS
#endif // End of #ifndef PREFERENCES_OBSERVER_H
