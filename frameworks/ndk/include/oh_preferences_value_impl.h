/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OH_PREFERENCES_VALUE_IMPL_H
#define OH_PREFERENCES_VALUE_IMPL_H

#include "oh_preferences_value.h"
#include "preferences.h"

#ifdef __cplusplus
extern "C" {
#endif

struct OH_PreferencesValue {
    int id;
};

struct OH_PreferencesPair {
    const char *key;
    const OH_PreferencesValue *value;
};


class OH_PreferencesValueImpl : public OH_PreferencesValue {
public:
    OHOS::NativePreferences::PreferencesValue value_;
    Preference_ValueType type_;
};

#ifdef __cplusplus
}
#endif
#endif // OH_PREFERENCES_VALUE_IMPL_H
