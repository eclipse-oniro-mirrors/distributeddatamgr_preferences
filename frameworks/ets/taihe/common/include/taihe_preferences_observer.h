/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef PREFERENCES_FRAMEWORKS_TAIHE_PREFERENCES_OBSERVER_H
#define PREFERENCES_FRAMEWORKS_TAIHE_PREFERENCES_OBSERVER_H

#include "preferences_observer.h"
#include "taihe/runtime.hpp"
#include "taihe_common_utils.h"

namespace OHOS {
namespace PreferencesEtsKit {
using ValueType = ohos::data::preferences::ValueType;
using StringCallback = ::taihe::callback<void(::taihe::string_view)>;
using MapCallback = ::taihe::callback<void(::taihe::map_view<::taihe::string, ValueType>)>;
using CallbackType = std::variant<StringCallback, MapCallback>;

class TaihePreferencesObserver : public OHOS::NativePreferences::PreferencesObserver {
public:
    TaihePreferencesObserver(CallbackType callback, ani_ref ref);
    virtual ~TaihePreferencesObserver();
    void OnChange(const std::string &key) override;
    void OnChange(const std::map<std::string, NativePreferences::PreferencesValue> &records) override;
    ani_ref GetRef();
private:
    CallbackType callback_;
    ani_ref ref_;
};
} // namespace PreferencesEtsKit
} // namespace OHOS
#endif // PREFERENCES_FRAMEWORKS_TAIHE_PREFERENCES_OBSERVER_H
