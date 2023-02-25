/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTEDDATAMGR_PREFERENCES_NAPI_PREFERENCES_OBSERVER_H
#define DISTRIBUTEDDATAMGR_PREFERENCES_NAPI_PREFERENCES_OBSERVER_H

#include "napi/native_api.h"
#include "preferences_observer.h"
#include "js_observer.h"

namespace OHOS {
namespace PreferencesJsKit {
class JSPreferencesObserver
    : public OHOS::NativePreferences::PreferencesObserver
    , public JSObserver {
public:
    JSPreferencesObserver(std::shared_ptr<UvQueue> uvQueue, napi_value callback);
    virtual ~JSPreferencesObserver() = default;
    void OnChange(const std::string &key) override;
};
} // namespace PreferencesJsKit
} // namespace OHOS
#endif // DISTRIBUTEDDATAMGR_PREFERENCES_NAPI_PREFERENCES_OBSERVER_H
