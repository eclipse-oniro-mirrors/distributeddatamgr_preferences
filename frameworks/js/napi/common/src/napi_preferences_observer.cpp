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
#include "napi_preferences_observer.h"

#include "js_utils.h"

using namespace OHOS::NativePreferences;

namespace OHOS {
namespace PreferencesJsKit {
JSPreferencesObserver::JSPreferencesObserver(std::shared_ptr<UvQueue> uvQueue, napi_value callback)
    : JSObserver(uvQueue, callback)
{
}

void JSPreferencesObserver::OnChange(const std::string &key)
{
    AsyncCall([key](napi_env env, int &argc, napi_value *argv) {
        argc = 1;
        argv[0] = JSUtils::Convert2JSValue(env, key);
    });
    LOG_DEBUG("OnChange key end");
}

void JSPreferencesObserver::OnChange(const std::map<std::string, PreferencesValue> &records)
{
    AsyncCall([records](napi_env env, int &argc, napi_value *argv) {
        napi_value result;
        int errCode = napi_create_object(env, &result);
        if (errCode != napi_ok) {
            LOG_ERROR("napi_create_object failed, onChange return.");
            return;
        }
        for (const auto &[key, value] : records) {
            napi_set_named_property(env, result, key.c_str(), JSUtils::Convert2JSValue(env, value.value_));
        }
        argc = 1;
        argv[0] = result;
    });
    LOG_DEBUG("OnChange records end");
}
} // namespace PreferencesJsKit
} // namespace OHOS