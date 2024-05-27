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
#include "js_sendable_utils.h"

using namespace OHOS::NativePreferences;
using namespace OHOS::Sendable::JSPreferences;
namespace OHOS {
namespace PreferencesJsKit {
JSPreferencesObserver::JSPreferencesObserver(std::shared_ptr<UvQueue> uvQueue, napi_value callback, bool sendabel)
    : JSObserver(uvQueue, callback, sendabel)
{
}

void JSPreferencesObserver::OnChange(const std::string &key)
{
    AsyncCall([key](napi_env env, bool sendable, int &argc, napi_value *argv) {
        argc = 1;
        argv[0] = sendable ? Utils::ConvertToSendable(env, key) : JSUtils::Convert2JSValue(env, key);
    });
    LOG_DEBUG("OnChange key end");
}

void JSPreferencesObserver::OnChange(const std::map<std::string, PreferencesValue> &records)
{
    AsyncCall([records](napi_env env, bool sendable, int &argc, napi_value *argv) {
        napi_value result;
        std::vector<napi_property_descriptor> descriptors;
        for (const auto &[key, value] : records) {
            descriptors.push_back(napi_property_descriptor(
                DECLARE_NAPI_DEFAULT_PROPERTY(key.c_str(), Utils::ConvertToSendable(env, value.value_))));
        }
        sendable ? napi_create_sendable_object_with_properties(env, descriptors.size(), descriptors.data(), &result)
                 : napi_create_object_with_properties(env, &result, descriptors.size(), descriptors.data());
        argc = 1;
        argv[0] = result;
    });
    LOG_DEBUG("OnChange records end");
}
} // namespace PreferencesJsKit
} // namespace OHOS