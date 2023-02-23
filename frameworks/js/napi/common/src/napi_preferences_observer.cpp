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

#include "js_logger.h"
#include "js_utils.h"

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
        int status = JSUtils::Convert2JSValue(env, key, argv[0]);
        if (status != JSUtils::OK) {
            LOG_DEBUG("OnChange CallFunction error.");
        }
    });
    LOG_DEBUG("OnChange key end");
}
} // namespace PreferencesJsKit
} // namespace OHOS