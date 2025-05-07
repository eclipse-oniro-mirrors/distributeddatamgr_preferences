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
#include "taihe_preferences_observer.h"

#include "log_print.h"
#include "taihe_common_utils.h"

namespace OHOS {
namespace PreferencesEtsKit {
TaihePreferencesObserver::TaihePreferencesObserver(CallbackType callback, ani_ref ref)
    : callback_(std::move(callback)), ref_(std::move(ref)) {}

TaihePreferencesObserver::~TaihePreferencesObserver()
{
    if (auto *env = ::taihe::get_env()) {
        env->GlobalReference_Delete(ref_);
    }
}

void TaihePreferencesObserver::OnChange(const std::string &key)
{
    StringCallback_t *callback = std::get_if<StringCallback_t>(&callback_);
    if (callback != nullptr) {
        (*callback)(key);
        LOG_DEBUG("OnChange key end");
    }
}

void TaihePreferencesObserver::OnChange(const std::map<std::string, NativePreferences::PreferencesValue> &records)
{
    MapCallback_t *callback = std::get_if<MapCallback_t>(&callback_);
    if (callback != nullptr) {
        (*callback)(EtsUtils::ConvertMapToTaiheMap(records));
        LOG_DEBUG("OnChange key end");
    }
}

ani_ref TaihePreferencesObserver::GetRef()
{
    return ref_;
}

void TaihePreferencesObserver::ClearRef()
{
    if (ref_ == nullptr) {
        return;
    }
    if (auto *env = ::taihe::get_env()) {
        env->GlobalReference_Delete(ref_);
    }
    ref_ = nullptr;
}
} // namespace PreferencesEtsKit
} // namespace OHOS
