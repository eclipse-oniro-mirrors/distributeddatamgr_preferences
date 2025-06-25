/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "preferences_proxy.h"

#include <variant>

#include "ani_common_utils.h"
#include "log_print.h"
#include "napi_preferences_error.h"
#include "taihe_common_utils.h"

namespace OHOS {
namespace PreferencesEtsKit {
using namespace EtsUtils;
using namespace taihe;
using JSError = PreferencesJsKit::JSError;
using ParamTypeError = PreferencesJsKit::ParamTypeError;
using InnerError = PreferencesJsKit::InnerError;

static constexpr const char* KEY_EXCEEDS_MAXIMUM_LENGTH = "The key must be less than 1024 bytes.";
static constexpr const char* ENV_NOT_FOUND = "Failed to get env.";
PreferencesProxy::PreferencesProxy() {}

PreferencesProxy::PreferencesProxy(std::shared_ptr<NativePreferences::Preferences> preferences)
    : preferences_(preferences) {}

PreferencesProxy::~PreferencesProxy()
{
    UnRegisteredAllObservers(RegisterMode::LOCAL_CHANGE);
    UnRegisteredAllObservers(RegisterMode::MULTI_PRECESS_CHANGE);
    UnRegisteredAllDataObserver({});
    preferences_ = nullptr;
}

bool PreferencesProxy::CheckKey(const std::string &key)
{
    return key.length() <= NativePreferences::Preferences::MAX_KEY_LENGTH;
}

ValueTypeT PreferencesProxy::GetSync(string_view key, ValueTypeT const& defValue)
{
    if (preferences_ == nullptr) {
        SetBusinessError(std::make_shared<InnerError>("Failed to get instance."));
        return defValue;
    }
    auto keyStr = std::string(key);
    if (!CheckKey(keyStr)) {
        SetBusinessError(std::make_shared<ParamTypeError>(KEY_EXCEEDS_MAXIMUM_LENGTH));
        return defValue;
    }
    auto preferencesValue = NativePreferences::PreferencesValue();
    preferencesValue = preferences_->Get(keyStr, preferencesValue);
    if (std::holds_alternative<std::monostate>(preferencesValue.value_)) {
        return defValue;
    }
    return EtsUtils::ConvertToValueType(preferencesValue);
}

uintptr_t PreferencesProxy::GetAllSync()
{
    if (preferences_ == nullptr) {
        SetBusinessError(std::make_shared<InnerError>("Failed to get instance."));
        return 0;
    }
    auto allElements = preferences_->GetAllDatas();
    auto mapObj = EtsUtils::PreferencesMapToObject(::taihe::get_env(), allElements);
    if (mapObj == nullptr) {
        SetBusinessError(std::make_shared<InnerError>("Failed to convert object."));
    }
    return reinterpret_cast<uintptr_t>(mapObj);
}

bool PreferencesProxy::HasSync(string_view key)
{
    if (preferences_ == nullptr) {
        SetBusinessError(std::make_shared<InnerError>("Failed to get instance."));
        return false;
    }
    auto keyStr = std::string(key);
    if (!CheckKey(keyStr)) {
        SetBusinessError(std::make_shared<ParamTypeError>(KEY_EXCEEDS_MAXIMUM_LENGTH));
        return false;
    }
    return preferences_->HasKey(keyStr);
}

void PreferencesProxy::PutSync(string_view key, ValueTypeT const& value)
{
    if (preferences_ == nullptr) {
        SetBusinessError(std::make_shared<InnerError>("Failed to get instance."));
        return;
    }
    auto keyStr = std::string(key);
    if (!CheckKey(keyStr)) {
        SetBusinessError(std::make_shared<ParamTypeError>(KEY_EXCEEDS_MAXIMUM_LENGTH));
        return;
    }
    auto nativeValue = EtsUtils::ConvertToPreferencesValue(value);
    if (std::holds_alternative<std::monostate>(nativeValue.value_)) {
        SetBusinessError(std::make_shared<InnerError>("Failed to parse value."));
        return;
    }
    auto errCode = preferences_->Put(keyStr, nativeValue);
    if (errCode != NativePreferences::E_OK) {
        SetBusinessError(std::make_shared<InnerError>(errCode));
    }
}

void PreferencesProxy::DeleteSync(string_view key)
{
    if (preferences_ == nullptr) {
        SetBusinessError(std::make_shared<InnerError>("Failed to get instance."));
        return;
    }
    auto keyStr = std::string(key);
    if (!CheckKey(keyStr)) {
        SetBusinessError(std::make_shared<ParamTypeError>(KEY_EXCEEDS_MAXIMUM_LENGTH));
        return;
    }
    auto errCode = preferences_->Delete(keyStr);
    if (errCode != NativePreferences::E_OK) {
        SetBusinessError(std::make_shared<InnerError>(errCode));
    }
}

void PreferencesProxy::ClearSync()
{
    if (preferences_ == nullptr) {
        SetBusinessError(std::make_shared<InnerError>("Failed to get instance."));
        return;
    }
    auto errCode = preferences_->Clear();
    if (errCode != NativePreferences::E_OK) {
        SetBusinessError(std::make_shared<InnerError>(errCode));
    }
}

void PreferencesProxy::FlushSync()
{
    if (preferences_ == nullptr) {
        SetBusinessError(std::make_shared<InnerError>("Failed to get instance."));
        return;
    }
    auto errCode = preferences_->FlushSync();
    if (errCode != NativePreferences::E_OK) {
        SetBusinessError(std::make_shared<InnerError>(errCode));
    }
}

bool PreferencesProxy::HasRegisteredObserver(ani_env *env, ani_ref callbackRef, RegisterMode mode)
{
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ :
        (mode == RegisterMode::MULTI_PRECESS_CHANGE) ? multiProcessObservers_ : dataObservers_;
    for (auto &it : observers) {
        ani_boolean isEqual = false;
        if (ANI_OK == env->Reference_StrictEquals(callbackRef, it->GetRef(), &isEqual) && isEqual) {
            LOG_DEBUG("The observer has already subscribed, size:%{public}zu.", observers.size());
            return true;
        }
    }
    return false;
}

std::shared_ptr<JSError> PreferencesProxy::CreateGlobalReference(ani_env *env, uintptr_t opq, ani_ref &callbackRef)
{
    auto aniStatus = env->GlobalReference_Create(reinterpret_cast<ani_object>(opq), &callbackRef);
    if (aniStatus != ANI_OK) {
        LOG_ERROR("Failed to create ref, ret:%{public}d", static_cast<int32_t>(aniStatus));
        return std::make_shared<InnerError>("Failed to create ref.");
    }
    return nullptr;
}

void PreferencesProxy::RegisteredObserver(RegisterMode mode, CallbackType callback, uintptr_t opq)
{
    if (preferences_ == nullptr) {
        SetBusinessError(std::make_shared<InnerError>("Failed to get instance."));
        return;
    }
    auto env = ::taihe::get_env();
    if (env == nullptr) {
        SetBusinessError(std::make_shared<InnerError>(ENV_NOT_FOUND));
        return;
    }
    ani_ref callbackRef;
    auto errCode = CreateGlobalReference(env, opq, callbackRef);
    if (errCode != nullptr) {
        SetBusinessError(errCode);
        return;
    }
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ : multiProcessObservers_;

    if (!HasRegisteredObserver(env, callbackRef, mode)) {
        auto observer = std::make_shared<TaihePreferencesObserver>(callback, callbackRef);
        int32_t errCode = preferences_->RegisterObserver(observer, mode);
        if (errCode != NativePreferences::E_OK) {
            SetBusinessError(std::make_shared<InnerError>(errCode));
            return;
        }
        observers.push_back(observer);
    } else {
        env->GlobalReference_Delete(callbackRef);
    }
    LOG_DEBUG("The observer subscribed success.");
    return;
}

void PreferencesProxy::RegisteredDataObserver(const std::vector<std::string> &keys, CallbackType callback,
    uintptr_t opq)
{
    if (preferences_ == nullptr) {
        SetBusinessError(std::make_shared<InnerError>("Failed to get instance."));
        return;
    }
    auto env = ::taihe::get_env();
    if (env == nullptr) {
        SetBusinessError(std::make_shared<InnerError>(ENV_NOT_FOUND));
        return;
    }
    ani_ref callbackRef;
    auto errCode = CreateGlobalReference(env, opq, callbackRef);
    if (errCode != nullptr) {
        SetBusinessError(errCode);
        return;
    }
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = dataObservers_;
    if (!HasRegisteredObserver(env, callbackRef, RegisterMode::DATA_CHANGE)) {
        auto observer = std::make_shared<TaihePreferencesObserver>(callback, callbackRef);
        int32_t errCode = preferences_->RegisterDataObserver(observer, keys);
        if (errCode != NativePreferences::E_OK) {
            SetBusinessError(std::make_shared<InnerError>(errCode));
            return;
        }
        observers.push_back(observer);
    } else {
        env->GlobalReference_Delete(callbackRef);
    }
    LOG_DEBUG("The dataChange observer subscribed success.");
    return;
}

void PreferencesProxy::OnChange(callback_view<void(string_view)> cb, uintptr_t opq)
{
    RegisteredObserver(RegisterMode::LOCAL_CHANGE, cb, opq);
}

void PreferencesProxy::OnDataChange(array_view<string> keys, callback_view<void(map_view<string, ValueTypeT>)> cb,
    uintptr_t opq)
{
    RegisteredDataObserver(std::vector<std::string>(keys.begin(), keys.end()), cb, opq);
}

void PreferencesProxy::OnMultiProcessChange(callback_view<void(string_view)> cb, uintptr_t opq)
{
    RegisteredObserver(RegisterMode::MULTI_PRECESS_CHANGE, cb, opq);
}

void PreferencesProxy::UnRegisteredObserver(RegisterMode mode, uintptr_t opq)
{
    if (preferences_ == nullptr) {
        SetBusinessError(std::make_shared<InnerError>("Failed to get instance."));
        return;
    }
    auto env = ::taihe::get_env();
    if (env == nullptr) {
        SetBusinessError(std::make_shared<InnerError>(ENV_NOT_FOUND));
        return;
    }
    ani_ref callbackRef;
    auto errCode = CreateGlobalReference(env, opq, callbackRef);
    if (errCode != nullptr) {
        SetBusinessError(errCode);
        return;
    }
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ : multiProcessObservers_;
    auto it = observers.begin();
    while (it != observers.end()) {
        ani_boolean isEqual = false;
        if (ANI_OK == env->Reference_StrictEquals(callbackRef, (*it)->GetRef(), &isEqual) && isEqual) {
            int32_t errCode = preferences_->UnRegisterObserver(*it, mode);
            if (errCode != NativePreferences::E_OK) {
                SetBusinessError(std::make_shared<InnerError>(errCode));
                return;
            }
            it = observers.erase(it);
            LOG_DEBUG("The observer unsubscribed success.");
            break; // specified observer is current iterator
        }
        ++it;
    }
    return;
}

void PreferencesProxy::UnRegisteredAllObservers(RegisterMode mode)
{
    if (preferences_ == nullptr) {
        SetBusinessError(std::make_shared<InnerError>("Failed to get instance."));
        return;
    }
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ : multiProcessObservers_;
    bool hasFailed = false;
    int32_t result = NativePreferences::E_OK;
    int32_t errCode = NativePreferences::E_OK;
    for (auto &observer : observers) {
        result = preferences_->UnRegisterObserver(observer, mode);
        if (result != NativePreferences::E_OK) {
            hasFailed = true;
            LOG_ERROR("The observer unsubscribed has failed, errCode %{public}d.", result);
            errCode = result;
        }
    }
    observers.clear();
    LOG_DEBUG("All observers unsubscribed success.");
    if (hasFailed) {
        SetBusinessError(std::make_shared<InnerError>(errCode));
    }
}

void PreferencesProxy::OffChange(optional_view<uintptr_t> opq)
{
    if (opq.has_value()) {
        UnRegisteredObserver(RegisterMode::LOCAL_CHANGE, opq.value());
    } else {
        UnRegisteredAllObservers(RegisterMode::LOCAL_CHANGE);
    }
}

void PreferencesProxy::UnRegisteredDataObserver(const std::vector<std::string> &keys, uintptr_t opq)
{
    if (preferences_ == nullptr) {
        SetBusinessError(std::make_shared<InnerError>("Failed to get instance."));
        return;
    }
    auto env = ::taihe::get_env();
    if (env == nullptr) {
        SetBusinessError(std::make_shared<InnerError>(ENV_NOT_FOUND));
        return;
    }
    ani_ref callbackRef;
    auto errCode = CreateGlobalReference(env, opq, callbackRef);
    if (errCode != nullptr) {
        SetBusinessError(errCode);
        return;
    }
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = dataObservers_;
    auto it = observers.begin();
    while (it != observers.end()) {
        ani_boolean isEqual = false;
        if (ANI_OK == env->Reference_StrictEquals(callbackRef, (*it)->GetRef(), &isEqual) && isEqual) {
            int32_t errCode = preferences_->UnRegisterDataObserver(*it, keys);
            if (errCode != NativePreferences::E_OK && errCode != NativePreferences::E_OBSERVER_RESERVE) {
                SetBusinessError(std::make_shared<InnerError>(errCode));
                return;
            }
            if (errCode == NativePreferences::E_OK) {
                it = observers.erase(it);
            }
            break;
        }
        ++it;
    }
    LOG_DEBUG("The dataChange observer unsubscribed success.");
    return;
}

void PreferencesProxy::UnRegisteredAllDataObserver(const std::vector<std::string> &keys)
{
    if (preferences_ == nullptr) {
        SetBusinessError(std::make_shared<InnerError>("Failed to get instance."));
        return;
    }
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = dataObservers_;
    auto it = observers.begin();
    while (it != observers.end()) {
        int32_t errCode = preferences_->UnRegisterDataObserver(*it, keys);
        if (errCode != NativePreferences::E_OK && errCode != NativePreferences::E_OBSERVER_RESERVE) {
            SetBusinessError(std::make_shared<InnerError>(errCode));
            return;
        }
        if (errCode == NativePreferences::E_OK) {
            it = observers.erase(it);
        } else {
            ++it;
        }
    }
    LOG_DEBUG("The dataChange observer unsubscribed success.");
    return;
}

void PreferencesProxy::OffMultiProcessChange(optional_view<uintptr_t> opq)
{
    if (opq.has_value()) {
        UnRegisteredObserver(RegisterMode::MULTI_PRECESS_CHANGE, opq.value());
    } else {
        UnRegisteredAllObservers(RegisterMode::MULTI_PRECESS_CHANGE);
    }
}

void PreferencesProxy::OffDataChange(array_view<string> keys, optional_view<uintptr_t> opq)
{
    auto nativeKeys = std::vector<std::string>(keys.begin(), keys.end());
    if (opq.has_value()) {
        UnRegisteredDataObserver(nativeKeys, opq.value());
    } else {
        UnRegisteredAllDataObserver(nativeKeys);
    }
}

} // namespace PreferencesEtsKit
} // namespace OHOS
