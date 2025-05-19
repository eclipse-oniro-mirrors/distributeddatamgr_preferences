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
#include "taihe_common_utils.h"
#include "taihe_preferences_error.h"

namespace OHOS {
namespace PreferencesEtsKit {

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
    PRE_ANI_ASSERT_BASE(key.length() <= NativePreferences::Preferences::MAX_KEY_LENGTH,
        std::make_shared<ParamTypeError>("The key must be less than 1024 bytes."), false);
    return true;
}

ValueType_t PreferencesProxy::GetSync(string_view key, ValueType_t const& defValue)
{
    PRE_ANI_ASSERT_BASE(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when get, the instance is nullptr."), defValue);
    auto keyStr = std::string(key);
    if (!CheckKey(keyStr)) {
        return defValue;
    }
    NativePreferences::PreferencesValue preferencesValue();
    preferencesValue = preferences_->Get(keyStr, preferencesValue);
    if (std::holds_alternative<std::monostate>(preferencesValue.value_)) {
        return defValue;
    }
    return EtsUtils::ConvertToValueType(preferencesValue);
}

uintptr_t PreferencesProxy::GetAllSync()
{
    PRE_ANI_ASSERT_BASE(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when getAll, the instance is nullptr."), 0);
    auto allElements = preferences_->GetAllDatas();
    return reinterpret_cast<uintptr_t>(EtsUtils::PreferencesMapToObject(::taihe::get_env(), allElements));
}

bool PreferencesProxy::HasSync(string_view key)
{
    PRE_ANI_ASSERT_BASE(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when has, the instance is nullptr."), false);
    auto keyStr = std::string(key);
    if (!CheckKey(keyStr)) {
        return false;
    }
    return preferences_->HasKey(keyStr);
}

void PreferencesProxy::PutSync(string_view key, ValueType_t const& value)
{
    PRE_ANI_ASSERT_RETURN_VOID(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when put, the instance is nullptr."));
    auto keyStr = std::string(key);
    if (!CheckKey(keyStr)) {
        return;
    }
    auto nativeValue = EtsUtils::ConvertToPreferencesValue(value);
    auto errCode = preferences_->Put(keyStr, nativeValue);
    PRE_ANI_ASSERT_RETURN_VOID(errCode == OHOS::NativePreferences::E_OK, std::make_shared<InnerError>(errCode));
}

void PreferencesProxy::DeleteSync(string_view key)
{
    PRE_ANI_ASSERT_RETURN_VOID(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when delete, the instance is nullptr."));
    auto keyStr = std::string(key);
    if (!CheckKey(keyStr)) {
        return;
    }
    auto errCode = preferences_->Delete(keyStr);
    PRE_ANI_ASSERT_RETURN_VOID(errCode == OHOS::NativePreferences::E_OK, std::make_shared<InnerError>(errCode));
}

void PreferencesProxy::ClearSync()
{
    PRE_ANI_ASSERT_RETURN_VOID(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when clear, the instance is nullptr."));
    auto errCode = preferences_->Clear();
    PRE_ANI_ASSERT_RETURN_VOID(errCode == OHOS::NativePreferences::E_OK, std::make_shared<InnerError>(errCode));
}

void PreferencesProxy::FlushSync()
{
    PRE_ANI_ASSERT_RETURN_VOID(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when flush, the instance is nullptr."));
    auto errCode = preferences_->FlushSync();
    PRE_ANI_ASSERT_RETURN_VOID(errCode == OHOS::NativePreferences::E_OK, std::make_shared<InnerError>(errCode));
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

ani_ref PreferencesProxy::CreateGlobalReference(ani_env *env, uintptr_t opq)
{
    ani_ref ref = nullptr;
    PRE_ANI_ASSERT_BASE(env != nullptr, std::make_shared<InnerError>("Failed to get env."), ref);
    auto aniStatus = env->GlobalReference_Create(reinterpret_cast<ani_object>(opq), &ref);
    if (aniStatus != ANI_OK) {
        LOG_ERROR("Failed to create ref, ret:%{public}d", static_cast<int32_t>(aniStatus));
        auto err = std::make_shared<InnerError>("Failed to create ref.");
        ::taihe::set_business_error(err->GetCode(), err->GetMsg().c_str());
        return ref;
    }
    return ref;
}

void PreferencesProxy::RegisteredObserver(RegisterMode mode, CallbackType callback, uintptr_t opq)
{
    PRE_ANI_ASSERT_RETURN_VOID(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when on, the instance is nullptr."));
    auto env = ::taihe::get_env();
    ani_ref callbackRef = CreateGlobalReference(env, opq);
    if (callbackRef == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ : multiProcessObservers_;

    if (!HasRegisteredObserver(env, callbackRef, mode)) {
        auto observer = std::make_shared<TaihePreferencesObserver>(callback, callbackRef);
        int32_t errCode = preferences_->RegisterObserver(observer, mode);
        PRE_ANI_ASSERT_RETURN_VOID(errCode == E_OK, std::make_shared<InnerError>(errCode));
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
    PRE_ANI_ASSERT_RETURN_VOID(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when on, the instance is nullptr."));
    auto env = ::taihe::get_env();
    ani_ref callbackRef = CreateGlobalReference(env, opq);
    if (callbackRef == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = dataObservers_;
    if (!HasRegisteredObserver(env, callbackRef, RegisterMode::DATA_CHANGE)) {
        auto observer = std::make_shared<TaihePreferencesObserver>(callback, callbackRef);
        int32_t errCode = preferences_->RegisterDataObserver(observer, keys);
        PRE_ANI_ASSERT_RETURN_VOID(errCode == E_OK, std::make_shared<InnerError>(errCode));
        observers.push_back(observer);
    } else {
        env->GlobalReference_Delete(callbackRef);
    }
    LOG_DEBUG("The dataChange observer subscribed success.");
    return;
}

void PreferencesProxy::OnChange(callback_view<void(string_view)> cb, uintptr_t opq)
{
    PRE_ANI_ASSERT_RETURN_VOID(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when on, the instance is nullptr."));
    RegisteredObserver(RegisterMode::LOCAL_CHANGE, cb, opq);
}

void PreferencesProxy::OnDataChange(array_view<string> keys, callback_view<void(map_view<string, ValueType_t>)> cb,
    uintptr_t opq)
{
    PRE_ANI_ASSERT_RETURN_VOID(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when on, the instance is nullptr."));
    RegisteredDataObserver(std::vector<std::string>(keys.begin(), keys.end()), cb, opq);
}

void PreferencesProxy::OnMultiProcessChange(callback_view<void(string_view)> cb, uintptr_t opq)
{
    PRE_ANI_ASSERT_RETURN_VOID(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when on, the instance is nullptr."));
    RegisteredObserver(RegisterMode::MULTI_PRECESS_CHANGE, cb, opq);
}

void PreferencesProxy::UnRegisteredObserver(RegisterMode mode, uintptr_t opq)
{
    PRE_ANI_ASSERT_RETURN_VOID(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when off, the instance is nullptr."));
    auto env = ::taihe::get_env();
    ani_ref callbackRef = CreateGlobalReference(env, opq);
    if (callbackRef == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ : multiProcessObservers_;
    auto it = observers.begin();
    while (it != observers.end()) {
        ani_boolean isEqual = false;
        if (ANI_OK == env->Reference_StrictEquals(callbackRef, (*it)->GetRef(), &isEqual) && isEqual) {
            int32_t errCode = preferences_->UnRegisterObserver(*it, mode);
            PRE_ANI_ASSERT_RETURN_VOID(errCode == E_OK, std::make_shared<InnerError>(errCode));
            (*it)->ClearRef();
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
    PRE_ANI_ASSERT_RETURN_VOID(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when off, the instance is nullptr."));
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = (mode == RegisterMode::LOCAL_CHANGE) ? localObservers_ : multiProcessObservers_;
    bool hasFailed = false;
    int32_t result = E_OK;
    int32_t errCode = E_OK;
    for (auto &observer : observers) {
        result = preferences_->UnRegisterObserver(observer, mode);
        if (result != E_OK) {
            hasFailed = true;
            LOG_ERROR("The observer unsubscribed has failed, errCode %{public}d.", result);
            errCode = result;
        }
        observer->ClearRef();
    }
    observers.clear();
    LOG_DEBUG("All observers unsubscribed success.");
    PRE_ANI_ASSERT_RETURN_VOID(!hasFailed, std::make_shared<InnerError>(errCode));
}

void PreferencesProxy::OffChange(optional_view<uintptr_t> opq)
{
    PRE_ANI_ASSERT_RETURN_VOID(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when off, the instance is nullptr."));
    if (opq.has_value()) {
        UnRegisteredObserver(RegisterMode::LOCAL_CHANGE, opq.value());
    } else {
        UnRegisteredAllObservers(RegisterMode::LOCAL_CHANGE);
    }
}

void PreferencesProxy::UnRegisteredDataObserver(const std::vector<std::string> &keys, uintptr_t opq)
{
    PRE_ANI_ASSERT_RETURN_VOID(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when off, the instance is nullptr."));
    auto env = ::taihe::get_env();
    ani_ref callbackRef = CreateGlobalReference(env, opq);
    if (callbackRef == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = dataObservers_;
    auto it = observers.begin();
    while (it != observers.end()) {
        ani_boolean isEqual = false;
        if (ANI_OK == env->Reference_StrictEquals(callbackRef, (*it)->GetRef(), &isEqual) && isEqual) {
            int32_t errCode = preferences_->UnRegisterDataObserver(*it, keys);
            PRE_ANI_ASSERT_RETURN_VOID(errCode == E_OK || errCode == E_OBSERVER_RESERVE,
                std::make_shared<InnerError>(errCode));
            if (errCode == E_OK) {
                (*it)->ClearRef();
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
    PRE_ANI_ASSERT_RETURN_VOID(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when off, the instance is nullptr."));
    std::lock_guard<std::mutex> lck(listMutex_);
    auto &observers = dataObservers_;
    auto it = observers.begin();
    while (it != observers.end()) {
        int32_t errCode = preferences_->UnRegisterDataObserver(*it, keys);
        PRE_ANI_ASSERT_RETURN_VOID(errCode == E_OK || errCode == E_OBSERVER_RESERVE,
            std::make_shared<InnerError>(errCode));
        if (errCode == E_OK) {
            (*it)->ClearRef();
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
    PRE_ANI_ASSERT_RETURN_VOID(preferences_ != nullptr,
        std::make_shared<InnerError>("Failed to get instance when off, the instance is nullptr."));
    auto nativeKeys = std::vector<std::string>(keys.begin(), keys.end());
    if (opq.has_value()) {
        UnRegisteredDataObserver(nativeKeys, opq.value());
    } else {
        UnRegisteredAllDataObserver(nativeKeys);
    }
}

} // namespace PreferencesEtsKit
} // namespace OHOS
