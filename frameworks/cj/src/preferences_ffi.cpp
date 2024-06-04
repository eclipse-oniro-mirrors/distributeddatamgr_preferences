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

#include <vector>
#include <map>
#include <cinttypes>

#include "preferences_ffi.h"
#include "preferences_impl.h"
#include "preferences_log.h"
#include "cj_lambda.h"

using namespace OHOS::FFI;
using namespace OHOS::Preferences;

namespace OHOS {
namespace Preferences {
extern "C" {
int64_t FfiOHOSPreferencesGetPreferences(OHOS::AbilityRuntime::Context* context, const char* name,
    const char* dataGroupId, int32_t* errCode)
{
    auto nativePreferences = FFIData::Create<PreferencesImpl>(context, name, dataGroupId, errCode);
    return nativePreferences->GetID();
}

int32_t FfiOHOSPreferencesDeletePreferences(OHOS::AbilityRuntime::Context* context, const char* name,
    const char* dataGroupId)
{
    return PreferencesImpl::DeletePreferences(context, name, dataGroupId);
}

int32_t FfiOHOSPreferencesRemovePreferencesFromCache(OHOS::AbilityRuntime::Context* context, const char* name,
    const char* dataGroupId)
{
    return PreferencesImpl::RemovePreferencesFromCache(context, name, dataGroupId);
}

ValueType FfiOHOSPreferencesGet(int64_t id, const char* key, ValueType defValue)
{
    auto instance = FFIData::GetData<PreferencesImpl>(id);
    if (!instance) {
        LOGE("[Preferences] instance not exist. %{public}" PRId64, id);
        return ValueType{0};
    }
    return instance->Get(key, defValue);
}

int32_t FfiOHOSPreferencesPut(int64_t id, const char* key, ValueType value)
{
    auto instance = FFIData::GetData<PreferencesImpl>(id);
    if (!instance) {
        LOGE("[Preferences] instance not exist. %{public}" PRId64, id);
        return ERR_INVALID_INSTANCE_CODE;
    }
    return instance->Put(key, value);
}

ValueTypes FfiOHOSPreferencesGetAll(int64_t id)
{
    auto instance = FFIData::GetData<PreferencesImpl>(id);
    if (!instance) {
        LOGE("[Preferences] instance not exist. %{public}" PRId64, id);
        return ValueTypes{0};
    }
    return instance->GetAll();
}

void FfiOHOSPreferencesFlush(int64_t id)
{
    auto instance = FFIData::GetData<PreferencesImpl>(id);
    if (!instance) {
        LOGE("[Preferences] instance not exist. %{public}" PRId64, id);
        return;
    }
    instance->Flush();
    return;
}

void FfiOHOSPreferencesClear(int64_t id)
{
    auto instance = FFIData::GetData<PreferencesImpl>(id);
    if (!instance) {
        LOGE("[Preferences] instance not exist. %{public}" PRId64, id);
        return;
    }
    instance->Clear();
    return;
}

bool FfiOHOSPreferencesHas(int64_t id, const char* key)
{
    auto instance = FFIData::GetData<PreferencesImpl>(id);
    if (!instance) {
        LOGE("[Preferences] instance not exist. %{public}" PRId64, id);
        return false;
    }
    return instance->HasKey(key);
}

int32_t FfiOHOSPreferencesDelete(int64_t id, const char* key)
{
    auto instance = FFIData::GetData<PreferencesImpl>(id);
    if (!instance) {
        LOGE("[Preferences] instance not exist. %{public}" PRId64, id);
        return ERR_INVALID_INSTANCE_CODE;
    }
    return instance->Delete(key);
}
    
int32_t FfiOHOSPreferencesOn(int64_t id, const char* mode,
    void (*callback)(const char* value), void (*callbackRef)(const char* valueRef))
{
    auto instance = FFIData::GetData<PreferencesImpl>(id);
    if (!instance) {
        LOGE("[Preferences] instance not exist. %{public}" PRId64, id);
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto onChange = [lambda = CJLambda::Create(callbackRef)](const std::string& valueRef) ->
        void { lambda(valueRef.c_str()); };
    return instance->RegisterObserver(mode, (std::function<void(std::string)>*)(callback), onChange);
}

int32_t FfiOHOSPreferencesOff(int64_t id, const char* mode, void (*callback)(const char* value))
{
    auto instance = FFIData::GetData<PreferencesImpl>(id);
    if (!instance) {
        LOGE("[Preferences] instance not exist. %{public}" PRId64, id);
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto onChange = [lambda = CJLambda::Create(callback)](const std::string& value) -> void { lambda(value.c_str()); };
    return instance->UnRegisterObserver(mode, (std::function<void(std::string)>*)(callback));
}

int32_t FfiOHOSPreferencesOffAll(int64_t id, const char* mode)
{
    auto instance = FFIData::GetData<PreferencesImpl>(id);
    if (!instance) {
        LOGE("[Preferences] instance not exist. %{public}" PRId64, id);
        return ERR_INVALID_INSTANCE_CODE;
    }
    return instance->UnRegisteredAllObservers(mode);
}
}
}
}