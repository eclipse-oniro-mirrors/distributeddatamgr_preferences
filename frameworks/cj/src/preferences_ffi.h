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
#ifndef PREFERENCES_FFI_H
#define PREFERENCES_FFI_H

#include <cstdint>

#include "ffi_remote_data.h"
#include "cj_common_ffi.h"
#include "preferences_interface.h"
#include "preferences_impl.h"

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "napi_base_context.h"
#endif

namespace OHOS {
namespace Preferences {
    
extern "C" {
    FFI_EXPORT int64_t FfiOHOSPreferencesGetPreferences(OHOS::AbilityRuntime::Context* context, const char* name,
        const char* dataGroupId, int32_t* errCode);

    FFI_EXPORT int32_t FfiOHOSPreferencesDeletePreferences(OHOS::AbilityRuntime::Context* context, const char* name,
        const char* dataGroupId);

    FFI_EXPORT int32_t FfiOHOSPreferencesRemovePreferencesFromCache(OHOS::AbilityRuntime::Context* context,
        const char* name, const char* dataGroupId);

    FFI_EXPORT int64_t FfiOHOSPreferencesGetPreferencesV1(int64_t ctxId, const char* name,
        const char* dataGroupId, int32_t* errCode);

    FFI_EXPORT int32_t FfiOHOSPreferencesDeletePreferencesV1(int64_t ctxId, const char* name,
        const char* dataGroupId);

    FFI_EXPORT int32_t FfiOHOSPreferencesRemovePreferencesFromCacheV1(int64_t ctxId,
        const char* name, const char* dataGroupId);

    FFI_EXPORT int32_t FfiOHOSPreferencesDelete(int64_t id, const char* key);

    FFI_EXPORT bool FfiOHOSPreferencesHas(int64_t id, const char* key);

    FFI_EXPORT int32_t FfiOHOSPreferencesOn(int64_t id, const char* mode, void (*callbackRef)(const char* valueRef));

    FFI_EXPORT int32_t FfiOHOSPreferencesOff(int64_t id, const char* mode, void (*callbackRef)(const char* valueRef));

    FFI_EXPORT int32_t FfiOHOSPreferencesOffAll(int64_t id, const char* mode);

    FFI_EXPORT ValueType FfiOHOSPreferencesGet(int64_t id, const char* key, ValueType defValue);

    FFI_EXPORT int32_t FfiOHOSPreferencesPut(int64_t id, const char* key, ValueType value);

    FFI_EXPORT ValueTypes FfiOHOSPreferencesGetAll(int64_t id);

    FFI_EXPORT void FfiOHOSPreferencesFlush(int64_t id);

    FFI_EXPORT void FfiOHOSPreferencesClear(int64_t id);

    FFI_EXPORT void FfiOHOSPreferencesFreeValueType(ValueType* pValue);

    FFI_EXPORT void FfiOHOSPreferencesFreeValueTypes(ValueTypes* pValues);
}

} // namespace Preferences
} // namespace OHOS

#endif