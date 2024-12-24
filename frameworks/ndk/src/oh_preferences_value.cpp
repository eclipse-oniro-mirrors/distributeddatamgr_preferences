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
#include "oh_preferences_value.h"

#include "log_print.h"
#include "oh_preferences_err_code.h"
#include "oh_preferences_impl.h"
#include "oh_preferences_value_impl.h"
#include "securec.h"

using namespace OHOS::PreferencesNdk;

static OH_PreferencesValueImpl *GetSelf(const OH_PreferencesValue *value)
{
    if (value == nullptr ||
        !NDKPreferencesUtils::PreferencesStructValidCheck(
            value->cid, PreferencesNdkStructId::PREFERENCES_OH_VALUE_CID)) {
        LOG_ERROR("preferences_value invalid, value is null: %{public}d", (value == nullptr));
        return nullptr;
    }
    OH_PreferencesValue *prefValue = const_cast<OH_PreferencesValue *>(value);
    return static_cast<OH_PreferencesValueImpl *>(prefValue);
}

const char *OH_PreferencesPair_GetKey(const OH_PreferencesPair *pairs, uint32_t index)
{
    if (pairs == nullptr || index >= pairs[0].maxIndex) {
        LOG_ERROR("failed to get key from pair, pairs is null or index over limit");
        return nullptr;
    }

    if (!NDKPreferencesUtils::PreferencesStructValidCheck(
        pairs[index].cid, PreferencesNdkStructId::PREFERENCES_OH_PAIR_CID)) {
        LOG_ERROR("cid error when get key from pair, cid: %{public}ld", static_cast<long>(pairs[index].cid));
        return nullptr;
    }
    return pairs[index].key;
}

const OH_PreferencesValue *OH_PreferencesPair_GetPreferencesValue(const OH_PreferencesPair *pairs, uint32_t index)
{
    if (pairs == nullptr || index >= pairs[0].maxIndex) {
        LOG_ERROR("failed to get value from pair, pairs is null or index over limit");
        return nullptr;
    }

    if (!NDKPreferencesUtils::PreferencesStructValidCheck(
        pairs[index].cid, PreferencesNdkStructId::PREFERENCES_OH_PAIR_CID)) {
        LOG_ERROR("cid error when get value from pair, cid: %{public}ld", static_cast<long>(pairs[index].cid));
        return nullptr;
    }
    return pairs[index].value;
}

Preference_ValueType OH_PreferencesValue_GetValueType(const OH_PreferencesValue *object)
{
    auto self = GetSelf(object);
    if (self == nullptr) {
        LOG_ERROR("Preferences GetValueType failed, object is null");
        return Preference_ValueType::PREFERENCE_TYPE_NULL;
    }
    if (self->value_.IsInt()) {
        return Preference_ValueType::PREFERENCE_TYPE_INT;
    } else if (self->value_.IsBool()) {
        return Preference_ValueType::PREFERENCE_TYPE_BOOL;
    } else if (self->value_.IsString()) {
        return Preference_ValueType::PREFERENCE_TYPE_STRING;
    }
    return Preference_ValueType::PREFERENCE_TYPE_NULL;
}

int OH_PreferencesValue_GetInt(const OH_PreferencesValue *object, int *value)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr) {
        LOG_ERROR("Preferences GetInt failed, object is null: %{public}d, value is null: %{public}d, err: %{public}d",
            (self == nullptr), (value == nullptr), OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (self->value_.IsInt()) {
        *value = (int)(self->value_);
        return OH_Preferences_ErrCode::PREFERENCES_OK;
    }
    LOG_ERROR("Preferences GetInt failed, type error, err: %{public}d",
        OH_Preferences_ErrCode::PREFERENCES_ERROR_KEY_NOT_FOUND);
    return OH_Preferences_ErrCode::PREFERENCES_ERROR_KEY_NOT_FOUND;
}

int OH_PreferencesValue_GetBool(const OH_PreferencesValue *object, bool *value)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr) {
        LOG_ERROR("Preferences GetBool failed, object is null: %{public}d, value is null: %{public}d, err: %{public}d",
            (self == nullptr), (self == nullptr), OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (self->value_.IsBool()) {
        *value = (bool)(self->value_);
        return OH_Preferences_ErrCode::PREFERENCES_OK;
    }
    LOG_ERROR("Preferences GetBool failed, type error, err: %{public}d",
        OH_Preferences_ErrCode::PREFERENCES_ERROR_KEY_NOT_FOUND);
    return OH_Preferences_ErrCode::PREFERENCES_ERROR_KEY_NOT_FOUND;
}

int OH_PreferencesValue_GetString(const OH_PreferencesValue *object, char **value, uint32_t *valueLen)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr || valueLen == nullptr) {
        LOG_ERROR("Preferences GetString failed, object is null: %{public}d, value is null: %{public}d, "
            "valueLen is null: %{public}d, err: %{public}d", (self == nullptr), (value == nullptr),
            (valueLen == nullptr), OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (self->value_.IsString()) {
        std::string str = (std::string)(self->value_);
        size_t strLen = str.size();
        if (strLen >= SIZE_MAX) {
            LOG_ERROR("string length overlimit: %{public}zu", strLen);
            return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
        }
        void *ptr = malloc(strLen + 1); // free by caller
        if (ptr == nullptr) {
            LOG_ERROR("malloc failed when value get string, errno: %{public}d", errno);
            return OH_Preferences_ErrCode::PREFERENCES_ERROR_MALLOC;
        }

        int sysErr = memset_s(ptr, (strLen + 1), 0, (strLen + 1));
        if (sysErr != EOK) {
            LOG_ERROR("memset failed when value get string, errCode: %{public}d", sysErr);
        }
        if (strLen > 0) {
            sysErr = memcpy_s(ptr, strLen, str.c_str(), strLen);
            if (sysErr != EOK) {
                LOG_ERROR("memcpy failed when value get string, errCode: %{public}d", sysErr);
                free(ptr);
                return OH_Preferences_ErrCode::PREFERENCES_ERROR_MALLOC;
            }
        }
        *value = reinterpret_cast<char *>(ptr);
        *valueLen = strLen + 1;
        return OH_Preferences_ErrCode::PREFERENCES_OK;
    }
    LOG_ERROR("Preferences GetString failed, type error, err: %{public}d",
        OH_Preferences_ErrCode::PREFERENCES_ERROR_KEY_NOT_FOUND);
    return OH_Preferences_ErrCode::PREFERENCES_ERROR_KEY_NOT_FOUND;
}
