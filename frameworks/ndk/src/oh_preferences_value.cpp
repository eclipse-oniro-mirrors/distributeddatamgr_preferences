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

using namespace OHOS::PreferencesNdk;

static OH_PreferencesValueImpl *GetSelf(const OH_PreferencesValue *value)
{
    if (value == nullptr) {
        LOG_ERROR("preferences_value invalid, which is null");
        return nullptr;
    }
    OH_PreferencesValue *prefValue = const_cast<OH_PreferencesValue *>(value);
    OH_PreferencesValueImpl *self = static_cast<OH_PreferencesValueImpl *>(prefValue);
    if (self->value_.IsInt()) {
        self->type_ = Preference_ValueType::TYPE_INT;
    } else if (self->value_.IsBool()) {
        self->type_ = Preference_ValueType::TYPE_BOOL;
    } else if (self->value_.IsString()) {
        self->type_ = Preference_ValueType::TYPE_STRING;
    } else {
        return nullptr;
    }
    return self;
}

const char *OH_PreferencesPair_GetKey(const OH_PreferencesPair *pairs, uint32_t index)
{
    if (pairs == nullptr) {
        return nullptr;
    }
    return pairs[index].key;
}

const OH_PreferencesValue *OH_PreferencesPair_GetPreferencesValue(const OH_PreferencesPair *pairs, uint32_t index)
{
    if (pairs == nullptr) {
        return nullptr;
    }
    return pairs[index].value;
}

Preference_ValueType OH_PreferencesValue_GetValueType(const OH_PreferencesValue *object)
{
    auto self = GetSelf(object);
    if (self == nullptr) {
        LOG_ERROR("Preferences GetValueType failed, object is null");
        return Preference_ValueType::TYPE_NULL;
    }
    return self->type_;
}

int OH_PreferencesValue_GetInt(const OH_PreferencesValue *object, int *value)
{
    auto self = GetSelf(object);
    if (self == nullptr) {
        LOG_ERROR("Preferences GetInt failed, object is null");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (self->type_ == Preference_ValueType::TYPE_INT) {
        *value = std::get<int>(self->value_.value_);
        return OH_Preferences_ErrCode::PREFERENCES_OK;
    }
    LOG_ERROR("Preferences GetInt failed, type: %{public}d", self->type_);
    return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
}

int OH_PreferencesValue_GetBool(const OH_PreferencesValue *object, bool *value)
{
    auto self = GetSelf(object);
    if (self == nullptr) {
        LOG_ERROR("Preferences GetBool failed, object is null");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (self->type_ == Preference_ValueType::TYPE_BOOL) {
        *value = std::get<bool>(self->value_.value_);
        return OH_Preferences_ErrCode::PREFERENCES_OK;
    }
    LOG_ERROR("Preferences GetBool failed, type: %{public}d", self->type_);
    return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
}

int OH_PreferencesValue_GetString(const OH_PreferencesValue *object, char **value, uint32_t *valueLen)
{
    auto self = GetSelf(object);
    if (self == nullptr) {
        LOG_ERROR("Preferences GetString failed, object is null");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (self->type_ == Preference_ValueType::TYPE_STRING) {
        std::string str = (std::string)(self->value_);
        void *ptr = malloc(str.size() + 1); // free by caller
        if (ptr == nullptr) {
            LOG_ERROR("malloc failed when value get string, errno: %{public}d", errno);
            return OH_Preferences_ErrCode::PREFERENCES_ERROR_MALLOC;
        }
        *value = (char *)ptr;
        for (size_t i = 0; i < str.size() + 1; i++) {
            (*value)[i] = (char)str[i];
        }
        (*value)[str.size()] = '\0';
        *valueLen = str.size() + 1;
        return OH_Preferences_ErrCode::PREFERENCES_OK;
    }
    LOG_ERROR("Preferences GetString failed, type: %{public}d", self->type_);
    return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
}
