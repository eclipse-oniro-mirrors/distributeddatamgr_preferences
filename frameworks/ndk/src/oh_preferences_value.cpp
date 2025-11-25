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
    } else if (self->value_.IsLong()) {
        return Preference_ValueType::PREFERENCE_TYPE_INT64;
    } else if (self->value_.IsDouble()) {
        return Preference_ValueType::PREFERENCE_TYPE_DOUBLE;
    } else if (self->value_.IsBoolArray()) {
        return Preference_ValueType::PREFERENCE_TYPE_BOOL_ARRAY;
    } else if (self->value_.IsStringArray()) {
        return Preference_ValueType::PREFERENCE_TYPE_STRING_ARRAY;
    } else if (self->value_.IsDoubleArray()) {
        return Preference_ValueType::PREFERENCE_TYPE_DOUBLE_ARRAY;
    } else if (self->value_.IsUint8Array()) {
        return Preference_ValueType::PREFERENCE_TYPE_BLOB;
    } else if (self->value_.IsIntArray()) {
        return Preference_ValueType::PREFERENCE_TYPE_INT_ARRAY;
    } else if (self->value_.IsInt64Array()) {
        return Preference_ValueType::PREFERENCE_TYPE_INT64_ARRAY;
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
        void *ptr = malloc(strLen + 1);
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

void OH_PreferencesPair_Destroy(OH_PreferencesPair *pairs, uint32_t count)
{
    if (pairs == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < count; ++i) {
        if (pairs[i].key != nullptr) {
            delete(pairs[i].key);
        }
        OH_PreferencesValue_Destroy(const_cast<OH_PreferencesValue*>(pairs[i].value));
    }
    free(pairs);
}

OH_PreferencesValue* OH_PreferencesValue_Create(void)
{
    OH_PreferencesValue *impl = new (std::nothrow) OH_PreferencesValueImpl();
    if (impl == nullptr) {
        LOG_ERROR("Failed to create OH_PreferencesValue");
        return nullptr;
    }
    impl->cid = PreferencesNdkStructId::PREFERENCES_OH_VALUE_CID;
    return impl;
}

void OH_PreferencesValue_Destroy(OH_PreferencesValue *value)
{
    if (value == nullptr ||
        !NDKPreferencesUtils::PreferencesStructValidCheck(
            value->cid, PreferencesNdkStructId::PREFERENCES_OH_VALUE_CID)) {
        LOG_ERROR("destroy value failed, value is null: %{public}d, errCode: %{public}d",
            (value == nullptr), OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM);
        return;
    }
    delete static_cast<OH_PreferencesValueImpl*>(value);
}

int OH_PreferencesValue_SetInt(const OH_PreferencesValue *object, int value)
{
    auto self = GetSelf(object);
    if (self == nullptr) {
        LOG_ERROR("SetInt failed: object is null");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    self->value_ = OHOS::NativePreferences::PreferencesValue(value);
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesValue_SetBool(const OH_PreferencesValue *object, bool value)
{
    auto self = GetSelf(object);
    if (self == nullptr) {
        LOG_ERROR("SetBool failed: object is null");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    self->value_ = OHOS::NativePreferences::PreferencesValue(value);
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesValue_SetString(const OH_PreferencesValue *object, const char *value)
{
    auto self = GetSelf(object);
    if (self == nullptr) {
        LOG_ERROR("SetString failed: object is null");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (value == nullptr) {
        LOG_ERROR("SetString failed: input string is null");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    self->value_ = OHOS::NativePreferences::PreferencesValue(std::string(value));
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesValue_SetInt64(const OH_PreferencesValue *object, int64_t value)
{
    auto self = GetSelf(object);
    if (self == nullptr) {
        LOG_ERROR("SetInt64 failed: object is null");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    self->value_ = OHOS::NativePreferences::PreferencesValue(value);
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesValue_SetDouble(const OH_PreferencesValue *object, double value)
{
    auto self = GetSelf(object);
    if (self == nullptr) {
        LOG_ERROR("SetDouble failed: object is null");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    self->value_ = OHOS::NativePreferences::PreferencesValue(value);
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

template<typename T>
static int CopyArrayOut(const std::vector<T>& src, T** outArray, uint32_t* outCount)
{
    if (outArray == nullptr || outCount == nullptr) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    size_t count = src.size();
    if (count > UINT32_MAX) {
        LOG_ERROR("Array size too large");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    T* ptr = static_cast<T*>(malloc(sizeof(T) * count));
    if (ptr == nullptr) {
        LOG_ERROR("malloc failed for array, errno: %{public}d", errno);
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_MALLOC;
    }
    for (size_t i = 0; i < count; ++i) {
        ptr[i] = src[i];
    }
    *outArray = ptr;
    *outCount = static_cast<uint32_t>(count);
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesValue_SetIntArray(const OH_PreferencesValue *object, const int *value, uint32_t count)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    std::vector<int> vec(value, value + count);
    self->value_ = vec;
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesValue_SetDoubleArray(const OH_PreferencesValue *object, const double *value, uint32_t count)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    std::vector<double> vec(value, value + count);
    self->value_ = OHOS::NativePreferences::PreferencesValue(vec);
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesValue_SetBoolArray(const OH_PreferencesValue *object, const bool *value, uint32_t count)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    std::vector<bool> vec(value, value + count);
    self->value_ = OHOS::NativePreferences::PreferencesValue(vec);
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesValue_SetStringArray(const OH_PreferencesValue *object, const char **value, uint32_t count)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    std::vector<std::string> vec;
    for (uint32_t i = 0; i < count; ++i) {
        if (value[i] == nullptr) {
            LOG_ERROR("Null string in string array at index %{public}u", i);
            return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
        }
        vec.emplace_back(value[i]);
    }
    self->value_ = OHOS::NativePreferences::PreferencesValue(vec);
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesValue_SetInt64Array(const OH_PreferencesValue *object, const int64_t *value, uint32_t count)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr || count == 0) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    std::vector<int64_t> vec(value, value + count);
    self->value_ = vec;
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesValue_SetBlob(const OH_PreferencesValue *object, const uint8_t *value, uint32_t count)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    std::vector<uint8_t> vec(value, value + count);
    self->value_ = OHOS::NativePreferences::PreferencesValue(vec);
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesValue_GetInt64(const OH_PreferencesValue *object, int64_t *value)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr) {
        LOG_ERROR("GetInt64 failed: invalid param");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (self->value_.IsLong()) {
        *value = (int64_t)(self->value_);
        return OH_Preferences_ErrCode::PREFERENCES_OK;
    }
    LOG_ERROR("GetInt64 failed: type mismatch");
    return OH_Preferences_ErrCode::PREFERENCES_ERROR_KEY_NOT_FOUND;
}

int OH_PreferencesValue_GetDouble(const OH_PreferencesValue *object, double *value)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr) {
        LOG_ERROR("GetDouble failed: invalid param");
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (self->value_.IsDouble()) {
        *value = (double)(self->value_);
        return OH_Preferences_ErrCode::PREFERENCES_OK;
    }
    LOG_ERROR("GetDouble failed: type mismatch");
    return OH_Preferences_ErrCode::PREFERENCES_ERROR_KEY_NOT_FOUND;
}

int OH_PreferencesValue_GetIntArray(const OH_PreferencesValue *object, int **value, uint32_t *count)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr || count == nullptr) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    if (self->value_.IsIntArray()) {
        std::vector<int> vec = (std::vector<int>)(self->value_);
        return CopyArrayOut(vec, value, count);
    }
    return OH_Preferences_ErrCode::PREFERENCES_ERROR_KEY_NOT_FOUND;
}

int OH_PreferencesValue_GetBoolArray(const OH_PreferencesValue *object, bool **value, uint32_t *count)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr || count == nullptr) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (self->value_.IsBoolArray()) {
        std::vector<bool> vec = (std::vector<bool>)(self->value_);
        if (CopyArrayOut(vec, value, count) != OH_Preferences_ErrCode::PREFERENCES_OK) {
            return OH_Preferences_ErrCode::PREFERENCES_ERROR_MALLOC;
        }
        return OH_Preferences_ErrCode::PREFERENCES_OK;
    }
    return OH_Preferences_ErrCode::PREFERENCES_ERROR_KEY_NOT_FOUND;
}

int OH_PreferencesValue_GetStringArray(const OH_PreferencesValue *object, char ***value, uint32_t *count)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr || count == nullptr) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (!(self->value_.IsStringArray())) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_KEY_NOT_FOUND;
    }

    std::vector<std::string> vec = (std::vector<std::string>)(self->value_);
    if (vec.size() == 0) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    char** arrary = static_cast<char**>(malloc(sizeof(char*) * vec.size()));
    if (arrary == nullptr) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_MALLOC;
    }

    for (size_t i = 0; i < vec.size(); ++i) {
        const std::string& s = vec[i];
        char* str = static_cast<char*>(malloc(s.size() + 1));
        if (str == nullptr) {
            for (size_t j = 0; j < i; ++j) {
                free(arrary[j]);
            }
            free(arrary);
            return OH_Preferences_ErrCode::PREFERENCES_ERROR_MALLOC;
        }
        if (memcpy_s(str, s.size() + 1, s.c_str(), s.size() + 1) != EOK) {
            free(str);
            for (size_t j = 0; j < i; ++j) {
                free(arrary[j]);
            }
            free(arrary);
            return OH_Preferences_ErrCode::PREFERENCES_ERROR_MALLOC;
        }
        arrary[i] = str;
    }
    *value = arrary;
    *count = static_cast<uint32_t>(vec.size());
    return OH_Preferences_ErrCode::PREFERENCES_OK;
}

int OH_PreferencesValue_GetInt64Array(const OH_PreferencesValue *object, int64_t **value, uint32_t *count)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr || count == nullptr) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }

    if (self->value_.IsInt64Array()) {
        std::vector<int64_t> vec = (std::vector<int64_t>)(self->value_);
        return CopyArrayOut(vec, value, count);
    }
    return OH_Preferences_ErrCode::PREFERENCES_ERROR_KEY_NOT_FOUND;
}

int OH_PreferencesValue_GetDoubleArray(const OH_PreferencesValue *object, double **value, uint32_t *count)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr || count == nullptr) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (self->value_.IsDoubleArray()) {
        std::vector<double> vec = (std::vector<double>)(self->value_);
        return CopyArrayOut(vec, value, count);
    }
    return OH_Preferences_ErrCode::PREFERENCES_ERROR_KEY_NOT_FOUND;
}

int OH_PreferencesValue_GetBlob(const OH_PreferencesValue *object, uint8_t **value, uint32_t *count)
{
    auto self = GetSelf(object);
    if (self == nullptr || value == nullptr || count == nullptr) {
        return OH_Preferences_ErrCode::PREFERENCES_ERROR_INVALID_PARAM;
    }
    if (self->value_.IsUint8Array()) {
        std::vector<uint8_t> vec = (std::vector<uint8_t>)(self->value_);
        return CopyArrayOut(vec, value, count);
    }
    return OH_Preferences_ErrCode::PREFERENCES_ERROR_KEY_NOT_FOUND;
}