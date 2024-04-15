/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "preferences_value_parcel.h"

#include "log_print.h"
#include "preferences_errno.h"
#include "securec.h"

namespace OHOS {
namespace NativePreferences {

uint8_t PreferencesValueParcel::GetTypeIndex(const PreferencesValue &value)
{
    if (value.IsInt()) {
        return INT_TYPE;
    } else if (value.IsLong()) {
        return LONG_TYPE;
    } else if (value.IsFloat()) {
        return FLOAT_TYPE;
    } else if (value.IsDouble()) {
        return DOUBLE_TYPE;
    } else if (value.IsBool()) {
        return BOOL_TYPE;
    } else if (value.IsString()) {
        return STRING_TYPE;
    } else if (value.IsStringArray()) {
        return STRING_ARRAY_TYPE;
    } else if (value.IsBoolArray()) {
        return BOOL_ARRAY_TYPE;
    } else if (value.IsDoubleArray()) {
        return DOUBLE_ARRAY_TYPE;
    } else if (value.IsUint8Array()) {
        return UINT8_ARRAY_TYPE;
    } else if (value.IsObject()) {
        return OBJECT_TYPE;
    } else {
        return BIG_INT_TYPE;
    }
}

uint32_t PreferencesValueParcel::CalSize(PreferencesValue value)
{
    uint8_t type = GetTypeIndex(value);
    switch (type) {
        case INT_TYPE:
            return sizeof(uint8_t) + sizeof(int);
        case LONG_TYPE:
            return sizeof(uint8_t) + sizeof(int64_t);
        case FLOAT_TYPE:
            return sizeof(uint8_t) + sizeof(float);
        case DOUBLE_TYPE:
            return sizeof(uint8_t) + sizeof(double);
        case BOOL_TYPE:
            return sizeof(uint8_t) + sizeof(bool);
        case OBJECT_TYPE:
        case STRING_TYPE: {
            uint32_t strLen = sizeof(uint8_t) + sizeof(size_t);
            strLen += (type == STRING_TYPE) ? std::get<std::string>(value.value_).size() :
                std::get<Object>(value.value_).valueStr.size();
            return  strLen;
        }
        case BOOL_ARRAY_TYPE:
            return sizeof(uint8_t) + sizeof(size_t) + std::get<std::vector<bool>>(value.value_).size() * sizeof(bool);
        case DOUBLE_ARRAY_TYPE:
            return sizeof(uint8_t) + sizeof(size_t) +
                std::get<std::vector<double>>(value.value_).size() * sizeof(double);
        case UINT8_ARRAY_TYPE:
            return sizeof(uint8_t) + sizeof(size_t) +
                ((std::get<std::vector<uint8_t>>(value.value_).size()) * sizeof(uint8_t));
        case STRING_ARRAY_TYPE: {
            uint32_t strArrBlobLen = sizeof(uint8_t) + sizeof(size_t);
            std::vector<std::string> strVec = std::get<std::vector<std::string>>(value.value_);

            for (size_t i = 0; i < strVec.size(); i++) {
                strArrBlobLen += sizeof(size_t);
                strArrBlobLen += strVec[i].size();
            }
            return strArrBlobLen;
        }
        case BIG_INT_TYPE:
            return sizeof(uint8_t) + sizeof(size_t) + sizeof(int64_t) +
                std::get<BigInt>(value.value_).words_.size() * sizeof(uint64_t);
        default:
            break;
    }
    return 0;
}

int PreferencesValueParcel::MarshallingBasicValueInner(const PreferencesValue &value, const uint8_t type,
    std::vector<uint8_t> &data)
{
    uint8_t *startAddr = data.data();
    size_t basicDataLen = 0;
    if (data.size() <= sizeof(uint8_t)) {
        LOG_ERROR("memcpy error when marshalling basic value, type: %d", type);
        return E_ERROR;
    }
    size_t memLen = data.size() - sizeof(uint8_t);
    int errCode = E_OK;
    switch (type) {
        case INT_TYPE: {
            int intValue = std::get<int>(value.value_);
            basicDataLen = sizeof(int);
            errCode = memcpy_s(startAddr + sizeof(uint8_t), memLen, &intValue, basicDataLen);
            break;
        }
        case LONG_TYPE: {
            int64_t longValue = std::get<int64_t>(value.value_);
            basicDataLen = sizeof(int64_t);
            errCode = memcpy_s(startAddr + sizeof(uint8_t), memLen, &longValue, basicDataLen);
            break;
        }
        case FLOAT_TYPE: {
            float floatValue = std::get<float>(value.value_);
            basicDataLen = sizeof(float);
            errCode = memcpy_s(startAddr + sizeof(uint8_t), memLen, &floatValue, basicDataLen);
            break;
        }
        case DOUBLE_TYPE: {
            double doubleValue = std::get<double>(value.value_);
            basicDataLen = sizeof(double);
            errCode = memcpy_s(startAddr + sizeof(uint8_t), memLen, &doubleValue, basicDataLen);
            break;
        }
        case BOOL_TYPE: {
            bool boolValue = std::get<bool>(value.value_);
            basicDataLen = sizeof(bool);
            errCode = memcpy_s(startAddr + sizeof(uint8_t), memLen, &boolValue, basicDataLen);
            break;
        }
        default:
            break;
    }
    
    if (errCode != E_OK) {
        LOG_ERROR("memcpy failed when marshalling basic value, %d", errCode);
        return E_ERROR;
    }
    return E_OK;
}

/**
 *     ------------------------
 *     |  type  |   BasicData   |
 *     ------------------------
 * len:  uint8_t   sizeof(int) or size of(Bool) e.g.
*/
int PreferencesValueParcel::MarshallingBasicValue(const PreferencesValue &value, const uint8_t type,
    std::vector<uint8_t> &data)
{
    uint8_t *startAddr = data.data();
    int errCode = memcpy_s(startAddr, data.size(), &type, sizeof(uint8_t));
    if (errCode != E_OK) {
        LOG_ERROR("memcpy failed when marshalling basic value's type, %d", errCode);
        return E_NOT_SUPPORTED;
    }
    return MarshallingBasicValueInner(value, type, data);
}

/**
 *     -------------------------------------
 *     |  type  |   strLen   |   strData   |
 *     -------------------------------------
 * len:  uint8_t   size_t        strLen
*/
int PreferencesValueParcel::MarshallingStringValue(const PreferencesValue &value, const uint8_t type,
    std::vector<uint8_t> &data)
{
    std::string stringValue;
    if (type == OBJECT_TYPE) {
        Object objValue = std::get<Object>(value.value_);
        stringValue = objValue.valueStr;
    } else {
        // it's string type
        stringValue = std::get<std::string>(value.value_);
    }
    uint8_t *startAddr = data.data();
    int errCode = memcpy_s(startAddr, sizeof(uint8_t), &type, sizeof(uint8_t));
    if (errCode != E_OK) {
        LOG_ERROR("memcpy failed when marshalling string value's type, %d", errCode);
        return -E_ERROR;
    }
    size_t strLen = stringValue.size();
    errCode = memcpy_s(startAddr + sizeof(uint8_t), sizeof(size_t), &strLen, sizeof(size_t));
    if (errCode != E_OK) {
        LOG_ERROR("memcpy failed when marshalling string value's str len, %d", errCode);
        return -E_ERROR;
    }
    errCode = memcpy_s(startAddr + sizeof(uint8_t) + sizeof(size_t), strLen,
        stringValue.c_str(), strLen);
    if (errCode != E_OK) {
        LOG_ERROR("memcpy failed when marshalling string value's str data, %d", errCode);
        return -E_ERROR;
    }
    return E_OK;
}

/**
 *     --------------------------------------------------------------------
 *     |  type  |   vec_num   |  len1  |  str1  |  len2  |  str2  |  ...  |
 *     --------------------------------------------------------------------
 * len:  uint8_t   size_t        sizet     len1    size_t   len2
*/
int PreferencesValueParcel::MarshallingStringArrayValue(const PreferencesValue &value, const uint8_t type,
    std::vector<uint8_t> &data)
{
    std::vector<std::string> strVec = std::get<std::vector<std::string>>(value.value_);
    uint8_t *startAddr = data.data();
    // write type into data
    int errCode = memcpy_s(startAddr, sizeof(uint8_t), &type, sizeof(uint8_t));
    if (errCode != E_OK) {
        LOG_ERROR("memcpy failed when marshalling string array value's type, %d", errCode);
        return -E_ERROR;
    }
    startAddr += sizeof(uint8_t);

    // write vector size into data
    size_t vecNum = strVec.size();
    errCode = memcpy_s(startAddr, sizeof(size_t), &vecNum, sizeof(size_t));
    if (errCode != E_OK) {
        LOG_ERROR("memcpy failed when marshalling string array value's vector num, %d", errCode);
        return -E_ERROR;
    }
    startAddr += sizeof(size_t);

    // write every single str into data
    for (size_t i = 0; i < vecNum; i++) {
        size_t strLen = strVec[i].size();
        errCode = memcpy_s(startAddr, sizeof(size_t), &strLen, sizeof(size_t));
        if (errCode != E_OK) {
            LOG_ERROR("memcpy failed when marshalling string array value's str len, %d", errCode);
            return -E_ERROR;
        }
        startAddr += sizeof(size_t);

        errCode = memcpy_s(startAddr, strLen, strVec[i].c_str(), strLen);
        if (errCode != E_OK) {
            LOG_ERROR("memcpy failed when marshalling string array value's str data, %d", errCode);
            return -E_ERROR;
        }
        startAddr += strLen;
    }
    return E_OK;
}

int PreferencesValueParcel::MarshallingVecUInt8AfterType(const PreferencesValue &value, uint8_t *startAddr)
{
    std::vector<uint8_t> vec = std::get<std::vector<uint8_t>>(value.value_);
    size_t vecNum = vec.size();
    // write vec num
    int errCode = memcpy_s(startAddr, sizeof(size_t), &vecNum, sizeof(size_t));
    if (errCode != E_OK) {
        LOG_ERROR("memcpy failed when marshalling uint8 array value's vector num, %d", errCode);
        return E_ERROR;
    }
    startAddr += sizeof(size_t);
    errCode = memcpy_s(startAddr, vecNum * sizeof(uint8_t), vec.data(), vecNum * sizeof(uint8_t));
    if (errCode != E_OK) {
        LOG_ERROR("memcpy failed when marshalling uint8 array value's data, %d", errCode);
        return E_ERROR;
    }
    return errCode;
}

/**
 *     --------------------------------------------------------------------------
 *     |  type  |  vec_num  |    sign    |     data1     |     data2     | .... |
 *     --------------------------------------------------------------------------
 * len:  uint8_t   size_t   sizeof(int64_t)  sizeof(int64_t)    sizeof(int64_t)
*/
int PreferencesValueParcel::MarshallingVecBigIntAfterType(const PreferencesValue &value, uint8_t *startAddr)
{
    BigInt bigIntValue = std::get<BigInt>(value.value_);
    int64_t sign = static_cast<int64_t>(bigIntValue.sign_);
    std::vector<uint64_t> words = bigIntValue.words_;

    // write vec num
    size_t vecNum = words.size();
    int errCode = memcpy_s(startAddr, sizeof(size_t), &vecNum, sizeof(size_t));
    if (errCode != E_OK) {
        LOG_ERROR("memcpy failed when marshalling bigInt array value's vector num, %d", errCode);
        return E_ERROR;
    }
    startAddr += sizeof(size_t);

    // write sign
    errCode = memcpy_s(startAddr, sizeof(int64_t), &sign, sizeof(int64_t));
    if (errCode != E_OK) {
        LOG_ERROR("memcpy failed when marshalling bigInt array value's sign, %d", errCode);
        return E_ERROR;
    }
    startAddr += sizeof(int64_t);

    // write vec element
    for (size_t i = 0; i < vecNum; i++) {
        uint64_t item = words[i];
        errCode = memcpy_s(startAddr, sizeof(uint64_t), &item, sizeof(uint64_t));
        if (errCode != E_OK) {
            LOG_ERROR("memcpy failed when marshalling bigInt array value's words, %d", errCode);
            return E_ERROR;
        }
        startAddr += sizeof(uint64_t);
    }
    return errCode;
}

int PreferencesValueParcel::MarshallingVecDoubleAfterType(const PreferencesValue &value, uint8_t *startAddr)
{
    std::vector<double> vec = std::get<std::vector<double>>(value.value_);
    size_t vecNum = vec.size();
    // write vec num
    int errCode = memcpy_s(startAddr, sizeof(size_t), &vecNum, sizeof(size_t));
    if (errCode != E_OK) {
        LOG_ERROR("memcpy failed when marshalling double array value's vector num, %d", errCode);
        return E_ERROR;
    }
    startAddr += sizeof(size_t);

    // write vec element
    for (size_t i = 0; i < vecNum; i++) {
        double item = vec[i];
        errCode = memcpy_s(startAddr, sizeof(double), &item, sizeof(double));
        if (errCode != E_OK) {
            LOG_ERROR("memcpy failed when marshalling double array value's vector data, %d", errCode);
            return E_ERROR;
        }
        startAddr += sizeof(double);
    }
    return errCode;
}

int PreferencesValueParcel::MarshallingVecBoolAfterType(const PreferencesValue &value, uint8_t *startAddr)
{
    const std::vector<bool> vec = std::get<std::vector<bool>>(value.value_);
    size_t vecNum = vec.size();
    // write vec num
    int errCode = memcpy_s(startAddr, sizeof(size_t), &vecNum, sizeof(size_t));
    if (errCode != E_OK) {
        LOG_ERROR("memcpy failed when marshalling bool array value's vector num, %d", errCode);
        return E_ERROR;
    }
    startAddr += sizeof(size_t);

    // write vec element
    for (size_t i = 0; i < vecNum; i++) {
        bool item = vec[i];
        errCode = memcpy_s(startAddr, sizeof(bool), &item, sizeof(bool));
        if (errCode != E_OK) {
            LOG_ERROR("memcpy failed when marshalling bool array value's vector data, %d", errCode);
            return E_ERROR;
        }
        startAddr += sizeof(bool);
    }
    return errCode;
}

/**
 *     -----------------------------------------------------------------------
 *     |  type  |  vec_num  |    data1    |    data2    |    data3    | .... |
 *     ----------------------------------------------------------------------
 * len:  uint8_t   size_t     sizeof(typ)    sizeof(typ)
*/
int PreferencesValueParcel::MarshallingBasicArrayValue(const PreferencesValue &value, const uint8_t type,
    std::vector<uint8_t> &data)
{
    uint8_t *startAddr = data.data();
    int errCode = memcpy_s(startAddr, sizeof(uint8_t), &type, sizeof(uint8_t));
    if (errCode != E_OK) {
        LOG_ERROR("memcpy failed when marshalling basic array value's type, %d", errCode);
        return E_ERROR;
    }
    // write type
    startAddr += sizeof(uint8_t);

    switch (type) {
        case UINT8_ARRAY_TYPE:
            errCode = MarshallingVecUInt8AfterType(value, startAddr);
            break;
        case BIG_INT_TYPE:
            errCode = MarshallingVecBigIntAfterType(value, startAddr);
            break;
        case DOUBLE_ARRAY_TYPE:
            errCode = MarshallingVecDoubleAfterType(value, startAddr);
            break;
        case BOOL_ARRAY_TYPE:
            errCode = MarshallingVecBoolAfterType(value, startAddr);
            break;
        default:
            errCode = E_INVALID_ARGS;
            break;
    }
    return errCode;
}

int PreferencesValueParcel::MarshallingPreferenceValue(const PreferencesValue &value, std::vector<uint8_t> &data)
{
    int errCode = E_OK;
    uint8_t type = GetTypeIndex(value);
    switch (type) {
        case INT_TYPE:
        case LONG_TYPE:
        case FLOAT_TYPE:
        case DOUBLE_TYPE:
        case BOOL_TYPE:
            errCode = MarshallingBasicValue(value, type, data);
            break;
        case STRING_TYPE:
        case OBJECT_TYPE:
            errCode = MarshallingStringValue(value, type, data);
            break;
        case STRING_ARRAY_TYPE:
            errCode = MarshallingStringArrayValue(value, type, data);
            break;
        case UINT8_ARRAY_TYPE:
        case BIG_INT_TYPE:
        case DOUBLE_ARRAY_TYPE:
        case BOOL_ARRAY_TYPE:
            errCode = MarshallingBasicArrayValue(value, type, data);
            break;
        default:
            errCode = E_INVALID_ARGS;
            LOG_ERROR("MarshallingPreferenceValue failed, type invalid, %d", errCode);
            break;
    }
    return errCode;
}

std::pair<int, PreferencesValue> PreferencesValueParcel::UnmarshallingBasicValue(const uint8_t type,
    const std::vector<uint8_t> &data)
{
    const uint8_t *startAddr = data.data();
    switch (type) {
        case INT_TYPE: {
            const int intValue = *(reinterpret_cast<const int *>(startAddr + sizeof(uint8_t)));
            return std::make_pair(E_OK, PreferencesValue(intValue));
        }
        case LONG_TYPE: {
            const int64_t longValue = *(reinterpret_cast<const int64_t *>(startAddr + sizeof(uint8_t)));
            return std::make_pair(E_OK, PreferencesValue(longValue));
        }
        case FLOAT_TYPE: {
            const float floatValue = *(reinterpret_cast<const float *>(startAddr + sizeof(uint8_t)));
            return std::make_pair(E_OK, PreferencesValue(floatValue));
        }
        case DOUBLE_TYPE: {
            const double doubleValue = *(reinterpret_cast<const double *>(startAddr + sizeof(uint8_t)));
            return std::make_pair(E_OK, PreferencesValue(doubleValue));
        }
        case BOOL_TYPE: {
            const bool boolValue = *(reinterpret_cast<const bool *>(startAddr + sizeof(uint8_t)));
            return std::make_pair(E_OK, PreferencesValue(boolValue));
        }
        default:
            break;
    }
    return std::make_pair(E_INVALID_ARGS, PreferencesValue(0));
}

std::pair<int, PreferencesValue> PreferencesValueParcel::UnmarshallingStringValue(const uint8_t type,
    const std::vector<uint8_t> &data)
{
    const uint8_t *startAddr = data.data();
    std::string strValue;
    size_t strLen = *(reinterpret_cast<const size_t *>(startAddr + sizeof(uint8_t)));
    strValue.resize(strLen);
    strValue.assign(startAddr + sizeof(uint8_t) + sizeof(size_t), startAddr + sizeof(uint8_t) + sizeof(size_t) +
        strLen);

    if (type == OBJECT_TYPE) {
        Object obj;
        obj.valueStr = strValue;
        return std::make_pair(E_OK, PreferencesValue(obj));
    } else if (type == STRING_TYPE) {
        return std::make_pair(E_OK, PreferencesValue(strValue));
    }
    return std::make_pair(E_INVALID_ARGS, PreferencesValue(0));
}

std::pair<int, PreferencesValue> PreferencesValueParcel::UnmarshallingStringArrayValue(const uint8_t type,
    const std::vector<uint8_t> &data)
{
    if (type != STRING_ARRAY_TYPE) {
        return std::make_pair(E_INVALID_ARGS, PreferencesValue(0));
    }

    const uint8_t *startAddr = data.data() + sizeof(uint8_t);
    size_t vecNum = *(reinterpret_cast<const size_t *>(startAddr));
    startAddr += sizeof(size_t);

    std::vector<std::string> strVec;
    strVec.resize(vecNum);
    for (size_t i = 0; i < vecNum; i++) {
        size_t strLen = *(reinterpret_cast<const size_t *>(startAddr));
        startAddr += sizeof(size_t);
        std::string strValue;
        strValue.resize(strLen);
        strValue.assign(startAddr, startAddr + strLen);
        strVec[i] = strValue;
        startAddr += strLen;
    }
    return std::make_pair(E_OK, PreferencesValue(strVec));
}

std::pair<int, PreferencesValue> PreferencesValueParcel::UnmarshallingVecUInt8(const std::vector<uint8_t> &data)
{
    const uint8_t *startAddr = data.data() + sizeof(uint8_t);
    size_t vecNum = *(reinterpret_cast<const size_t *>(startAddr));
    startAddr += sizeof(size_t);

    std::vector<uint8_t> vec;
    vec.resize(vecNum);
    for (size_t i = 0; i < vecNum; i++) {
        uint8_t element = *(reinterpret_cast<const uint8_t *>(startAddr));
        vec[i] = element;
        startAddr += sizeof(uint8_t);
    }
    return std::make_pair(E_OK, PreferencesValue(vec));
}

std::pair<int, PreferencesValue> PreferencesValueParcel::UnmarshallingVecDouble(const std::vector<uint8_t> &data)
{
    const uint8_t *startAddr = data.data() + sizeof(uint8_t);
    size_t vecNum = *(reinterpret_cast<const size_t *>(startAddr));
    startAddr += sizeof(size_t);

    std::vector<double> vec;
    vec.resize(vecNum);
    for (size_t i = 0; i < vecNum; i++) {
        double element = *(reinterpret_cast<const double *>(startAddr));
        vec[i] = element;
        startAddr += sizeof(double);
    }
    return std::make_pair(E_OK, PreferencesValue(vec));
}

std::pair<int, PreferencesValue> PreferencesValueParcel::UnmarshallingVecBool(const std::vector<uint8_t> &data)
{
    const uint8_t *startAddr = data.data() + sizeof(uint8_t);
    size_t vecNum = *(reinterpret_cast<const size_t *>(startAddr));
    startAddr += sizeof(size_t);

    std::vector<bool> vec;
    vec.resize(vecNum);
    for (size_t i = 0; i < vecNum; i++) {
        bool element = *(reinterpret_cast<const bool *>(startAddr));
        vec[i] = element;
        startAddr += sizeof(bool);
    }
    return std::make_pair(E_OK, PreferencesValue(vec));
}

std::pair<int, PreferencesValue> PreferencesValueParcel::UnmarshallingVecBigInt(const std::vector<uint8_t> &data)
{
    const uint8_t *startAddr = data.data() + sizeof(uint8_t);
    size_t vecNum = *(reinterpret_cast<const size_t *>(startAddr));
    startAddr += sizeof(size_t);

    int64_t sign = *(reinterpret_cast<const int64_t *>(startAddr));
    startAddr += sizeof(int64_t);

    std::vector<uint64_t> vec;
    vec.resize(vecNum);
    for (size_t i = 0; i < vecNum; i++) {
        uint64_t element = *(reinterpret_cast<const uint64_t *>(startAddr));
        vec[i] = element;
        startAddr += sizeof(uint64_t);
    }
    BigInt bigIntValue = BigInt(vec, sign);
    return std::make_pair(E_OK, PreferencesValue(bigIntValue));
}

std::pair<int, PreferencesValue> PreferencesValueParcel::UnmarshallingBasicArrayValue(const uint8_t type,
    const std::vector<uint8_t> &data)
{
    switch (type) {
        case UINT8_ARRAY_TYPE:
            return UnmarshallingVecUInt8(data);
            break;
        case BIG_INT_TYPE:
            return UnmarshallingVecBigInt(data);
            break;
        case DOUBLE_ARRAY_TYPE:
            return UnmarshallingVecDouble(data);
            break;
        case BOOL_ARRAY_TYPE:
            return UnmarshallingVecBool(data);
            break;
        default:
            break;
    }
    return std::make_pair(E_INVALID_ARGS, PreferencesValue(0));
}

std::pair<int, PreferencesValue> PreferencesValueParcel::UnmarshallingPreferenceValue(const std::vector<uint8_t> &data)
{
    PreferencesValue value(0);
    if (data.empty()) {
        LOG_ERROR("UnmarshallingPreferenceValue failed, data empty, %d", E_INVALID_ARGS);
        return std::make_pair(E_INVALID_ARGS, value);
    }
    uint8_t type = data[0];

    switch (type) {
        case INT_TYPE:
        case LONG_TYPE:
        case FLOAT_TYPE:
        case DOUBLE_TYPE:
        case BOOL_TYPE:
            return UnmarshallingBasicValue(type, data);
        case OBJECT_TYPE:
        case STRING_TYPE:
            return UnmarshallingStringValue(type, data);
        case STRING_ARRAY_TYPE:
            return UnmarshallingStringArrayValue(type, data);
        case UINT8_ARRAY_TYPE:
        case BIG_INT_TYPE:
        case DOUBLE_ARRAY_TYPE:
        case BOOL_ARRAY_TYPE:
            return UnmarshallingBasicArrayValue(type, data);
        default:
            break;
    }

    return std::make_pair(E_INVALID_ARGS, value);
}
} // namespace NativePreferences
} // namespace OHOS