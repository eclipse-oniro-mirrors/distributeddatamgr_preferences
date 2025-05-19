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

#include "ani_common_utils.h"

#include "log_print.h"

namespace OHOS {
namespace PreferencesEtsKit {
namespace EtsUtils {
using Object = OHOS::NativePreferences::Object;
using PreferencesValue = OHOS::NativePreferences::PreferencesValue;

static constexpr const char* CLASS_NAME_DOUBLE = "Lstd/core/Double;";
static constexpr const char* CLASS_NAME_BOOLEAN = "Lstd/core/Boolean;";
static constexpr const char* CLASS_NAME_BIGINT = "Lescompat/BigInt;";
static constexpr const char* CLASS_NAME_UINT8_ARRAY = "Lescompat/Uint8Array;";
static constexpr const char* CLASS_NAME_ARRAY = "Lescompat/Array;";
static constexpr const char* CLASS_NAME_RRECORD = "Lescompat/Record;";
static constexpr const char* CLASS_NAME_JSON = "Lescompat/JSON;";
static constexpr const char* METHOD_NAME_STRINGIFY = "stringify";
static constexpr const char* METHOD_NAME_PARSE = "parse";
static constexpr const char* METHOD_NAME_CONSTRUCTOR = "<ctor>";
static constexpr const char* METHOD_NAME_SET = "$_set";

static ani_string StdStringToANIString(ani_env* env, const std::string &str)
{
    ani_string stringAni = nullptr;
    ani_status status = env->String_NewUTF8(str.c_str(), str.size(), &stringAni);
    if (status != ANI_OK) {
        LOG_INFO("String_NewUTF8 failed, ret: %{public}d, size: %{public}zu.", status, str.size());
    }
    return stringAni;
}

static ani_object DoubleToObject(ani_env *env, double value)
{
    ani_object aniObject = nullptr;
    ani_double doubleValue = static_cast<ani_double>(value);
    ani_class aniClass;
    ani_status status = env->FindClass(CLASS_NAME_DOUBLE, &aniClass);
    if (status != ANI_OK) {
        LOG_ERROR("Double not found, ret: %{public}d.", status);
        return aniObject;
    }
    ani_method aniCtor;
    status = env->Class_FindMethod(aniClass, METHOD_NAME_CONSTRUCTOR, "D:V", &aniCtor);
    if (status != ANI_OK) {
        LOG_ERROR("Method <ctor> not found, ret: %{public}d.", status);
        return aniObject;
    }
    status = env->Object_New(aniClass, aniCtor, &aniObject, doubleValue);
    if (status != ANI_OK) {
        LOG_ERROR("Object_New failed, ret: %{public}d.", status);
        return aniObject;
    }
    return aniObject;
}

static ani_object BoolToObject(ani_env *env, bool value)
{
    ani_object aniObject = nullptr;
    ani_boolean boolValue = static_cast<bool>(value);
    ani_class aniClass;
    ani_status status = env->FindClass(CLASS_NAME_BOOLEAN, &aniClass);
    if (status != ANI_OK) {
        LOG_ERROR("Bool not found, ret: %{public}d.", status);
        return aniObject;
    }

    ani_method aniCtor;
    status = env->Class_FindMethod(aniClass, METHOD_NAME_CONSTRUCTOR, "Z:V", &aniCtor);
    if (status != ANI_OK) {
        LOG_ERROR("Method <ctor> not found, ret: %{public}d.", status);
        return aniObject;
    }
    status = env->Object_New(aniClass, aniCtor, &aniObject, boolValue);
    if (status != ANI_OK) {
        LOG_ERROR("Object_New failed, ret: %{public}d.", status);
        return aniObject;
    }
    return aniObject;
}

static ani_object StringToObject(ani_env *env, const std::string &value)
{
    ani_string stringValue = StdStringToANIString(env, value);
    return static_cast<ani_object>(stringValue);
}

static ani_object BigIntToObject(ani_env *env, int64_t value)
{
    ani_object aniObject = nullptr;
    ani_class aniClass;
    ani_status status = env->FindClass(CLASS_NAME_BIGINT, &aniClass);
    if (status != ANI_OK) {
        LOG_ERROR("BigInt not found, ret: %{public}d.", status);
        return aniObject;
    }

    ani_method aniCtor;
    status = env->Class_FindMethod(aniClass, METHOD_NAME_CONSTRUCTOR, "J:V", &aniCtor);
    if (status != ANI_OK) {
        LOG_ERROR("Method <ctor> not found, ret: %{public}d.", status);
        return aniObject;
    }
    status = env->Object_New(aniClass, aniCtor, &aniObject, value);
    if (status != ANI_OK) {
        LOG_ERROR("Object_New failed, ret: %{public}d.", status);
        return aniObject;
    }
    return aniObject;
}

static ani_object Uint8ArrayToObject(ani_env *env, const std::vector<uint8_t> values)
{
    ani_object aniObject = nullptr;
    ani_class arrayClass;
    ani_status status = env->FindClass(CLASS_NAME_UINT8_ARRAY, &arrayClass);
    if (status != ANI_OK) {
        LOG_ERROR("Uint8Array not found, ret: %{public}d.", status);
        return aniObject;
    }
    ani_method arrayCtor;
    status = env->Class_FindMethod(arrayClass, METHOD_NAME_CONSTRUCTOR, "I:V", &arrayCtor);
    if (status != ANI_OK) {
        LOG_ERROR("Method <ctor> not found, ret: %{public}d.", status);
        return aniObject;
    }
    auto valueSize = values.size();
    status = env->Object_New(arrayClass, arrayCtor, &aniObject, valueSize);
    if (status != ANI_OK) {
        LOG_ERROR("Object_New failed, ret: %{public}d.", status);
        return aniObject;
    }
    ani_ref buffer;
    status = env->Object_GetFieldByName_Ref(aniObject, "buffer", &buffer);
    if (status != ANI_OK) {
        LOG_ERROR("GetField failed, ret: %{public}d.", status);
        return aniObject;
    }
    void *bufData;
    size_t bufLength;
    status = env->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &bufData, &bufLength);
    if (status != ANI_OK) {
        LOG_ERROR("ArrayBuffer_GetInfo failed, ret: %{public}d.", status);
        return aniObject;
    }
    auto ret = memcpy_s(bufData, bufLength, values.data(), bufLength);
    if (ret != 0) {
        LOG_ERROR("memcpy_s failed, ret: %{public}d.", ret);
        return nullptr;
    }
    return aniObject;
}

static ani_object StringArrayToObject(ani_env *env, const std::vector<std::string> values)
{
    ani_object arrayObj = nullptr;
    ani_class arrayCls = nullptr;
    ani_status status = env->FindClass(CLASS_NAME_ARRAY, &arrayCls);
    if (status != ANI_OK) {
        LOG_ERROR("Array not found, ret: %{public}d.", status);
        return arrayObj;
    }
    ani_method arrayCtor;
    status = env->Class_FindMethod(arrayCls, METHOD_NAME_CONSTRUCTOR, "I:V", &arrayCtor);
    if (status != ANI_OK) {
        LOG_ERROR("Method <ctor> not found, ret: %{public}d.", status);
        return arrayObj;
    }
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, values.size());
    if (status != ANI_OK) {
        LOG_ERROR("Object_New failed, ret: %{public}d.", status);
        return arrayObj;
    }
    ani_size index = 0;
    for (auto value : values) {
        ani_string ani_str;
        status = env->String_NewUTF8(value.c_str(), value.size(), &ani_str);
        if (status != ANI_OK) {
            LOG_ERROR("String_NewUTF8 failed, ret: %{public}d, size: %{public}zu.", status, value.size());
            break;
        }
        status = env->Object_CallMethodByName_Void(arrayObj, METHOD_NAME_SET, "ILstd/core/Object;:V", index, ani_str);
        if (status != ANI_OK) {
            LOG_ERROR("Call $_set failed, ret: %{public}d, index: %{public}d.", status, static_cast<int32_t>(index));
            break;
        }
        index++;
    }
    return arrayObj;
}

static ani_object BoolArrayToObject(ani_env *env, const std::vector<bool> values)
{
    ani_object arrayObj = nullptr;
    ani_class arrayCls = nullptr;
    ani_status status = env->FindClass(CLASS_NAME_ARRAY, &arrayCls);
    if (status != ANI_OK) {
        LOG_ERROR("Array not found, ret: %{public}d.", status);
        return arrayObj;
    }

    ani_method arrayCtor;
    status = env->Class_FindMethod(arrayCls, METHOD_NAME_CONSTRUCTOR, "I:V", &arrayCtor);
    if (status != ANI_OK) {
        LOG_ERROR("Method <ctor> not found, ret: %{public}d.", status);
        return arrayObj;
    }
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, values.size());
    if (status != ANI_OK) {
        LOG_ERROR("Object_New failed, ret: %{public}d.", status);
        return arrayObj;
    }
    ani_size index = 0;
    for (auto value : values) {
        ani_object aniValue = BoolToObject(env, value);
        status = env->Object_CallMethodByName_Void(arrayObj, METHOD_NAME_SET, "ILstd/core/Object;:V", index, aniValue);
        if (status != ANI_OK) {
            LOG_ERROR("Call $_set failed, ret: %{public}d, index: %{public}d.", status, static_cast<int32_t>(index));
            break;
        }
        index++;
    }
    return arrayObj;
}

static ani_object DoubleArrayToObject(ani_env *env, const std::vector<double> values)
{
    ani_object arrayObj = nullptr;
    ani_class arrayCls = nullptr;
    ani_status status = env->FindClass(CLASS_NAME_ARRAY, &arrayCls);
    if (status != ANI_OK) {
        LOG_ERROR("Array not found, ret: %{public}d.", status);
        return arrayObj;
    }
    ani_method arrayCtor;
    status = env->Class_FindMethod(arrayCls, METHOD_NAME_CONSTRUCTOR, "I:V", &arrayCtor);
    if (status != ANI_OK) {
        LOG_ERROR("Method <ctor> not found, ret: %{public}d.", status);
        return arrayObj;
    }
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, values.size());
    if (status != ANI_OK) {
        LOG_ERROR("Object_New failed, ret: %{public}d.", status);
        return arrayObj;
    }
    ani_size index = 0;
    for (auto value : values) {
        ani_object aniValue = DoubleToObject(env, value);
        status = env->Object_CallMethodByName_Void(arrayObj, METHOD_NAME_SET, "ILstd/core/Object;:V", index, aniValue);
        if (status != ANI_OK) {
            LOG_ERROR("Call $_set failed, ret: %{public}d, index: %{public}d.", status, static_cast<int32_t>(index));
            break;
        }
        index++;
    }
    return arrayObj;
}

static ani_object ObjectToANIObject(ani_env *env, const Object &obj)
{
    return nullptr;
}

ani_object PreferencesValueToObject(ani_env *env, const PreferencesValue &res)
{
    if (env == nullptr) {
        LOG_ERROR("Env is nullptr.");
        return nullptr;
    }
    if (res.IsDouble()) {
        return DoubleToObject(env, res);
    }
    if (res.IsBool()) {
        return BoolToObject(env, res);
    }
    if (res.IsString()) {
        return StringToObject(env, res);
    }
    if (res.IsLong()) {
        return BigIntToObject(env, res);
    }
    if (res.IsUint8Array()) {
        return Uint8ArrayToObject(env, static_cast<std::vector<uint8_t>>(res));
    }
    if (res.IsStringArray()) {
        return StringArrayToObject(env, res);
    }
    if (res.IsBoolArray()) {
        return BoolArrayToObject(env, res);
    }
    if (res.IsDoubleArray()) {
        return DoubleArrayToObject(env, res);
    }
    if (res.IsObject()) {
        return ObjectToANIObject(env, res);
    }
    return nullptr;
}

ani_object PreferencesMapToObject(ani_env *env, std::unordered_map<std::string, PreferencesValue> &values)
{
    ani_object aniObject = nullptr;
    if (env == nullptr) {
        LOG_ERROR("Env is nullptr.");
        return aniObject;
    }
    ani_class cls;
    ani_status status = env->FindClass(CLASS_NAME_RRECORD, &cls);
    if (status != ANI_OK) {
        LOG_ERROR("Record not found, ret: %{public}d.", status);
        return aniObject;
    }

    ani_method aniCtor;
    status = env->Class_FindMethod(cls, METHOD_NAME_CONSTRUCTOR, ":V", &aniCtor);
    if (status != ANI_OK) {
        LOG_ERROR("Method <ctor> not found, ret: %{public}d.", status);
        return aniObject;
    }
    status = env->Object_New(cls, aniCtor, &aniObject);
    if (status != ANI_OK) {
        LOG_ERROR("Object_New failed, ret: %{public}d.", status);
        return aniObject;
    }
    ani_method setter;
    status = env->Class_FindMethod(cls, METHOD_NAME_SET, nullptr, &setter);
    if (status != ANI_OK) {
        LOG_ERROR("Method $_set not found, ret: %{public}d.", status);
        return aniObject;
    }

    for (auto& value : values) {
        ani_string aniKey = StdStringToANIString(env, value.first);
        ani_object aniObjVal = PreferencesValueToObject(env, value.second);
        status = env->Object_CallMethod_Void(aniObject, setter, aniKey, aniObjVal);
        if (status != ANI_OK) {
            LOG_INFO("Call $_set failed, ret: %{public}d.", status);
            break;
        }
    }
    return aniObject;
}

std::string AniStringToStdStr(ani_env *env, ani_string aniStr)
{
    ani_size strSize;
    env->String_GetUTF8Size(aniStr, &strSize);
    if (strSize == 0) {
        return "";
    }
    std::vector<char> buffer(strSize + 1);
    char* utf8Buffer = buffer.data();

    ani_size bytes_written = 0;
    env->String_GetUTF8(aniStr, utf8Buffer, strSize + 1, &bytes_written);
    utf8Buffer[bytes_written] = '\0';
    std::string content = std::string(utf8Buffer);
    return content;
}

PreferencesValue AniObjectToPreferencesValue(ani_env *env, uintptr_t object)
{
    PreferencesValue preferencesValue;
    if (env == nullptr) {
        LOG_ERROR("Env is nullptr.");
        return preferencesValue;
    }
    ani_class cls;
    ani_status status = env->FindClass(CLASS_NAME_JSON, &cls);
    if (status != ANI_OK) {
        LOG_ERROR("JSON not found, ret: %{public}d.", status);
        return preferencesValue;
    }
    ani_static_method stringify;
    status = env->Class_FindStaticMethod(cls, METHOD_NAME_STRINGIFY, "Lstd/core/Object;:Lstd/core/String;", &stringify);
    if (status != ANI_OK) {
        LOG_ERROR("Stringify not found, ret: %{public}d.", status);
        return preferencesValue;
    }
    ani_ref result;
    status = env->Class_CallStaticMethod_Ref(cls, stringify, &result, reinterpret_cast<ani_object>(object));
    if (status != ANI_OK) {
        LOG_ERROR("JSON.stringify run failed, ret: %{public}d.", status);
        return preferencesValue;
    }
    auto resStr = AniStringToStdStr(env, reinterpret_cast<ani_string>(result));
    return Object(std::move(resStr));
}
} // namespace EtsUtils
} // namespace PreferencesEtsKit
} // namespace OHOS