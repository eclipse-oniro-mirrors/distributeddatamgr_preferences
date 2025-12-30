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

#ifndef PREFERENCES_ANI_COMMON_INCLUDE_ANI_UTILS_H
#define PREFERENCES_ANI_COMMON_INCLUDE_ANI_UTILS_H

#include <ani.h>

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

template<typename T>
class NativeObjectWrapper {
public:
    static ani_object Create([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_class clazz)
    {
        T* nativePtr = new (std::nothrow) T();
        if (!nativePtr) {
            return nullptr;
        }
        return Wrap(env, clazz, nativePtr);
    }

    static ani_object Wrap([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_class clazz, T* nativePtr)
    {
        ani_method ctor;
        if (ANI_OK != env->Class_FindMethod(clazz, "<ctor>", "l:", &ctor)) {
            return nullptr;
        }

        ani_object obj = nullptr;
        if (ANI_OK != env->Object_New(clazz, ctor, &obj, reinterpret_cast<ani_long>(nativePtr))) {
            return nullptr;
        }
        return obj;
    }

    static T* Unwrap(ani_env *env, ani_object object, const char* propName = "nativePtr")
    {
        ani_long nativePtr;
        if (ANI_OK != env->Object_GetFieldByName_Long(object, propName, &nativePtr)) {
            return nullptr;
        }
        return reinterpret_cast<T*>(nativePtr);
    }
};

std::string AniStringToStdStr(ani_env *env, ani_string aniStr)
{
    ani_size strSize;
    env->String_GetUTF8Size(aniStr, &strSize);
    if (strSize == 0) {
        return "";
    }
    std::vector<char> buffer(strSize + 1);
    char* utf8Buffer = buffer.data();

    ani_size bytesWritten = 0;
    env->String_GetUTF8(aniStr, utf8Buffer, strSize + 1, &bytesWritten);
    if (bytesWritten > strSize) {
        bytesWritten = strSize;
    }
    utf8Buffer[bytesWritten] = '\0';
    std::string content = std::string(utf8Buffer);
    return content;
}

bool ANIUtils_UnionIsInstanceOf(ani_env *env, ani_object unionObj, std::string& clsName)
{
    ani_class cls;
    env->FindClass(clsName.c_str(), &cls);

    ani_boolean ret;
    env->Object_InstanceOf(unionObj, cls, &ret);
    return ret;
}

class UnionAccessor {
public:
    UnionAccessor(ani_env *env, ani_object &obj)
        : env_(env), obj_(obj) {}

    bool IsInstanceOf(std::string&& clsName)
    {
        ani_class cls;
        env_->FindClass(clsName.c_str(), &cls);

        ani_boolean ret;
        env_->Object_InstanceOf(obj_, cls, &ret);
        return ret;
    }

    bool IsInstanceOf(std::string&& clsName, ani_object obj)
    {
        ani_class cls;
        env_->FindClass(clsName.c_str(), &cls);

        ani_boolean ret;
        env_->Object_InstanceOf(obj, cls, &ret);
        return ret;
    }

    template<typename T>
    bool TryConvert(T &value);

private:
    ani_env *env_;
    ani_object obj_;
};

template<>
bool UnionAccessor::TryConvert<ani_boolean>(ani_boolean &value)
{
    if (!IsInstanceOf("std.core.Boolean")) {
        return false;
    }
    return ANI_OK == env_->Object_CallMethodByName_Boolean(obj_, "booleanValue", nullptr, &value);
}

template<>
bool UnionAccessor::TryConvert<ani_double>(ani_double &value)
{
    if (!IsInstanceOf("std.core.Double")) {
        return false;
    }
    return ANI_OK == env_->Object_CallMethodByName_Double(obj_, "toDouble", nullptr, &value);
}

template<>
bool UnionAccessor::TryConvert<std::string>(std::string &value)
{
    if (!IsInstanceOf("std.core.String")) {
        return false;
    }
    value = AniStringToStdStr(env_, static_cast<ani_string>(obj_));
    return true;
}

template<>
bool UnionAccessor::TryConvert<ani_long>(ani_long &value)
{
    if (!IsInstanceOf("std.core.BigInt")) {
        return false;
    }
    ani_class bigIntCls;
    const char* className = "std.core.BigInt";
    if (ANI_OK != env_->FindClass(className, &bigIntCls)) {
        return false;
    }
    ani_method getLongMethod;
    if (ANI_OK != env_->Class_FindMethod(bigIntCls, "getLong", ":l", &getLongMethod)) {
        return false;
    }

    if (ANI_OK != env_->Object_CallMethod_Long(obj_, getLongMethod, &value)) {
        return false;
    }
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::vector<double>>(std::vector<double> &value)
{
    ani_double length;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        return false;
    }
    if (length > static_cast<ani_double>(INT_MAX)) {
        return false;
    }
    for (int i = 0; i < static_cast<int>(length); i++) {
        ani_ref arrayRef;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "i:C{std.core.Object}", &arrayRef, (ani_int)i)) {
            return false;
        }
        if (!IsInstanceOf("std.core.Double", static_cast<ani_object>(arrayRef))) {
            return false;
        }
        ani_double doubleValue;
        if (ANI_OK != env_->Object_CallMethodByName_Double(static_cast<ani_object>(arrayRef), "toDouble",
            nullptr, &doubleValue)) {
            return false;
        }
        value.push_back(static_cast<double>(doubleValue));
    }
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::vector<std::string>>(std::vector<std::string> &value)
{
    ani_double length;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref arrayRef;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "i:C{std.core.Object}", &arrayRef, (ani_int)i)) {
            return false;
        }
        if (!IsInstanceOf("std.core.String", static_cast<ani_object>(arrayRef))) {
            return false;
        }
        value.push_back(AniStringToStdStr(env_, static_cast<ani_string>(arrayRef)));
    }
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::vector<bool>>(std::vector<bool> &value)
{
    ani_double length;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref arrayRef;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "i:C{std.core.Object}", &arrayRef, (ani_int)i)) {
            return false;
        }
        if (!IsInstanceOf("std.core.Boolean", static_cast<ani_object>(arrayRef))) {
            return false;
        }
        ani_boolean boolValue;
        if (ANI_OK != env_->Object_CallMethodByName_Boolean(static_cast<ani_object>(arrayRef), "toBoolean", nullptr,
            &boolValue)) {
            return false;
        }
        value.push_back(static_cast<bool>(boolValue));
    }
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::vector<uint8_t>>(std::vector<uint8_t> &value)
{
    ani_ref buffer;
    if (ANI_OK != env_->Object_GetFieldByName_Ref(obj_, "buffer", &buffer)) {
        return false;
    }
    void* data;
    size_t length;
    if (ANI_OK != env_->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &data, &length)) {
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        value.emplace_back(static_cast<uint8_t*>(data)[i]);
    }
    return true;
}
#endif // PREFERENCES_ANI_COMMON_INCLUDE_ANI_UTILS_H
