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

#ifndef ANI_UTILS_H
#define ANI_UTILS_H

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
        T* nativePtr = new T;
        return Wrap(env, clazz, nativePtr);
    }

    static ani_object Wrap([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_class clazz, T* nativePtr)
    {
        ani_method ctor;
        if (ANI_OK != env->Class_FindMethod(clazz, "<ctor>", "J:V", &ctor)) {
            std::cerr << "Not found '<ctor>'" << std::endl;
            ani_object nullobj = nullptr;
            return nullobj;
        }

        ani_object obj;
        if (ANI_OK != env->Object_New(clazz, ctor, &obj, reinterpret_cast<ani_long>(nativePtr))) {
            std::cerr << "Object_New failed" << std::endl;
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

class NativeObject {
public:
    virtual ~NativeObject() = default;
};

template<typename T>
class NativeObjectAdapter : public NativeObject {
public:
    explicit NativeObjectAdapter()
    {
        obj_ = std::make_shared<T>();
    }

    std::shared_ptr<T> Get()
    {
        return obj_;
    }

private:
    std::shared_ptr<T> obj_;
};

class NativeObjectManager {
public:
    static NativeObjectManager& GetInstance()
    {
        static NativeObjectManager instance;
        return instance;
    }

    template<typename T>
    std::shared_ptr<T> Get(ani_object &object)
    {
        std::lock_guard<std::mutex> lockGuard(mutex_);

        auto iter = aniToNativeObjMapper_.find(object);
        if (iter != aniToNativeObjMapper_.end()) {
            return std::static_pointer_cast<NativeObjectAdapter<T>>(iter->second)->Get();
        }
        auto nativeObj = std::make_shared<NativeObjectAdapter<T>>();
        aniToNativeObjMapper_.emplace(object, nativeObj);
        return nativeObj->Get();
    }

private:
    std::unordered_map<ani_object, std::shared_ptr<NativeObject>> aniToNativeObjMapper_;
    std::mutex mutex_;
};

std::string AniStringToStdStr(ani_env *env, ani_string aniStr)
{
    ani_size  strSize;
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

bool ANIUtils_UnionIsInstanceOf(ani_env *env, ani_object union_obj, std::string& cls_name)
{
    ani_class cls;
    env->FindClass(cls_name.c_str(), &cls);

    ani_boolean ret;
    env->Object_InstanceOf(union_obj, cls, &ret);
    return ret;
}

class UnionAccessor {
public:
    UnionAccessor(ani_env *env, ani_object &obj)
        : env_(env), obj_(obj) {}

    bool IsInstanceOf(std::string&& cls_name)
    {
        ani_class cls;
        env_->FindClass(cls_name.c_str(), &cls);

        ani_boolean ret;
        env_->Object_InstanceOf(obj_, cls, &ret);
        return ret;
    }

    bool IsInstanceOf(std::string&& cls_name, ani_object obj)
    {
        ani_class cls;
        env_->FindClass(cls_name.c_str(), &cls);

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
    if (!IsInstanceOf("Lstd/core/Boolean;")) {
        return false;
    }
    return ANI_OK == env_->Object_CallMethodByName_Boolean(obj_, "unboxed", nullptr, &value);
}

template<>
bool UnionAccessor::TryConvert<ani_double>(ani_double &value)
{
    if (!IsInstanceOf("Lstd/core/Double;")) {
        std::cerr << "Not found 'Lstd/core/Double;'" << std::endl;
        return false;
    }
    return ANI_OK == env_->Object_CallMethodByName_Double(obj_, "unboxed", nullptr, &value);
}

template<>
bool UnionAccessor::TryConvert<std::string>(std::string &value)
{
    if (!IsInstanceOf("Lstd/core/String;")) {
        return false;
    }
    value = AniStringToStdStr(env_, static_cast<ani_string>(obj_));
    return true;
}

template<>
bool UnionAccessor::TryConvert<ani_long>(ani_long &value)
{
    if (!IsInstanceOf("Lescompat/BigInt;")) {
        return false;
    }
    ani_class bigIntCls;
    const char* className = "Lescompat/BigInt;";
    if (ANI_OK != env_->FindClass(className, &bigIntCls)) {
        std::cerr << "Not found '" << className << "'" << std::endl;
        return false;
    }
    ani_method getLongMethod;
    if (ANI_OK != env_->Class_FindMethod(bigIntCls, "getLong", ":J", &getLongMethod)) {
        std::cerr << "Class_GetMethod Failed '" << className << "'" << std::endl;
        return false;
    }

    if (ANI_OK != env_->Object_CallMethod_Long(obj_, getLongMethod, &value)) {
        std::cerr << "Object_CallMethod_Long '" << "getLongMethod" << "'" << std::endl;
        return false;
    }
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::vector<double>>(std::vector<double> &value)
{
    ani_double length;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        std::cerr << "Object_GetPropertyByName_Double length Failed" << std::endl;
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref arrayRef;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "I:Lstd/core/Object;", &arrayRef, (ani_int)i)) {
            std::cerr << "Object_GetPropertyByName_Ref Failed" << std::endl;
            return false;
        }
        if (!IsInstanceOf("Lstd/core/Double;", static_cast<ani_object>(arrayRef))) {
            std::cerr << "Not found 'Lstd/core/Double;'" << std::endl;
            return false;
        }
        ani_double doubleValue;
        if (ANI_OK != env_->Object_CallMethodByName_Double(static_cast<ani_object>(arrayRef), "unboxed",
            nullptr, &doubleValue)) {
            std::cerr << "Object_CallMethodByName_Double unbox Failed" << std::endl;
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
        std::cerr << "Object_GetPropertyByName_Double length Failed" << std::endl;
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref arrayRef;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "I:Lstd/core/Object;", &arrayRef, (ani_int)i)) {
            std::cerr << "Object_GetPropertyByName_Ref Failed" << std::endl;
            return false;
        }
        if (!IsInstanceOf("Lstd/core/String;", static_cast<ani_object>(arrayRef))) {
            std::cerr << "Not found 'Lstd/core/String;'" << std::endl;
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
        std::cerr << "Object_GetPropertyByName_Double length Failed" << std::endl;
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref arrayRef;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "I:Lstd/core/Object;", &arrayRef, (ani_int)i)) {
            std::cerr << "Object_GetPropertyByName_Ref Failed" << std::endl;
            return false;
        }
        if (!IsInstanceOf("Lstd/core/Boolean;", static_cast<ani_object>(arrayRef))) {
            std::cerr << "Not found 'Lstd/core/Boolean;'" << std::endl;
            return false;
        }
        ani_boolean boolValue;
        if (ANI_OK != env_->Object_CallMethodByName_Boolean(static_cast<ani_object>(arrayRef), "unboxed", nullptr,
            &boolValue)) {
            std::cerr << "Object_CallMethodByName_Boolean unbox Failed" << std::endl;
            return false;
        }
        value.push_back(static_cast<double>(boolValue));
    }
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::vector<uint8_t>>(std::vector<uint8_t> &value)
{
    ani_ref buffer;
    if (ANI_OK != env_->Object_GetFieldByName_Ref(obj_, "buffer", &buffer)) {
        std::cout << "Failed: env->Object_GetFieldByName_Ref()" << std::endl;
        return false;
    }
    void* data;
    size_t length;
    if (ANI_OK != env_->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &data, &length)) {
        std::cerr << "Failed: env->ArrayBuffer_GetInfo()" << std::endl;
        return false;
    }
    std::cout << "Length of buffer = " << length << std::endl;
    for (size_t i = 0; i < length; i++) {
        value.emplace_back(static_cast<uint8_t*>(data)[i]);
    }
    return true;
}
#endif
