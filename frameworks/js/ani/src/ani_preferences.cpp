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

#include <ani.h>
#include <array>
#include <iostream>
#include <securec.h>
#include "ani_utils.h"
#include "log_print.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "preferences_value.h"

using namespace OHOS::NativePreferences;

static ani_error CreateAniError(ani_env *env, std::string&& errMsg)
{
    static const char *errorClsName = "Lescompat/Error;";
    ani_class cls {};
    if (ANI_OK != env->FindClass(errorClsName, &cls)) {
        std::cerr << "Not found '" << errorClsName << "'" << std::endl;
        return nullptr;
    }
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "Lstd/core/String;:V", &ctor)) {
        std::cerr << "Not found ctor'" << errorClsName << "'" << std::endl;
        return nullptr;
    }
    ani_string error_msg;
    env->String_NewUTF8(errMsg.c_str(), 17U, &error_msg);
    ani_object errorObject;
    env->Object_New(cls, ctor, &errorObject, error_msg);
    return static_cast<ani_error>(errorObject);
}

static int executeRemoveName(ani_env *env, ani_object context, ani_string name)
{
    int errCode = E_ERROR;
    ani_ref nameTmp;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "name", &nameTmp)) {
        std::cout << "Object_GetFieldByName_Ref Faild" << std::endl;
        nameTmp = static_cast<ani_ref>(name);
    }
    std::string nameStr = AniStringToStdStr(env, static_cast<ani_string>(nameTmp));
    std::cout << "in executeRemoveName nameStr is :" << nameStr <<  std::endl;
    LOG_INFO("in executeRemoveName nameStr is: %{public}s .", nameStr.c_str());

    ani_ref dataGroupId;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "dataGroupId", &dataGroupId)) {
        std::cerr << "Object_GetFieldByName_Ref Faild from context" << std::endl;
        return errCode;
    }
    auto dataGroupId_str = AniStringToStdStr(env, static_cast<ani_string>(dataGroupId));
    std::cout << "in executeRemoveName dataGroupId is :" << dataGroupId_str <<  std::endl;

    std::string path = nameStr; // add name -> path funciton
    return PreferencesHelper::RemovePreferencesFromCache(path);
}

static int executeRemoveOpt(ani_env *env, ani_object context, ani_object opt)
{
    int errCode = E_ERROR;
    ani_ref nameTmp;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "name", &nameTmp)) {
        std::cout << "Object_GetFieldByName_Ref name from context Faild" << std::endl;
        if (ANI_OK != env->Object_GetPropertyByName_Ref(opt, "name", &nameTmp)) {
            std::cout << "Object_GetFieldByName_Ref name from opt Faild" << std::endl;
            return errCode;
        }
    }
    auto nameStr = AniStringToStdStr(env, static_cast<ani_string>(nameTmp));
    std::cout << "nameStr is :" << nameStr <<  std::endl;

    ani_ref dataGroupId;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "dataGroupId", &dataGroupId)) {
        std::cerr << "Object_GetFieldByName_Ref dataGroupId from context Faild" << std::endl;
        if (ANI_OK != env->Object_GetPropertyByName_Ref(opt, "dataGroupId", &dataGroupId)) {
            std::cout << "Object_GetFieldByName_Ref dataGroupId from opt Faild" << std::endl;
            return errCode;
        }
    }
    auto dataGroupId_str = AniStringToStdStr(env, static_cast<ani_string>(dataGroupId));
    std::cout << "dataGroupId is :" << dataGroupId_str <<  std::endl;

    std::string path = nameStr; // add name -> path funciton
    return PreferencesHelper::RemovePreferencesFromCache(path);
}

static ani_object createPreferencesObj(ani_env *env, Options options)
{
    int errCode = E_OK;
    std::shared_ptr<Preferences> preferences = PreferencesHelper::GetPreferences(options, errCode);
    if (preferences == nullptr) {
        std::cout << "preferences is null " << std::endl;
        ani_error err = CreateAniError(env, "GetPreferences failed!");
        env->ThrowError(err);
    }

    ani_namespace ns {};
    if (ANI_OK != env->FindNamespace("L@ohos/data/preferences/preferences;", &ns)) {
        std::cerr << "Not found namespace 'Lpreferences'" << std::endl;
        return nullptr;
    }

    static const char *className = "LPreferencesImpl;";
    ani_class cls;
    if (ANI_OK != env->Namespace_FindClass(ns, className, &cls)) {
        std::cerr << "Not found '" << className << "'" << std::endl;
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        std::cerr << "get ctor Failed'" << className << "'" << std::endl;
        return nullptr;
    }
    ani_object prefences_obj = {};
    if (ANI_OK != env->Object_New(cls, ctor, &prefences_obj, reinterpret_cast<ani_long>(preferences.get()))) {
        std::cerr << "Create Object Failed'" << className << "'" << std::endl;
        return nullptr;
    }
    std::cout << "preferences is  " << preferences << std::endl;
    return prefences_obj;
}

static ani_object executeGetName(ani_env *env, ani_object context, ani_string name)
{
    std::cout << "in cpp  executeGetName" << std::endl;
    ani_ref nameTmp;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "name", &nameTmp)) {
        std::cout << "Object_GetFieldByName_Ref Faild" << std::endl;
        nameTmp = static_cast<ani_ref>(name);
    }
    auto nameStr = AniStringToStdStr(env, static_cast<ani_string>(nameTmp));
    std::cout << "nameStr is :" << nameStr <<  std::endl;

    ani_ref dataGroupId;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "dataGroupId", &dataGroupId)) {
        std::cerr << "Object_GetFieldByName_Ref Faild" << std::endl;
        return nullptr;
    }
    auto dataGroupId_str = AniStringToStdStr(env, static_cast<ani_string>(dataGroupId));
    std::cout << "dataGroupId is :" << dataGroupId_str <<  std::endl;

    ani_ref bundleName;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "bundleName", &bundleName)) {
        std::cerr << "Object_GetFieldByName_Ref Faild" << std::endl;
        return nullptr;
    }
    auto bundleName_str = AniStringToStdStr(env, static_cast<ani_string>(bundleName));
    std::cout << "bundleName_str is :" << bundleName_str <<  std::endl;

    std::string path = nameStr;
    Options options(path, bundleName_str, dataGroupId_str);
    return createPreferencesObj(env, options);
}

static ani_object executeGetOpt(ani_env *env, ani_object context, ani_object opt)
{
    std::cout << "in cpp  executeGetOpt" << std::endl;
    ani_ref nameTmp;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "name", &nameTmp)) {
        std::cout << "Object_GetFieldByName_Ref name from context Faild" << std::endl;
        if (ANI_OK != env->Object_GetPropertyByName_Ref(opt, "name", &nameTmp)) {
            std::cout << "Object_GetFieldByName_Ref name from opt Faild" << std::endl;
            return nullptr;
        }
    }
    std::cout << "before trans nameStr is :" << nameTmp <<  std::endl;
    auto nameStr = AniStringToStdStr(env, static_cast<ani_string>(nameTmp));
    std::cout << "nameStr is :" << nameStr <<  std::endl;

    ani_ref dataGroupId;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "dataGroupId", &dataGroupId)) {
        std::cerr << "Object_GetFieldByName_Ref dataGroupId from context Faild" << std::endl;
        if (ANI_OK != env->Object_GetPropertyByName_Ref(opt, "dataGroupId", &dataGroupId)) {
            std::cout << "Object_GetFieldByName_Ref dataGroupId from opt Faild" << std::endl;
            return nullptr;
        }
    }
    auto dataGroupId_str = AniStringToStdStr(env, static_cast<ani_string>(dataGroupId));
    std::cout << "dataGroupId is :" << dataGroupId_str <<  std::endl;

    ani_ref bundleName;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "bundleName", &bundleName)) {
        std::cerr << "Object_GetFieldByName_Ref bundleName Faild" << std::endl;
        return nullptr;
    }
    auto bundleName_str = AniStringToStdStr(env, static_cast<ani_string>(bundleName));
    std::cout << "bundleName_str is :" << bundleName_str <<  std::endl;

    std::string path = nameStr;
    Options options(path, bundleName_str, dataGroupId_str);
    return createPreferencesObj(env, options);
}

static Preferences* unwrapp(ani_env *env, ani_object object)
{
    ani_long context;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativePtr", &context)) {
        return nullptr;
    }
    std::cout << "nativePtr is " << context << std::endl;
    return reinterpret_cast<Preferences *>(context);
}

static int deleteSync(ani_env *env, ani_object obj, ani_string key)
{
    int32_t errCode = E_ERROR;
    auto preferences =  unwrapp(env, obj);
    if (preferences != nullptr) {
        auto key_str = AniStringToStdStr(env, key);
        std::cerr << "key_str is " << key_str << std::endl;
        errCode = preferences->Delete(key_str);
        std::cerr << "errCode is " << errCode << std::endl;
    }
    return errCode;
}

static bool hasSyncInner(ani_env *env, ani_object obj, ani_string key)
{
    bool ret = false;
    auto preferences =  unwrapp(env, obj);
    if (preferences != nullptr) {
        auto key_str = AniStringToStdStr(env, key);
        std::cerr << "key_str is " << key_str << std::endl;
        ret = preferences->HasKey(key_str);
        std::cerr << "ret is " << ret << std::endl;
    }
    return ret;
}

static int flushSync(ani_env *env, ani_object obj)
{
    int32_t errCode = E_OK;
    auto preferences =  unwrapp(env, obj);
    if (preferences != nullptr) {
        std::cerr << "before flush..." << std::endl;
        errCode = preferences->FlushSync();
        std::cerr << "after flush errCode is " << errCode << std::endl;
    }
    return errCode;
}

static OHOS::NativePreferences::Object AniObjectToNativeObject(ani_env* env, ani_object unionValue)
{
    ani_class objCls;
    if (ANI_OK != env->FindClass("Lstd/core/Object;", &objCls)) {
        std::cerr << "Not found class 'Lstd/core/Object;'" << std::endl;
        return PreferencesValue(static_cast<int>(0));
    }
    ani_method toStringMethod;
    if (ANI_OK != env->Class_FindMethod(objCls, "toString", ":Lstd/core/String;", &toStringMethod)) {
        std::cerr << "Class_GetMethod toString Failed" << std::endl;
        return PreferencesValue(static_cast<int>(0));
    }
    ani_ref value = nullptr;
    if (ANI_OK != env->Object_CallMethod_Ref(unionValue, toStringMethod, &value)) {
        std::cerr << "Object_CallMethod_Ref toString Failed" << std::endl;
        return PreferencesValue(static_cast<int>(0));
    }
    std::string strObj = AniStringToStdStr(env, static_cast<ani_string>(value));
    return OHOS::NativePreferences::Object(strObj);
}

static PreferencesValue ParsePreferencesValue(ani_env *env, ani_object unionValue)
{
    UnionAccessor unionAccessor(env, unionValue);
    ani_double value = 0.0;
    if (unionAccessor.IsInstanceOf("Lstd/core/Double;")) {
        env->Object_CallMethodByName_Double(unionValue, "unboxed", nullptr, &value);
        return static_cast<double>(value);
    }

    if (unionAccessor.IsInstanceOf("Lstd/core/String;")) {
        std::string stringValue = AniStringToStdStr(env, static_cast<ani_string>(unionValue));
        return stringValue;
    }

    ani_boolean boolValue = 0;
    if (unionAccessor.IsInstanceOf("Lstd/core/Boolean;")) {
        if (ANI_OK != env->Object_CallMethodByName_Boolean(unionValue, "unboxed", nullptr, &boolValue)) {
            std::cerr << "Object_CallMethodByName_Double unbox Failed" << std::endl;
            return false;
        }
        return PreferencesValue(static_cast<bool>(boolValue));
    }

    std::vector<double> arrayDoubleValues = {};
    if (unionAccessor.TryConvert<std::vector<double>>(arrayDoubleValues) && arrayDoubleValues.size() > 0) {
        return PreferencesValue(arrayDoubleValues);
    }

    std::vector<std::string> arrayStrValues;
    if (unionAccessor.TryConvert<std::vector<std::string>>(arrayStrValues) && arrayStrValues.size() > 0) {
        return PreferencesValue(arrayStrValues);
    }

    std::vector<bool> arrayBoolValues;
    if (unionAccessor.TryConvert<std::vector<bool>>(arrayBoolValues) && arrayBoolValues.size() > 0) {
        return PreferencesValue(arrayBoolValues);
    }

    std::vector<uint8_t> arrayUint8Values;
    if (unionAccessor.TryConvert<std::vector<uint8_t>>(arrayUint8Values)) {
        return PreferencesValue(arrayUint8Values);
    }

    ani_long longValue;
    if (unionAccessor.TryConvert<ani_long>(longValue)) {
        return PreferencesValue(static_cast<int64_t>(longValue));
    }

    if (unionAccessor.IsInstanceOf("Lstd/core/Object;")) {
        return AniObjectToNativeObject(env, unionValue);
    }

    std::cerr << "Cannot find specified type" << std::endl;
    return PreferencesValue(static_cast<int>(0));
}

static ani_string StdStringToANIString(ani_env* env, const std::string& str)
{
    ani_string stringAni = nullptr;
    if (ANI_OK != env->String_NewUTF8(str.c_str(), str.size(), &stringAni)) {
        std::cerr << "String_NewUTF8 Failed" << std::endl;
    }
    return stringAni;
}

static ani_object DoubleToObject(ani_env *env, double value)
{
    ani_object aniObject = nullptr;
    ani_double doubleValue = static_cast<ani_double>(value);
    static const char *className = "Lstd/core/Double;";
    ani_class aniClass;
    if (ANI_OK != env->FindClass(className, &aniClass)) {
        std::cerr << "Not found '" << className << "'" << std::endl;
        return aniObject;
    }
    ani_method personInfoCtor;
    if (ANI_OK != env->Class_FindMethod(aniClass, "<ctor>", "D:V", &personInfoCtor)) {
        std::cerr << "Class_GetMethod Failed '" << className << "' <ctor>" << std::endl;
        return aniObject;
    }

    if (ANI_OK != env->Object_New(aniClass, personInfoCtor, &aniObject, doubleValue)) {
        std::cerr << "Object_New Failed '" << className << "' <ctor>" << std::endl;
        return aniObject;
    }
    return aniObject;
}

static ani_object BoolToObject(ani_env *env, bool value)
{
    ani_object aniObject = nullptr;
    ani_boolean boolValue = static_cast<bool>(value);
    static const char *className = "Lstd/core/Boolean;";
    ani_class aniClass;
    if (ANI_OK != env->FindClass(className, &aniClass)) {
        std::cerr << "Not found '" << className << "'" << std::endl;
        return aniObject;
    }

    ani_method personInfoCtor;
    if (ANI_OK != env->Class_FindMethod(aniClass, "<ctor>", "Z:V", &personInfoCtor)) {
        std::cerr << "Class_GetMethod Failed '" << className << "' <ctor>" << std::endl;
        return aniObject;
    }

    if (ANI_OK != env->Object_New(aniClass, personInfoCtor, &aniObject, boolValue)) {
        std::cerr << "Object_New Failed '" << className << "' <ctor>" << std::endl;
    }
    return aniObject;
}

static ani_object StringToObject(ani_env *env, std::string value)
{
    ani_string stringValue = StdStringToANIString(env, value);
    return static_cast<ani_object>(stringValue);
}

static ani_object BigIntToObject(ani_env *env, const BigInt value)
{
    ani_object aniObject = nullptr;
    ani_long longValue = static_cast<ani_long>(value.words_[0] * value.sign_);
    static const char *className = "Lescompat/BigInt;";
    ani_class aniClass;
    if (ANI_OK != env->FindClass(className, &aniClass)) {
        std::cerr << "Not found '" << className << "'" << std::endl;
        return aniObject;
    }

    ani_method personInfoCtor;
    if (ANI_OK != env->Class_FindMethod(aniClass, "<ctor>", "Lescompat/BigInt;:V", &personInfoCtor)) {
        std::cerr << "Class_GetMethod Failed '" << className << "' <ctor>" << std::endl;
        return aniObject;
    }

    if (ANI_OK != env->Object_New(aniClass, personInfoCtor, &aniObject, longValue)) {
        std::cerr << "Object_New Failed '" << className << "' <ctor>" << std::endl;
        return aniObject;
    }
    return aniObject;
}

static ani_object Uint8ArrayToObject(ani_env *env, const std::vector<uint8_t> values)
{
    ani_object aniObject = nullptr;
    ani_class arrayClass;
    ani_status retCode = env->FindClass("Lescompat/Uint8Array;", &arrayClass);
    if (retCode != ANI_OK) {
        std::cerr << "Failed: env->FindClass()" << std::endl;
        return aniObject;
    }
    ani_method arrayCtor;
    retCode = env->Class_FindMethod(arrayClass, "<ctor>", "I:V", &arrayCtor);
    if (retCode != ANI_OK) {
        std::cerr << "Failed: env->Class_FindMethod()" << std::endl;
        return aniObject;
    }
    auto valueSize = values.size();
    retCode = env->Object_New(arrayClass, arrayCtor, &aniObject, valueSize);
    if (retCode != ANI_OK) {
        std::cerr << "Failed: env->Object_New()" << std::endl;
        return aniObject;
    }
    ani_ref buffer;
    env->Object_GetFieldByName_Ref(aniObject, "buffer", &buffer);
    void *bufData;
    size_t bufLength;
    retCode = env->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &bufData, &bufLength);
    if (retCode != ANI_OK) {
        std::cerr << "Failed: env->ArrayBuffer_GetInfo()" << std::endl;
    }
    auto ret = memcpy_s(bufData, bufLength, values.data(), bufLength);
    if (ret != 0) {
        return nullptr;
    }
    return aniObject;
}

static ani_object StringArrayToObject(ani_env *env, const std::vector<std::string> values)
{
    ani_object arrayObj = nullptr;
    ani_class arrayCls = nullptr;
    if (ANI_OK != env->FindClass("Lescompat/Array;", &arrayCls)) {
        std::cerr << "FindClass Lescompat/Array; Failed" << std::endl;
    }

    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor)) {
        std::cerr << "Class_FindMethod <ctor> Failed" << std::endl;
        return arrayObj;
    }

    if (ANI_OK != env->Object_New(arrayCls, arrayCtor, &arrayObj, values.size())) {
        std::cerr << "Object_New Array Faild" << std::endl;
        return arrayObj;
    }
    ani_size index = 0;
    for (auto value : values) {
        ani_string ani_str;
        if (ANI_OK != env->String_NewUTF8(value.c_str(), value.size(), &ani_str)) {
            std::cerr << "String_NewUTF8 Faild " << std::endl;
            break;
        }
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, ani_str)) {
            std::cerr << "Object_CallMethodByName_Void  $_set Faild " << std::endl;
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
    if (ANI_OK != env->FindClass("Lescompat/Array;", &arrayCls)) {
        std::cerr << "FindClass Lescompat/Array; Failed" << std::endl;
        return arrayObj;
    }

    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor)) {
        std::cerr << "Class_FindMethod <ctor> Failed" << std::endl;
        return arrayObj;
    }

    if (ANI_OK != env->Object_New(arrayCls, arrayCtor, &arrayObj, values.size())) {
        std::cerr << "Object_New Array Faild" << std::endl;
        return arrayObj;
    }
    ani_size index = 0;
    for (auto value : values) {
        ani_object aniValue = BoolToObject(env, value);
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, aniValue)) {
            std::cerr << "Object_CallMethodByName_Void  $_set Faild " << std::endl;
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
    if (ANI_OK != env->FindClass("Lescompat/Array;", &arrayCls)) {
        std::cerr << "FindClass Lescompat/Array; Failed" << std::endl;
        return arrayObj;
    }

    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor)) {
        std::cerr << "Class_FindMethod <ctor> Failed" << std::endl;
        return arrayObj;
    }

    if (ANI_OK != env->Object_New(arrayCls, arrayCtor, &arrayObj, values.size())) {
        std::cerr << "Object_New Array Faild" << std::endl;
        return arrayObj;
    }
    ani_size index = 0;
    for (auto value : values) {
        ani_object aniValue = DoubleToObject(env, value);
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, aniValue)) {
            std::cerr << "Object_CallMethodByName_Void  $_set Faild " << std::endl;
            break;
        }
        index++;
    }
    return arrayObj;
}

static ani_object ObjectToANIObject(ani_env *env, const Object obj)
{
    ani_string aniString = StdStringToANIString(env, obj.valueStr);
    return static_cast<ani_object>(aniString);
}

static ani_object GetInner(ani_env *env, ani_object obj, ani_string key, ani_object valueType)
{
    ani_object aniObjectRet = nullptr;
    auto preferences = unwrapp(env, obj);
    if (preferences == nullptr) {
        std::cerr << "PutInner: unwrapp Preferences onject failed" << std::endl;
        return aniObjectRet;
    }
    auto keyValue = AniStringToStdStr(env, key);
    PreferencesValue res = preferences->Get(keyValue, ParsePreferencesValue(env, valueType));
    if (res.IsDouble()) {
        aniObjectRet = DoubleToObject(env, res);
    }

    if (res.IsBool()) {
        aniObjectRet = BoolToObject(env, res);
    }

    if (res.IsString()) {
        aniObjectRet = StringToObject(env, res);
    }

    if (res.IsBigInt()) {
        aniObjectRet = BigIntToObject(env, res);
    }

    if (res.IsUint8Array()) {
        aniObjectRet = Uint8ArrayToObject(env, static_cast<std::vector<uint8_t>>(res));
    }

    if (res.IsStringArray()) {
        aniObjectRet = StringArrayToObject(env, res);
    }

    if (res.IsBoolArray()) {
        aniObjectRet = BoolArrayToObject(env, res);
    }

    if (res.IsDoubleArray()) {
        aniObjectRet = DoubleArrayToObject(env, res);
    }

    if (res.IsObject()) {
        aniObjectRet = ObjectToANIObject(env, res);
    }
    return aniObjectRet;
}

static void PutInner(ani_env *env, ani_object obj, ani_string key, ani_object unionValue)
{
    auto preferences =  unwrapp(env, obj);
    if (preferences == nullptr) {
        std::cerr << "PutInner: unwrapp Preferences onject failed" << std::endl;
        return;
    }
    auto keyValue = AniStringToStdStr(env, key);
    PreferencesValue defValue = ParsePreferencesValue(env, unionValue);
    if (preferences->Put(keyValue, defValue) != 0) {
        std::cerr << "PutInner: put failed" << std::endl;
    }
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        std::cerr << "Unsupported ANI_VERSION_1" << std::endl;
        return ANI_ERROR;
    }

    ani_namespace ns {};
    if (ANI_OK != env->FindNamespace("L@ohos/data/preferences/preferences;", &ns)) {
        std::cerr << "Not found namespace 'Lpreferences'" << std::endl;
        return ANI_ERROR;
    }
    std::cerr << "After find namespace '" << ns << "'" << std::endl;

    std::array methods = {
        ani_native_function {"executeGetOpt", nullptr, reinterpret_cast<void *>(executeGetOpt)},
        ani_native_function {"executeGetName", nullptr, reinterpret_cast<void *>(executeGetName)},
        ani_native_function {"executeRemoveName", nullptr, reinterpret_cast<void *>(executeRemoveName)},
        ani_native_function {"executeRemoveOpt", nullptr, reinterpret_cast<void *>(executeRemoveOpt)},
        ani_native_function {"flushSync", nullptr, reinterpret_cast<void *>(flushSync)},
        ani_native_function {"getInner", nullptr, reinterpret_cast<void *>(GetInner)},
        ani_native_function {"putInner", nullptr, reinterpret_cast<void *>(PutInner)},
        ani_native_function {"deleteSyncInner", nullptr, reinterpret_cast<void *>(deleteSync)},
        ani_native_function {"hasSyncInner", nullptr, reinterpret_cast<void *>(hasSyncInner)},
    };

    std::cout << "Start bind native methods to '" << ns << "'" << std::endl;

    if (ANI_OK != env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size())) {
        std::cerr << "Cannot bind native methods to '" << ns << "'" << std::endl;
        return ANI_ERROR;
    };
    std::cout << "Finish bind native methods to '" << ns << "'" << std::endl;
    *result = ANI_VERSION_1;
    return ANI_OK;
}