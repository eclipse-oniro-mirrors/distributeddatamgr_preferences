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
#include "js_ani_ability.h"
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
        LOG_ERROR("Not found class '%{public}s'.", errorClsName);
        return nullptr;
    }
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "Lstd/core/String;:V", &ctor)) {
        LOG_ERROR("Not found ctor '%{public}s'.", errorClsName);
        return nullptr;
    }
    ani_string error_msg;
    env->String_NewUTF8(errMsg.c_str(), 17U, &error_msg);
    ani_object errorObject;
    env->Object_New(cls, ctor, &errorObject, error_msg);
    return static_cast<ani_error>(errorObject);
}

void getContextPath(ani_env *env, ani_object context, std::string &dataGroupStr, std::string &contextPath)
{
    OHOS::PreferencesJsKit::JSAbility::ContextInfo contextInfo;
    std::shared_ptr<OHOS::PreferencesJsKit::JSError> err = GetContextInfo(env, context, dataGroupStr, contextInfo);
    if (err != nullptr) {
        LOG_ERROR("err is %{public}s.", err->GetMsg().c_str());
        ani_error aniErr = CreateAniError(env, err->GetMsg());
        env->ThrowError(aniErr);
    }
    LOG_INFO("preferencesDir is %{public}s.", contextInfo.preferencesDir.c_str());
    contextPath = contextInfo.preferencesDir;
    return;
}

static int executeRemoveByName(ani_env *env, ani_object context, ani_string name)
{
    int errCode = E_ERROR;
    ani_ref nameTmp;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "name", &nameTmp)) {
        LOG_INFO("Object_GetFieldByName_Ref name Faild.");
        nameTmp = static_cast<ani_ref>(name);
    }
    std::string nameStr = AniStringToStdStr(env, static_cast<ani_string>(nameTmp));
    LOG_INFO("in executeRemoveByName nameStr is: %{public}s .", nameStr.c_str());

    ani_ref dataGroupId;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "dataGroupId", &dataGroupId)) {
        LOG_ERROR("Object_GetFieldByName_Ref dataGroupId Faild from context.");
        return errCode;
    }
    auto dataGroupStr = AniStringToStdStr(env, static_cast<ani_string>(dataGroupId));
    LOG_INFO("in executeRemoveByName dataGroupId is: %{public}s.", dataGroupStr.c_str());

    std::string contextPath;
    getContextPath(env, context, dataGroupStr, contextPath);
    LOG_INFO("in executeRemoveByName contextPath is: %{public}s.", contextPath.c_str());
    std::string path = contextPath.append("/").append(nameStr);
    return PreferencesHelper::RemovePreferencesFromCache(path);
}

static int executeRemoveByOpt(ani_env *env, ani_object context, ani_object opt)
{
    int errCode = E_ERROR;
    ani_ref nameTmp;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "name", &nameTmp)) {
        LOG_INFO("Object_GetFieldByName_Ref name from context Faild.");
        if (ANI_OK != env->Object_GetPropertyByName_Ref(opt, "name", &nameTmp)) {
            LOG_ERROR("Object_GetFieldByName_Ref name from opt Faild.");
            return errCode;
        }
    }
    auto nameStr = AniStringToStdStr(env, static_cast<ani_string>(nameTmp));
    LOG_INFO("nameStr is %{public}s.", nameStr.c_str());

    ani_ref dataGroupId;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "dataGroupId", &dataGroupId)) {
        LOG_INFO("Object_GetFieldByName_Ref dataGroupId from context Faild.");
        if (ANI_OK != env->Object_GetPropertyByName_Ref(opt, "dataGroupId", &dataGroupId)) {
            LOG_ERROR("Object_GetFieldByName_Ref dataGroupId from opt Faild.");
            return errCode;
        }
    }
    auto dataGroupStr = AniStringToStdStr(env, static_cast<ani_string>(dataGroupId));
    LOG_INFO("dataGroupId is %{public}s.", dataGroupStr.c_str());

    std::string contextPath;
    getContextPath(env, context, dataGroupStr, contextPath);
    LOG_INFO("in executeRemoveByOpt contextPath is: %{public}s.", contextPath.c_str());
    std::string path = contextPath.append("/").append(nameStr);
    return PreferencesHelper::RemovePreferencesFromCache(path);
}

static ani_object createPreferencesObj(ani_env *env, Options &options)
{
    int errCode = E_OK;
    std::shared_ptr<Preferences> preferences = PreferencesHelper::GetPreferences(options, errCode);
    if (preferences == nullptr) {
        LOG_ERROR("preferences is null.");
        ani_error err = CreateAniError(env, "GetPreferences failed!");
        env->ThrowError(err);
    }

    ani_namespace ns {};
    if (ANI_OK != env->FindNamespace("L@ohos/data/preferences/preferences;", &ns)) {
        LOG_ERROR("Not found namespace 'Lpreferences'");
        return nullptr;
    }

    static const char *className = "LPreferencesImpl;";
    ani_class cls;
    if (ANI_OK != env->Namespace_FindClass(ns, className, &cls)) {
        LOG_ERROR("Not found className %{public}s.", className);
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        LOG_ERROR("get ctor Failed %{public}s.'", className);
        return nullptr;
    }
    ani_object prefences_obj = {};
    if (ANI_OK != env->Object_New(cls, ctor, &prefences_obj, reinterpret_cast<ani_long>(preferences.get()))) {
        LOG_ERROR("Create Object Failed %{public}s.", className);
        return nullptr;
    }
    LOG_INFO("Create preferences succeed.");
    return prefences_obj;
}

static ani_object executeGetByName(ani_env *env, ani_object context, ani_string name)
{
    LOG_INFO("in cpp executeGetByName");
    ani_ref nameTmp;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "name", &nameTmp)) {
        LOG_INFO("Object_GetFieldByName_Ref Faild");
        nameTmp = static_cast<ani_ref>(name);
    }
    auto nameStr = AniStringToStdStr(env, static_cast<ani_string>(nameTmp));
    LOG_INFO("nameStr is: %{public}s.", nameStr.c_str());

    ani_ref dataGroupId;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "dataGroupId", &dataGroupId)) {
        LOG_ERROR("Object_GetFieldByName_Ref Faild.");
        return nullptr;
    }
    auto dataGroupIdStr = AniStringToStdStr(env, static_cast<ani_string>(dataGroupId));
    LOG_INFO("dataGroupId is: %{public}s.", dataGroupIdStr.c_str());

    OHOS::PreferencesJsKit::JSAbility::ContextInfo contextInfo;
    std::shared_ptr<OHOS::PreferencesJsKit::JSError> err = GetContextInfo(env, context, dataGroupIdStr, contextInfo);
    if (err != nullptr) {
        LOG_ERROR("err is %{public}s.", err->GetMsg().c_str());
        ani_error aniErr = CreateAniError(env, err->GetMsg());
        env->ThrowError(aniErr);
    }
    LOG_INFO("preferencesDir is %{public}s.", contextInfo.preferencesDir.c_str());
    std::string path = contextInfo.preferencesDir.append("/").append(nameStr);
    LOG_INFO("path is %{public}s, bundleName is %{public}s.", path.c_str(), contextInfo.bundleName.c_str());
    Options options(path, contextInfo.bundleName, dataGroupIdStr);
    return createPreferencesObj(env, options);
}

static ani_object executeGetByOpt(ani_env *env, ani_object context, ani_object opt)
{
    LOG_INFO("in cpp executeGetByOpt");
    ani_ref nameTmp;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "name", &nameTmp)) {
        LOG_INFO("Object_GetFieldByName_Ref name from context Faild");
        if (ANI_OK != env->Object_GetPropertyByName_Ref(opt, "name", &nameTmp)) {
            LOG_ERROR("Object_GetFieldByName_Ref name from opt Faild");
            return nullptr;
        }
    }

    auto nameStr = AniStringToStdStr(env, static_cast<ani_string>(nameTmp));
    LOG_INFO("nameStr is : %{public}s.", nameStr.c_str());

    ani_ref dataGroupId;
    if (ANI_OK != env->Object_GetFieldByName_Ref(context, "dataGroupId", &dataGroupId)) {
        LOG_INFO("Object_GetFieldByName_Ref dataGroupId from context Faild");
        if (ANI_OK != env->Object_GetPropertyByName_Ref(opt, "dataGroupId", &dataGroupId)) {
            LOG_ERROR("Object_GetFieldByName_Ref dataGroupId from opt Faild");
            return nullptr;
        }
    }
    auto dataGroupIdStr = AniStringToStdStr(env, static_cast<ani_string>(dataGroupId));
    LOG_INFO("dataGroupId is: %{public}s.", dataGroupIdStr.c_str());

    OHOS::PreferencesJsKit::JSAbility::ContextInfo contextInfo;
    std::shared_ptr<OHOS::PreferencesJsKit::JSError> err = GetContextInfo(env, context, dataGroupIdStr, contextInfo);
    if (err != nullptr) {
        LOG_ERROR("err is %{public}s.", err->GetMsg().c_str());
        ani_error aniErr = CreateAniError(env, err->GetMsg());
        env->ThrowError(aniErr);
    }
    LOG_INFO("preferencesDir is %{public}s.", contextInfo.preferencesDir.c_str());
    std::string path = contextInfo.preferencesDir.append("/").append(nameStr);
    LOG_INFO("path is %{public}s, bundleName is %{public}s.", path.c_str(), contextInfo.bundleName.c_str());
    Options options(path, contextInfo.bundleName, dataGroupIdStr);
    return createPreferencesObj(env, options);
}

static Preferences* unwrapp(ani_env *env, ani_object object)
{
    ani_long context;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativePtr", &context)) {
        return nullptr;
    }
    LOG_INFO("nativePtr is %{public}lld.", static_cast<long long>(context));
    return reinterpret_cast<Preferences *>(context);
}

static int deleteSync(ani_env *env, ani_object obj, ani_string key)
{
    int32_t errCode = E_ERROR;
    auto preferences =  unwrapp(env, obj);
    if (preferences != nullptr) {
        auto key_str = AniStringToStdStr(env, key);
        LOG_INFO("key_str is %{public}s.", key_str.c_str());
        errCode = preferences->Delete(key_str);
        LOG_INFO("errCode is %{public}d.", errCode);
    }
    return errCode;
}

static bool hasSyncInner(ani_env *env, ani_object obj, ani_string key)
{
    bool ret = false;
    auto preferences =  unwrapp(env, obj);
    if (preferences != nullptr) {
        auto key_str = AniStringToStdStr(env, key);
        LOG_INFO("key_str is %{public}s.", key_str.c_str());
        ret = preferences->HasKey(key_str);
        LOG_INFO("ret is %{public}d.", ret);
    }
    return ret;
}

static int flushSync(ani_env *env, ani_object obj)
{
    int32_t errCode = E_OK;
    auto preferences =  unwrapp(env, obj);
    if (preferences != nullptr) {
        LOG_INFO("before flush...");
        errCode = preferences->FlushSync();
        LOG_INFO("after flush errCode is %{public}d.", errCode);
    }
    return errCode;
}

static OHOS::NativePreferences::Object AniObjectToNativeObject(ani_env* env, ani_object unionValue)
{
    ani_class objCls;
    if (ANI_OK != env->FindClass("Lstd/core/Object;", &objCls)) {
        LOG_ERROR("Not found class 'Lstd/core/Object;'");
        return PreferencesValue(static_cast<int>(0));
    }
    ani_method toStringMethod;
    if (ANI_OK != env->Class_FindMethod(objCls, "toString", ":Lstd/core/String;", &toStringMethod)) {
        LOG_ERROR("Class_GetMethod toString Failed.");
        return PreferencesValue(static_cast<int>(0));
    }
    ani_ref value = nullptr;
    if (ANI_OK != env->Object_CallMethod_Ref(unionValue, toStringMethod, &value)) {
        LOG_ERROR("Object_CallMethod_Ref toString Failed");
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
            LOG_ERROR("Object_CallMethodByName_Double unbox Failed");
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

    LOG_INFO("Cannot find specified type");
    return PreferencesValue(static_cast<int>(0));
}

static ani_string StdStringToANIString(ani_env* env, const std::string& str)
{
    ani_string stringAni = nullptr;
    if (ANI_OK != env->String_NewUTF8(str.c_str(), str.size(), &stringAni)) {
        LOG_INFO("String_NewUTF8 Failed");
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
        LOG_ERROR("Not found '%{public}s'.", className);
        return aniObject;
    }
    ani_method personInfoCtor;
    if (ANI_OK != env->Class_FindMethod(aniClass, "<ctor>", "D:V", &personInfoCtor)) {
        LOG_ERROR("Class_GetMethod Failed '%{public}s <ctor>.'", className);
        return aniObject;
    }

    if (ANI_OK != env->Object_New(aniClass, personInfoCtor, &aniObject, doubleValue)) {
        LOG_ERROR("Object_New Failed '%{public}s. <ctor>", className);
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
        LOG_ERROR("Not found '%{public}s.'", className);
        return aniObject;
    }

    ani_method personInfoCtor;
    if (ANI_OK != env->Class_FindMethod(aniClass, "<ctor>", "Z:V", &personInfoCtor)) {
        LOG_ERROR("Class_GetMethod Failed '%{public}s' <ctor>.", className);
        return aniObject;
    }

    if (ANI_OK != env->Object_New(aniClass, personInfoCtor, &aniObject, boolValue)) {
        LOG_ERROR("Object_New Failed '%{public}s' <ctor>.", className);
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
        LOG_ERROR("Not found '%{public}s'.", className);
        return aniObject;
    }

    ani_method personInfoCtor;
    if (ANI_OK != env->Class_FindMethod(aniClass, "<ctor>", "Lescompat/BigInt;:V", &personInfoCtor)) {
        LOG_ERROR("Class_GetMethod Failed '%{public}s' <ctor>.", className);
        return aniObject;
    }

    if (ANI_OK != env->Object_New(aniClass, personInfoCtor, &aniObject, longValue)) {
        LOG_ERROR("Object_New Failed '%{public}s'.", className);
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
        LOG_ERROR("Failed: env->FindClass()");
        return aniObject;
    }
    ani_method arrayCtor;
    retCode = env->Class_FindMethod(arrayClass, "<ctor>", "I:V", &arrayCtor);
    if (retCode != ANI_OK) {
        LOG_ERROR("Failed: env->Class_FindMethod()");
        return aniObject;
    }
    auto valueSize = values.size();
    retCode = env->Object_New(arrayClass, arrayCtor, &aniObject, valueSize);
    if (retCode != ANI_OK) {
        LOG_ERROR("Failed: env->Object_New()");
        return aniObject;
    }
    ani_ref buffer;
    env->Object_GetFieldByName_Ref(aniObject, "buffer", &buffer);
    void *bufData;
    size_t bufLength;
    retCode = env->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &bufData, &bufLength);
    if (retCode != ANI_OK) {
        LOG_INFO("Failed: env->ArrayBuffer_GetInfo()");
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
        LOG_INFO("FindClass Lescompat/Array; Failed");
    }

    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor)) {
        LOG_ERROR("Class_FindMethod <ctor> Failed");
        return arrayObj;
    }

    if (ANI_OK != env->Object_New(arrayCls, arrayCtor, &arrayObj, values.size())) {
        LOG_ERROR("Object_New Array Faild");
        return arrayObj;
    }
    ani_size index = 0;
    for (auto value : values) {
        ani_string ani_str;
        if (ANI_OK != env->String_NewUTF8(value.c_str(), value.size(), &ani_str)) {
            LOG_INFO("String_NewUTF8 Faild ");
            break;
        }
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, ani_str)) {
            LOG_INFO("Object_CallMethodByName_Void  $_set Faild ");
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
        LOG_ERROR("FindClass Lescompat/Array; Failed");
        return arrayObj;
    }

    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor)) {
        LOG_ERROR("Class_FindMethod <ctor> Failed");
        return arrayObj;
    }

    if (ANI_OK != env->Object_New(arrayCls, arrayCtor, &arrayObj, values.size())) {
        LOG_ERROR("Object_New Array Faild");
        return arrayObj;
    }
    ani_size index = 0;
    for (auto value : values) {
        ani_object aniValue = BoolToObject(env, value);
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, aniValue)) {
            LOG_INFO("Object_CallMethodByName_Void  $_set Faild ");
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
        LOG_ERROR("FindClass Lescompat/Array; Failed");
        return arrayObj;
    }

    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor)) {
        LOG_ERROR("Class_FindMethod <ctor> Failed");
        return arrayObj;
    }

    if (ANI_OK != env->Object_New(arrayCls, arrayCtor, &arrayObj, values.size())) {
        LOG_ERROR("Object_New Array Faild");
        return arrayObj;
    }
    ani_size index = 0;
    for (auto value : values) {
        ani_object aniValue = DoubleToObject(env, value);
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, aniValue)) {
            LOG_INFO("Object_CallMethodByName_Void  $_set Faild ");
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
    LOG_INFO("in GetInner");
    ani_object aniObjectRet = nullptr;
    auto preferences = unwrapp(env, obj);
    if (preferences == nullptr) {
        LOG_ERROR("PutInner: unwrapp Preferences onject failed");
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
    LOG_INFO("end in GetInner");
    return aniObjectRet;
}

static int PutInner(ani_env *env, ani_object obj, ani_string key, ani_object unionValue)
{
    int32_t errCode = E_ERROR;
    auto preferences =  unwrapp(env, obj);
    if (preferences == nullptr) {
        LOG_ERROR("PutInner: unwrapp Preferences onject failed");
        return errCode;
    }
    auto keyValue = AniStringToStdStr(env, key);
    PreferencesValue defValue = ParsePreferencesValue(env, unionValue);
    errCode = preferences->Put(keyValue, defValue);
    if (preferences->Put(keyValue, defValue) != 0) {
        LOG_INFO("PutInner: put failed errCode is %{public}d.", errCode);
    }
    return errCode;
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        LOG_ERROR("Unsupported ANI_VERSION_1");
        return ANI_ERROR;
    }

    ani_namespace ns {};
    if (ANI_OK != env->FindNamespace("L@ohos/data/preferences/preferences;", &ns)) {
        LOG_ERROR("Not found namespace 'Lpreferences'");
        return ANI_ERROR;
    }
    LOG_INFO("After find namespace ohos/data/preferences/preferences.");

    std::array methods = {
        ani_native_function {"executeGetByOpt", nullptr, reinterpret_cast<void *>(executeGetByOpt)},
        ani_native_function {"executeGetByName", nullptr, reinterpret_cast<void *>(executeGetByName)},
        ani_native_function {"executeRemoveByName", nullptr, reinterpret_cast<void *>(executeRemoveByName)},
        ani_native_function {"executeRemoveByOpt", nullptr, reinterpret_cast<void *>(executeRemoveByOpt)},
        ani_native_function {"flushSync", nullptr, reinterpret_cast<void *>(flushSync)},
        ani_native_function {"getInner", nullptr, reinterpret_cast<void *>(GetInner)},
        ani_native_function {"putInner", nullptr, reinterpret_cast<void *>(PutInner)},
        ani_native_function {"deleteSyncInner", nullptr, reinterpret_cast<void *>(deleteSync)},
        ani_native_function {"hasSyncInner", nullptr, reinterpret_cast<void *>(hasSyncInner)},
    };

    LOG_INFO("Start bind native methods to ohos/data/preferences/preferences.");

    if (ANI_OK != env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size())) {
        LOG_ERROR("Cannot bind native methods to ohos/data/preferences/preferences.");
        return ANI_ERROR;
    };
    LOG_INFO("Finish bind native methods to ohos/data/preferences/preferences.");
    *result = ANI_VERSION_1;
    return ANI_OK;
}