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
#include "preferences_error.h"
#include "js_ani_ability.h"
#include "log_print.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "preferences_value.h"

using namespace OHOS::NativePreferences;
static ani_object PreferencesValueToObject(ani_env *env, PreferencesValue &res);

static void ThrowBusinessError(ani_env *env, int errCode, std::string&& errMsg)
{
    LOG_INFO("into ThrowBusinessError.");
    static const char *errorClsName = "@ohos.base.BusinessError";
    ani_class cls {};
    ani_status status = env->FindClass(errorClsName, &cls);
    if (status != ANI_OK) {
        LOG_ERROR("find class BusinessError %{public}s failed, status = %{public}d", errorClsName, status);
        return;
    }
    ani_method ctor;
    status = env->Class_FindMethod(cls, "<ctor>", ":", &ctor);
    if (status != ANI_OK) {
        LOG_ERROR("find method BusinessError.constructor failed, status = %{public}d", status);
        return;
    }
    ani_object errorObject;
    status = env->Object_New(cls, ctor, &errorObject);
    if (status != ANI_OK) {
        LOG_ERROR("create BusinessError object failed, status = %{public}d", status);
        return;
    }
    ani_double aniErrCode = static_cast<ani_double>(errCode);
    ani_string errMsgStr;
    status = env->String_NewUTF8(errMsg.c_str(), errMsg.size(), &errMsgStr);
    if (status != ANI_OK) {
        LOG_ERROR("convert errMsg to ani_string failed, status = %{public}d", status);
        return;
    }
    status = env->Object_SetFieldByName_Double(errorObject, "code", aniErrCode);
    if (status != ANI_OK) {
        LOG_ERROR("set error code failed, status = %{public}d", status);
        return;
    }
    status = env->Object_SetPropertyByName_Ref(errorObject, "message", errMsgStr);
    if (status != ANI_OK) {
        LOG_ERROR("set error message failed, status = %{public}d", status);
        return;
    }
    env->ThrowError(static_cast<ani_error>(errorObject));
    return;
}

static ani_string StdStringToANIString(ani_env* env, const std::string& str)
{
    ani_string stringAni = nullptr;
    if (ANI_OK != env->String_NewUTF8(str.c_str(), str.size(), &stringAni)) {
        LOG_INFO("String_NewUTF8 Failed");
    }
    return stringAni;
}

static bool GetContextPath(ani_env *env, ani_object context, std::string &dataGroupStr, std::string &contextPath)
{
    OHOS::PreferencesJsKit::JSAbility::ContextInfo contextInfo;
    std::shared_ptr<OHOS::PreferencesJsKit::JSError> err = GetContextInfo(env, context, dataGroupStr, contextInfo);
    if (err != nullptr) {
        LOG_ERROR("err is code: %{public}d, msg: %{public}s.", err->GetCode(), err->GetMsg().c_str());
        ThrowBusinessError(env,  err->GetCode(), err->GetMsg());
        return false;
    }
    contextPath = contextInfo.preferencesDir;
    return true;
}

static std::shared_ptr<Options> GetOptions(ani_env *env, ani_object context, std::string &dataGroupStr,
    std::string &nameStr)
{
    OHOS::PreferencesJsKit::JSAbility::ContextInfo contextInfo;
    std::shared_ptr<OHOS::PreferencesJsKit::JSError> err = GetContextInfo(env, context, dataGroupStr, contextInfo);
    if (err != nullptr) {
        LOG_ERROR("err is %{public}s.", err->GetMsg().c_str());
        ThrowBusinessError(env,  err->GetCode(), err->GetMsg());
        return nullptr;
    }
    std::string path = contextInfo.preferencesDir.append("/").append(nameStr);
    return std::make_shared<Options>(path, contextInfo.bundleName, dataGroupStr);
}

static int GetContextPathFromName(ani_env *env, ani_object context, ani_string name, std::string &path)
{
    std::string dataGroupStr = "";
    std::string contextPath;
    bool ret = GetContextPath(env, context, dataGroupStr, contextPath);
    if (!ret) {
        LOG_ERROR("GetContextPath failed.");
        return E_ERROR;
    }
    std::string nameStr = AniStringToStdStr(env, name);
    path = contextPath.append("/").append(nameStr);
    return E_OK;
}

static std::string GetDataGroupId(ani_env *env, ani_ref dataGroupId)
{
    std::string dataGroupIdStr;
    ani_boolean isNull = false;
    if (env->Reference_IsNull(dataGroupId, &isNull) != ANI_OK) {
        LOG_ERROR("Object_GetFieldByName_Ref dataGroupId is NUll failed.");
    }
    ani_boolean isUndefined = false;
    if (env->Reference_IsUndefined(dataGroupId, &isUndefined) != ANI_OK) {
        LOG_ERROR("Object_GetFieldByName_Ref dataGroupId is isUndefined failed.");
    }
    if (isNull || isUndefined) {
        dataGroupIdStr = "";
    } else {
        dataGroupIdStr = AniStringToStdStr(env, static_cast<ani_string>(dataGroupId));
    }
    return dataGroupIdStr;
}

static int GetContextPathFromOpt(ani_env *env, ani_object context, ani_object opt, std::string &path)
{
    ani_ref nameTmp;
    if (ANI_OK != env->Object_GetPropertyByName_Ref(opt, "name", &nameTmp)) {
        LOG_ERROR("Object_GetFieldByName_Ref name from opt Faild");
        return E_ERROR;
    }

    auto nameStr = AniStringToStdStr(env, static_cast<ani_string>(nameTmp));

    std::string dataGroupIdStr;
    ani_ref dataGroupId;
    if (env->Object_GetPropertyByName_Ref(opt, "dataGroupId", &dataGroupId) == ANI_OK) {
        LOG_INFO("Object_GetFieldByName_Ref dataGroupId from opt succeed.");
        dataGroupIdStr = GetDataGroupId(env, dataGroupId);
    }

    std::string contextPath;
    bool ret = GetContextPath(env, context, dataGroupIdStr, contextPath);
    if (!ret) {
        LOG_ERROR("GetContextPath failed.");
        return E_ERROR;
    }
    path = contextPath.append("/").append(nameStr);
    return E_OK;
}

static int ExecuteRemoveByName(ani_env *env, ani_object context, ani_string name)
{
    std::string path;
    int ret = GetContextPathFromName(env, context, name, path);
    if (ret != E_OK) {
        return ret;
    }
    return PreferencesHelper::RemovePreferencesFromCache(path);
}

static int ExecuteRemoveByOpt(ani_env *env, ani_object context, ani_object opt)
{
    std::string path;
    int ret = GetContextPathFromOpt(env, context, opt, path);
    if (ret != E_OK) {
        return ret;
    }
    return PreferencesHelper::RemovePreferencesFromCache(path);
}

static int DelPreferencesByOpt(ani_env *env, ani_object context, ani_object opt)
{
    std::string path;
    int ret = GetContextPathFromOpt(env, context, opt, path);
    if (ret != E_OK) {
        return ret;
    }
    return PreferencesHelper::DeletePreferences(path);
}

static int DelPreferencesByName(ani_env *env, ani_object context, ani_string name)
{
    std::string path;
    int ret = GetContextPathFromName(env, context, name, path);
    if (ret != E_OK) {
        return ret;
    }
    return PreferencesHelper::DeletePreferences(path);
}

static ani_object CreatePreferencesObj(ani_env *env, Options &options)
{
    int errCode = E_OK;
    std::shared_ptr<Preferences> preferences = PreferencesHelper::GetPreferences(options, errCode);
    if (preferences == nullptr) {
        LOG_ERROR("preferences is null, errCode=%{public}d", errCode);
        ThrowBusinessError(env, OHOS::PreferencesJsKit::E_INNER_ERROR, "GetPreferences failed!");
        return nullptr;
    }

    static const char *className = "@ohos.data.preferences.preferences.PreferencesImpl";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        LOG_ERROR("Not found className %{public}s.", className);
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        LOG_ERROR("get ctor Failed %{public}s.'", className);
        return nullptr;
    }
    ani_object prefencesObj = nullptr;
    if (ANI_OK != env->Object_New(cls, ctor, &prefencesObj, reinterpret_cast<ani_long>(preferences.get()))) {
        LOG_ERROR("Create Object Failed %{public}s.", className);
        return nullptr;
    }
    return prefencesObj;
}

static ani_object ExecuteGetByName(ani_env *env, ani_object context, ani_string name)
{
    LOG_INFO("in cpp ExecuteGetByName");
    auto nameStr = AniStringToStdStr(env, name);
    std::string dataGroupStr = "";
    auto optionsPtr = GetOptions(env, context, dataGroupStr, nameStr);
    if (optionsPtr == nullptr) {
        LOG_ERROR("GetOptions failed.");
        return nullptr;
    }
    return CreatePreferencesObj(env, *optionsPtr);
}

static ani_object ExecuteGetByOpt(ani_env *env, ani_object context, ani_object opt)
{
    ani_ref nameTmp;
    if (ANI_OK != env->Object_GetPropertyByName_Ref(opt, "name", &nameTmp)) {
        LOG_ERROR("Object_GetFieldByName_Ref name from opt Faild");
        return nullptr;
    }

    auto nameStr = AniStringToStdStr(env, static_cast<ani_string>(nameTmp));

    std::string dataGroupIdStr;
    ani_ref dataGroupId;
    if (env->Object_GetPropertyByName_Ref(opt, "dataGroupId", &dataGroupId) == ANI_OK) {
        LOG_INFO("Object_GetFieldByName_Ref dataGroupId from opt succeed.");
        dataGroupIdStr = GetDataGroupId(env, dataGroupId);
    }

    auto optionsPtr = GetOptions(env, context, dataGroupIdStr, nameStr);
    if (optionsPtr == nullptr) {
        LOG_ERROR("GetOptions failed.");
        return nullptr;
    }
    return CreatePreferencesObj(env, *optionsPtr);
}

static ani_object MapToObject(ani_env *env, std::map<std::string, PreferencesValue> &values)
{
    ani_object aniObject = nullptr;
    static const char *className = "std.core.Record";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        LOG_ERROR("Not found '%{public}s'.", className);
        return aniObject;
    }

    ani_method aniCtor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", ":", &aniCtor)) {
        LOG_ERROR("Class_GetMethod <ctor> Failed '%{public}s'.", className);
        return aniObject;
    }
    if (ANI_OK != env->Object_New(cls, aniCtor, &aniObject)) {
        LOG_ERROR("Object_New Failed '%{public}s'.", className);
        return aniObject;
    }
    ani_method setter;
    if (ANI_OK != env->Class_FindMethod(cls, "$_set", nullptr, &setter)) {
        LOG_ERROR("Class_GetMethod set Failed '%{public}s'.", className);
        return aniObject;
    }

    for (auto& value : values) {
        ani_string aniKey = StdStringToANIString(env, value.first);
        ani_object aniObjVal = PreferencesValueToObject(env, value.second);
        if (env->Object_CallMethod_Void(aniObject, setter, aniKey, aniObjVal) != ANI_OK) {
            LOG_INFO("Object_CallMethodByName_Void  $_set Faild ");
            break;
        }
    }
    return aniObject;
}

static ani_object GetAllSyncInner(ani_env *env, ani_object obj)
{
    LOG_INFO("into GetAllSyncInner.");
    auto preferences = NativeObjectWrapper<Preferences>::Unwrap(env, obj);
    if (preferences != nullptr) {
        std::map<std::string, PreferencesValue> values = preferences->GetAll();
        return MapToObject(env, values);
    }
    return nullptr;
}

static int DeleteSync(ani_env *env, ani_object obj, ani_string key)
{
    int32_t errCode = E_ERROR;
    auto preferences = NativeObjectWrapper<Preferences>::Unwrap(env, obj);
    if (preferences != nullptr) {
        auto key_str = AniStringToStdStr(env, key);
        errCode = preferences->Delete(key_str);
    }
    return errCode;
}

static bool HasSyncInner(ani_env *env, ani_object obj, ani_string key)
{
    bool ret = false;
    auto preferences =  NativeObjectWrapper<Preferences>::Unwrap(env, obj);
    if (preferences != nullptr) {
        auto key_str = AniStringToStdStr(env, key);
        ret = preferences->HasKey(key_str);
    }
    return ret;
}

static int FlushSync(ani_env *env, ani_object obj)
{
    int32_t errCode = E_ERROR;
    auto preferences =  NativeObjectWrapper<Preferences>::Unwrap(env, obj);
    if (preferences != nullptr) {
        errCode = preferences->FlushSync();
    }
    return errCode;
}

static OHOS::NativePreferences::Object AniObjectToNativeObject(ani_env* env, ani_object unionValue)
{
    ani_class objCls;
    if (ANI_OK != env->FindClass("std.core.Object", &objCls)) {
        LOG_ERROR("Not found class 'Lstd/core/Object;'");
        return PreferencesValue(static_cast<int>(0));
    }
    ani_method toStringMethod;
    if (ANI_OK != env->Class_FindMethod(objCls, "toString", ":C{std.core.String}", &toStringMethod)) {
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
    if (unionAccessor.IsInstanceOf("std.core.Double")) {
        env->Object_CallMethodByName_Double(unionValue, "toDouble", nullptr, &value);
        return static_cast<double>(value);
    }

    if (unionAccessor.IsInstanceOf("std.core.String")) {
        std::string stringValue = AniStringToStdStr(env, static_cast<ani_string>(unionValue));
        return stringValue;
    }

    ani_boolean boolValue = 0;
    if (unionAccessor.IsInstanceOf("std.core.Boolean")) {
        if (ANI_OK != env->Object_CallMethodByName_Boolean(unionValue, "toBoolean", nullptr, &boolValue)) {
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

    if (unionAccessor.IsInstanceOf("std.core.Object")) {
        return AniObjectToNativeObject(env, unionValue);
    }

    LOG_INFO("Cannot find specified type");
    return PreferencesValue(static_cast<int>(0));
}

static ani_object DoubleToObject(ani_env *env, double value)
{
    ani_object aniObject = nullptr;
    ani_double doubleValue = static_cast<ani_double>(value);
    static const char *className = "std.core.Double";
    ani_class aniClass;
    if (ANI_OK != env->FindClass(className, &aniClass)) {
        LOG_ERROR("Not found '%{public}s'.", className);
        return aniObject;
    }
    ani_method personInfoCtor;
    if (ANI_OK != env->Class_FindMethod(aniClass, "<ctor>", "d:", &personInfoCtor)) {
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
    static const char *className = "std.core.Boolean";
    ani_class aniClass;
    if (ANI_OK != env->FindClass(className, &aniClass)) {
        LOG_ERROR("Not found '%{public}s.'", className);
        return aniObject;
    }

    ani_method personInfoCtor;
    if (ANI_OK != env->Class_FindMethod(aniClass, "<ctor>", "z:", &personInfoCtor)) {
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

static ani_object BigIntToObject(ani_env *env, int64_t value)
{
    ani_object aniObject = nullptr;
    static const char *className = "std.core.BigInt";
    ani_class aniClass;
    if (ANI_OK != env->FindClass(className, &aniClass)) {
        LOG_ERROR("Not found '%{public}s'.", className);
        return aniObject;
    }

    ani_method personInfoCtor;
    if (ANI_OK != env->Class_FindMethod(aniClass, "<ctor>", "l:", &personInfoCtor)) {
        LOG_ERROR("Class_GetMethod Failed '%{public}s' <ctor>.", className);
        return aniObject;
    }
    if (ANI_OK != env->Object_New(aniClass, personInfoCtor, &aniObject, value)) {
        LOG_ERROR("Object_New Failed '%{public}s'.", className);
        return aniObject;
    }
    return aniObject;
}

static ani_object Uint8ArrayToObject(ani_env *env, const std::vector<uint8_t> values)
{
    ani_object aniObject = nullptr;
    ani_class arrayClass;
    ani_status retCode = env->FindClass("escompat.Uint8Array", &arrayClass);
    if (retCode != ANI_OK) {
        LOG_ERROR("Failed: env->FindClass()");
        return aniObject;
    }
    ani_method arrayCtor;
    retCode = env->Class_FindMethod(arrayClass, "<ctor>", "i:", &arrayCtor);
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
    if (ANI_OK != env->FindClass("escompat.Array", &arrayCls)) {
        LOG_INFO("FindClass Lescompat/Array; Failed");
    }

    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor)) {
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
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "iY:", index, ani_str)) {
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
    if (ANI_OK != env->FindClass("escompat.Array", &arrayCls)) {
        LOG_ERROR("FindClass Lescompat/Array; Failed");
        return arrayObj;
    }

    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor)) {
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
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "iY:", index, aniValue)) {
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
    if (ANI_OK != env->FindClass("escompat.Array", &arrayCls)) {
        LOG_ERROR("FindClass Lescompat/Array; Failed");
        return arrayObj;
    }

    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor)) {
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
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "iY:", index, aniValue)) {
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

static ani_object PreferencesValueToObject(ani_env *env, PreferencesValue &res)
{
    ani_object aniObjectRet = nullptr;
    if (res.IsDouble()) {
        aniObjectRet = DoubleToObject(env, res);
    }

    if (res.IsBool()) {
        aniObjectRet = BoolToObject(env, res);
    }

    if (res.IsString()) {
        aniObjectRet = StringToObject(env, res);
    }

    if (res.IsLong()) {
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

static ani_object GetInner(ani_env *env, ani_object obj, ani_string key, ani_object valueType)
{
    LOG_INFO("in GetInner");
    ani_object aniObjectRet = nullptr;
    auto preferences = NativeObjectWrapper<Preferences>::Unwrap(env, obj);
    if (preferences == nullptr) {
        LOG_ERROR("PutInner: unwrapp Preferences onject failed");
        return aniObjectRet;
    }
    auto keyValue = AniStringToStdStr(env, key);
    PreferencesValue res = preferences->Get(keyValue, ParsePreferencesValue(env, valueType));
    aniObjectRet = PreferencesValueToObject(env, res);
    return aniObjectRet;
}

static int PutInner(ani_env *env, ani_object obj, ani_string key, ani_object unionValue)
{
    int32_t errCode = E_ERROR;
    auto preferences =  NativeObjectWrapper<Preferences>::Unwrap(env, obj);
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

static int ClearSyncInner(ani_env *env, ani_object obj)
{
    int32_t errCode = E_ERROR;
    auto preferences =  NativeObjectWrapper<Preferences>::Unwrap(env, obj);
    if (preferences != nullptr) {
        errCode = preferences->Clear();
        LOG_INFO("Clear errCode is %{public}d.", errCode);
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
    if (ANI_OK != env->FindNamespace("@ohos.data.preferences.preferences;", &ns)) {
        LOG_ERROR("Not found namespace 'Lpreferences'");
        return ANI_ERROR;
    }
    LOG_INFO("After find namespace ohos/data/preferences/preferences.");

    std::array methods = {
        ani_native_function {"executeGetByOpt", nullptr, reinterpret_cast<void *>(ExecuteGetByOpt)},
        ani_native_function {"executeGetByName", nullptr, reinterpret_cast<void *>(ExecuteGetByName)},
        ani_native_function {"executeRemoveByName", nullptr, reinterpret_cast<void *>(ExecuteRemoveByName)},
        ani_native_function {"executeRemoveByOpt", nullptr, reinterpret_cast<void *>(ExecuteRemoveByOpt)},
        ani_native_function {"delPreByOpt", nullptr, reinterpret_cast<void *>(DelPreferencesByOpt)},
        ani_native_function {"delPreByName", nullptr, reinterpret_cast<void *>(DelPreferencesByName)},
        ani_native_function {"flushSync", nullptr, reinterpret_cast<void *>(FlushSync)},
        ani_native_function {"getInner", nullptr, reinterpret_cast<void *>(GetInner)},
        ani_native_function {"putInner", nullptr, reinterpret_cast<void *>(PutInner)},
        ani_native_function {"deleteSyncInner", nullptr, reinterpret_cast<void *>(DeleteSync)},
        ani_native_function {"hasSyncInner", nullptr, reinterpret_cast<void *>(HasSyncInner)},
        ani_native_function {"getAllSyncInner", nullptr, reinterpret_cast<void *>(GetAllSyncInner)},
        ani_native_function {"clearSyncInner", nullptr, reinterpret_cast<void *>(ClearSyncInner)},
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
