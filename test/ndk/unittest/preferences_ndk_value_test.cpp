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
#include <cctype>
#include <condition_variable>
#include <cstdint>
#include <fcntl.h>
#include <filesystem>
#include <functional>
#include <gtest/gtest.h>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <thread>
#include <vector>

#include "log_print.h"
#include "preferences_test_utils.h"
#include "oh_preferences_impl.h"
#include "oh_preferences.h"
#include "oh_preferences_err_code.h"
#include "oh_preferences_value.h"
#include "oh_preferences_option.h"
#include "preferences_helper.h"
 
using namespace testing::ext;

using namespace OHOS::PreferencesNdk;
using namespace OHOS::NativePreferences;
namespace {
class PreferencesNdkValueTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
 
void PreferencesNdkValueTest::SetUpTestCase(void)
{
    NdkTestUtils::CreateDirectoryRecursively("/data/test/");
}
void PreferencesNdkValueTest::TearDownTestCase(void) {}

void PreferencesNdkValueTest::SetUp(void)
{
    NdkTestUtils::CreateDirectoryRecursively("/data/test/");
}

void PreferencesNdkValueTest::TearDown(void) {}

enum class PrefDataType { UNASSIGNED, INT, STRING, BOOL };
 
static OH_PreferencesOption *GetCommonOption()
{
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    EXPECT_EQ(OH_PreferencesOption_SetFileName(option, "valueTestDbb"), PREFERENCES_OK);
    EXPECT_EQ(OH_PreferencesOption_SetBundleName(option, "com.uttest"), PREFERENCES_OK);
    EXPECT_EQ(OH_PreferencesOption_SetDataGroupId(option, "123"), PREFERENCES_OK);
    return option;
}

int PreferencesFlush(OH_Preferences *store)
{
    if (store == nullptr) {
        printf("preferences flush failed, store is null\n");
        return PREFERENCES_ERROR_BASE;
    }
    OH_PreferencesImpl *pref = static_cast<OH_PreferencesImpl *>(store);
    std::shared_ptr<OHOS::NativePreferences::Preferences> nativePreferences = pref->GetNativePreferences();
    return nativePreferences->FlushSync();
}

/**
 * @tc.name: NDKPreferencesTest_001
 * @tc.desc: test pref is nullptr
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Lirui
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesTest_001, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    std::string intKey = "ndktest_int_key";
    int value = 0;
    int res = 0;
    errCode = OH_Preferences_SetInt(nullptr, intKey.c_str(), 123);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);

    errCode = OH_Preferences_GetInt(nullptr, intKey.c_str(), &value);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);

    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    errCode = OH_Preferences_SetInt(pref, "", value);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);
    errCode = OH_Preferences_GetInt(pref, "", &res);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);

    errCode = OH_Preferences_SetInt(pref, nullptr, value);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);
    errCode = OH_Preferences_GetInt(pref, nullptr, &res);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(res, value);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/valueTestDb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesTest_002
 * @tc.desc: test pref is nullptr
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Lirui
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesTest_002, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    std::string stringKey = "ndktest_int_key";
    uint32_t len = 0;
    char *res = nullptr;
    char *resValue = nullptr;
    errCode = OH_Preferences_SetString(nullptr, stringKey.c_str(), "test");
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);

    errCode = OH_Preferences_GetString(nullptr, stringKey.c_str(), &res, &len);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);

    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    
    ASSERT_EQ(errCode, PREFERENCES_OK);

    errCode = OH_Preferences_SetString(pref, "", "test");
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);
    errCode = OH_Preferences_GetString(pref, "", &res, &len);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);

    errCode = OH_Preferences_SetString(pref, nullptr, "test");
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);
    errCode = OH_Preferences_GetString(pref, nullptr, &res, &len);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);

    errCode = OH_Preferences_SetString(pref, stringKey.c_str(), "123 test");
    ASSERT_EQ(errCode, PREFERENCES_OK);
    errCode = OH_Preferences_GetString(pref, stringKey.c_str(), &resValue, &len);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    EXPECT_EQ(strcmp(resValue, "123 test"), 0);
    EXPECT_EQ(PreferencesFlush(pref), PREFERENCES_OK);
    OH_Preferences_FreeString(resValue);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    pref = OH_Preferences_Open(option, &errCode);
    errCode = OH_Preferences_GetString(pref, stringKey.c_str(), &resValue, &len);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    EXPECT_EQ(strcmp(resValue, "123 test"), 0);
    (void)OH_PreferencesOption_Destroy(option);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/valueTestDb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesTest_003
 * @tc.desc: test pref is nullptr
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Lirui
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesTest_003, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    std::string boolKey = "ndktest_int_key";
    bool boolValue = false;
    errCode = OH_Preferences_SetBool(nullptr, boolKey.c_str(), true);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);

    errCode = OH_Preferences_GetBool(nullptr, boolKey.c_str(), &boolValue);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);

    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    
    errCode = OH_Preferences_SetBool(pref, "", false);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);
    errCode = OH_Preferences_GetBool(pref, "", &boolValue);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);

    errCode = OH_Preferences_SetBool(pref, nullptr, false);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);
    errCode = OH_Preferences_GetBool(pref, nullptr, &boolValue);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);

    errCode = OH_Preferences_SetBool(pref, " ", true);
    EXPECT_EQ(errCode, PREFERENCES_OK);
    errCode = OH_Preferences_GetBool(pref, " ", &boolValue);
    EXPECT_EQ(errCode, PREFERENCES_OK);
    ASSERT_EQ(boolValue, true);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/valueTestDb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesTest_004
 * @tc.desc: test pref is nullptr
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Lirui
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesTest_004, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    std::string boolKey = "ndktest_int_key";
    errCode = OH_Preferences_Delete(nullptr, boolKey.c_str());
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);

    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    errCode = OH_Preferences_Delete(pref, "");
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);
    errCode = OH_Preferences_Delete(pref, nullptr);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);

    errCode = OH_Preferences_SetBool(pref, boolKey.c_str(), false);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);
    bool res;
    errCode = OH_Preferences_GetBool(pref, boolKey.c_str(), &res);
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(res, false);
    (void)OH_PreferencesOption_Destroy(option);

    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/valueTestDb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesTest_005
 * @tc.desc: test key and value
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Lirui
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesTest_005, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    std::string boolKey = "ndktest_int_key";
    errCode = OH_Preferences_Delete(nullptr, boolKey.c_str());
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);

    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    (void)OH_PreferencesOption_Destroy(option);

    std::string stringKey(1024, 'a');
    errCode = OH_Preferences_SetString(pref, stringKey.c_str(), "test");
    EXPECT_EQ(errCode, PREFERENCES_OK);
    errCode = OH_Preferences_SetString(pref, stringKey.append("a").c_str(), "test");
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);
    std::string stringValue(16 * 1024 * 1024, 'a');
    errCode = OH_Preferences_SetString(pref, "test", stringValue.c_str());
    EXPECT_EQ(errCode, PREFERENCES_OK);
    errCode = OH_Preferences_SetString(pref, "test", stringValue.append("a").c_str());
    EXPECT_EQ(errCode, PREFERENCES_ERROR_INVALID_PARAM);
    
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/valueTestDb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesTestEmptyValueTest001
 * @tc.desc: test key and value
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Lirui
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesTestEmptyValueTest001, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    (void)OH_PreferencesOption_Destroy(option);

    uint32_t len = 0;
    char *valueGet = nullptr;
    EXPECT_EQ(OH_Preferences_SetString(pref, "abc", ""), PREFERENCES_OK);
    errCode = OH_Preferences_GetString(pref, "abc", &valueGet, &len);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    EXPECT_EQ(strcmp(valueGet, ""), 0);
    EXPECT_EQ(len, 1);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/valueTestDb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesTestTypeTest001
 * @tc.desc: test key and value
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: bluhuang
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesTestTypeTest001, TestSize.Level0)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    ASSERT_EQ(errCode, PREFERENCES_OK);
    (void)OH_PreferencesOption_Destroy(option);

    std::string key = "testKey";
    uint32_t len = 0;
    char *strValue = nullptr;
    bool boolValue = false;
    int intValue = -1;
    EXPECT_EQ(OH_Preferences_SetInt(pref, key.c_str(), 123), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_GetString(pref, key.c_str(), &strValue, &len), PREFERENCES_ERROR_KEY_NOT_FOUND);
    EXPECT_EQ(OH_Preferences_GetBool(pref, key.c_str(), &boolValue), PREFERENCES_ERROR_KEY_NOT_FOUND);
    EXPECT_EQ(OH_Preferences_GetInt(pref, key.c_str(), &intValue), PREFERENCES_OK);

    EXPECT_EQ(OH_Preferences_SetBool(pref, key.c_str(), true), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_GetInt(pref, key.c_str(), &intValue), PREFERENCES_ERROR_KEY_NOT_FOUND);
    EXPECT_EQ(OH_Preferences_GetString(pref, key.c_str(), &strValue, &len), PREFERENCES_ERROR_KEY_NOT_FOUND);
    EXPECT_EQ(OH_Preferences_GetBool(pref, key.c_str(), &boolValue), PREFERENCES_OK);

    EXPECT_EQ(OH_Preferences_SetString(pref, key.c_str(), ""), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_GetBool(pref, key.c_str(), &boolValue), PREFERENCES_ERROR_KEY_NOT_FOUND);
    EXPECT_EQ(OH_Preferences_GetInt(pref, key.c_str(), &intValue), PREFERENCES_ERROR_KEY_NOT_FOUND);
    EXPECT_EQ(OH_Preferences_GetString(pref, key.c_str(), &strValue, &len), PREFERENCES_OK);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/valueTestDb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesValueTest_CreateDestroy_001
 * @tc.desc: Test OH_PreferencesValue create and destroy
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_CreateDestroy_001, TestSize.Level0)
{
    // Test create success
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);
    
    // Test destroy valid value
    OH_PreferencesValue_Destroy(value);
    
    // Test destroy nullptr
    OH_PreferencesValue_Destroy(nullptr);
}

/**
 * @tc.name: NDKPreferencesValueTest_SetGetBasic_001
 * @tc.desc: Test basic set and get operations
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_SetGetBasic_001, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);
    
    // Test SetInt with null object
    int ret = OH_PreferencesValue_SetInt(nullptr, 123);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test SetInt success
    ret = OH_PreferencesValue_SetInt(value, 456);
    EXPECT_EQ(ret, PREFERENCES_OK);
    
    // Test GetInt with null object
    int intVal = 0;
    ret = OH_PreferencesValue_GetInt(value, &intVal);
    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_EQ(intVal, 456);
    
    // Test SetBool with null object
    ret = OH_PreferencesValue_SetBool(nullptr, true);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test SetBool success
    ret = OH_PreferencesValue_SetBool(value, true);
    EXPECT_EQ(ret, PREFERENCES_OK);
    
    // Test GetBool
    bool boolVal = false;
    ret = OH_PreferencesValue_GetBool(value, &boolVal);
    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_EQ(boolVal, true);
    
    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_SetGetString_001
 * @tc.desc: Test string set and get operations
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_SetGetString_001, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);
    
    // Test SetString with null object
    int ret = OH_PreferencesValue_SetString(nullptr, "test");
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test SetString with null value
    ret = OH_PreferencesValue_SetString(value, nullptr);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test SetString success
    ret = OH_PreferencesValue_SetString(value, "hello world");
    EXPECT_EQ(ret, PREFERENCES_OK);
    
    // Test GetString
    uint32_t len = 0;
    char* strVal = nullptr;
    ret = OH_PreferencesValue_GetString(value, &strVal, &len);
    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_STREQ(strVal, "hello world");
    EXPECT_GT(len, 0u);
    
    // Free the string
    OH_Preferences_FreeString(strVal);
    
    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_SetGetInt64_001
 * @tc.desc: Test int64 set and get operations
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_SetGetInt64_001, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);
    
    // Test SetInt64 with null object
    int ret = OH_PreferencesValue_SetInt64(nullptr, 123456789LL);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test SetInt64 success
    ret = OH_PreferencesValue_SetInt64(value, 9876543210LL);
    EXPECT_EQ(ret, PREFERENCES_OK);
    
    // Test GetInt64 with null object
    int64_t int64Val = 0;
    ret = OH_PreferencesValue_GetInt64(nullptr, &int64Val);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test GetInt64 with null value
    ret = OH_PreferencesValue_GetInt64(value, nullptr);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test GetInt64 success
    ret = OH_PreferencesValue_GetInt64(value, &int64Val);
    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_EQ(int64Val, 9876543210LL);
    
    // Test type mismatch
    OH_PreferencesValue_SetString(value, "not int64");
    ret = OH_PreferencesValue_GetInt64(value, &int64Val);
    EXPECT_EQ(ret, PREFERENCES_ERROR_KEY_NOT_FOUND);
    
    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_SetGetDouble_001
 * @tc.desc: Test double set and get operations
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_SetGetDouble_001, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);
    
    // Test SetDouble with null object
    int ret = OH_PreferencesValue_SetDouble(nullptr, 3.14159);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test SetDouble success
    ret = OH_PreferencesValue_SetDouble(value, 2.71828);
    EXPECT_EQ(ret, PREFERENCES_OK);
    
    // Test GetDouble with null params
    double doubleVal = 0.0;
    ret = OH_PreferencesValue_GetDouble(nullptr, &doubleVal);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_GetDouble(value, nullptr);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test GetDouble success
    ret = OH_PreferencesValue_GetDouble(value, &doubleVal);
    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_DOUBLE_EQ(doubleVal, 2.71828);
    
    // Test type mismatch
    OH_PreferencesValue_SetBool(value, true);
    ret = OH_PreferencesValue_GetDouble(value, &doubleVal);
    EXPECT_EQ(ret, PREFERENCES_ERROR_KEY_NOT_FOUND);
    
    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_SetGetIntArray_001
 * @tc.desc: Test int array set and get operations
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_SetGetIntArray_001, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);
    
    // Test SetIntArray with null params
    int intArray[] = {1, 2, 3, 4, 5};
    int ret = OH_PreferencesValue_SetIntArray(nullptr, intArray, 5);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_SetIntArray(value, nullptr, 5);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_SetIntArray(value, intArray, 0);
    EXPECT_EQ(ret, PREFERENCES_OK);
    
    // Test SetIntArray success
    ret = OH_PreferencesValue_SetIntArray(value, intArray, 5);
    EXPECT_EQ(ret, PREFERENCES_OK);
    
    // Test GetIntArray with null params
    int* outArray = nullptr;
    uint32_t count = 0;
    ret = OH_PreferencesValue_GetIntArray(nullptr, &outArray, &count);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_GetIntArray(value, nullptr, &count);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_GetIntArray(value, &outArray, nullptr);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test GetIntArray success
    ret = OH_PreferencesValue_GetIntArray(value, &outArray, &count);
    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_EQ(count, 5u);
    for (uint32_t i = 0; i < count; ++i) {
        EXPECT_EQ(outArray[i], intArray[i]);
    }
    
    // Free the array
    free(outArray);
    
    // Test type mismatch
    OH_PreferencesValue_SetString(value, "not array");
    ret = OH_PreferencesValue_GetIntArray(value, &outArray, &count);
    EXPECT_EQ(ret, PREFERENCES_ERROR_KEY_NOT_FOUND);
    
    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_SetGetBoolArray_001
 * @tc.desc: Test bool array set and get operations
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_SetGetBoolArray_001, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);
    
    // Test SetBoolArray with null params
    bool boolArray[] = {true, false, true, false};
    int ret = OH_PreferencesValue_SetBoolArray(nullptr, boolArray, 4);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_SetBoolArray(value, nullptr, 4);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test SetBoolArray success
    ret = OH_PreferencesValue_SetBoolArray(value, boolArray, 4);
    EXPECT_EQ(ret, PREFERENCES_OK);
    
    // Test GetBoolArray with null params
    bool* outArray = nullptr;
    uint32_t count = 0;
    ret = OH_PreferencesValue_GetBoolArray(nullptr, &outArray, &count);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_GetBoolArray(value, nullptr, &count);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_GetBoolArray(value, &outArray, nullptr);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test GetBoolArray success
    ret = OH_PreferencesValue_GetBoolArray(value, &outArray, &count);
    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_EQ(count, 4u);
    for (uint32_t i = 0; i < count; ++i) {
        EXPECT_EQ(outArray[i], boolArray[i]);
    }
    
    // Free the array
    free(outArray);
    
    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_SetGetStringArray_001
 * @tc.desc: Test string array set and get operations
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_SetGetStringArray_001, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);
    
    // Test SetStringArray with null params
    const char* strArray[] = {"hello", "world", "test"};
    int ret = OH_PreferencesValue_SetStringArray(nullptr, strArray, 3);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_SetStringArray(value, nullptr, 3);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test SetStringArray with null string in array
    const char* invalidStrArray[] = {"valid", nullptr, "test"};
    ret = OH_PreferencesValue_SetStringArray(value, invalidStrArray, 3);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test SetStringArray success
    ret = OH_PreferencesValue_SetStringArray(value, strArray, 3);
    EXPECT_EQ(ret, PREFERENCES_OK);
    
    // Test GetStringArray with null params
    char** outArray = nullptr;
    uint32_t count = 0;
    ret = OH_PreferencesValue_GetStringArray(nullptr, &outArray, &count);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_GetStringArray(value, nullptr, &count);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_GetStringArray(value, &outArray, nullptr);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test GetStringArray success
    ret = OH_PreferencesValue_GetStringArray(value, &outArray, &count);
    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_EQ(count, 3u);
    for (uint32_t i = 0; i < count; ++i) {
        EXPECT_STREQ(outArray[i], strArray[i]);
    }
    
    // Free the string array
    for (uint32_t i = 0; i < count; ++i) {
        free(outArray[i]);
    }
    free(outArray);
    
    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_SetGetInt64Array_001
 * @tc.desc: Test int64 array set and get operations
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_SetGetInt64Array_001, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);
    
    // Test SetInt64Array with null params
    int64_t int64Array[] = {1234567890LL, 9876543210LL, -1234567890LL};
    int ret = OH_PreferencesValue_SetInt64Array(nullptr, int64Array, 3);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_SetInt64Array(value, nullptr, 3);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_SetInt64Array(value, int64Array, 0);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test SetInt64Array success
    ret = OH_PreferencesValue_SetInt64Array(value, int64Array, 3);
    EXPECT_EQ(ret, PREFERENCES_OK);
    
    // Test GetInt64Array
    int64_t* outArray = nullptr;
    uint32_t count = 0;
    ret = OH_PreferencesValue_GetInt64Array(value, &outArray, &count);
    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_EQ(count, 3u);
    for (uint32_t i = 0; i < count; ++i) {
        EXPECT_EQ(outArray[i], int64Array[i]);
    }
    
    free(outArray);
    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_SetGetDoubleArray_001
 * @tc.desc: Test double array set and get operations
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_SetGetDoubleArray_001, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);
    
    // Test SetDoubleArray with null params
    double doubleArray[] = {1.1, 2.2, 3.3, 4.4};
    int ret = OH_PreferencesValue_SetDoubleArray(nullptr, doubleArray, 4);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_SetDoubleArray(value, nullptr, 4);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test SetDoubleArray success
    ret = OH_PreferencesValue_SetDoubleArray(value, doubleArray, 4);
    EXPECT_EQ(ret, PREFERENCES_OK);
    
    // Test GetDoubleArray
    double* outArray = nullptr;
    uint32_t count = 0;
    ret = OH_PreferencesValue_GetDoubleArray(value, &outArray, &count);
    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_EQ(count, 4u);
    for (uint32_t i = 0; i < count; ++i) {
        EXPECT_DOUBLE_EQ(outArray[i], doubleArray[i]);
    }
    
    free(outArray);
    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_SetGetBlob_001
 * @tc.desc: Test blob set and get operations
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_SetGetBlob_001, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);
    
    // Test SetBlob with null params
    uint8_t blobData[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    int ret = OH_PreferencesValue_SetBlob(nullptr, blobData, 5);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_SetBlob(value, nullptr, 5);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test SetBlob success
    ret = OH_PreferencesValue_SetBlob(value, blobData, 5);
    EXPECT_EQ(ret, PREFERENCES_OK);
    
    // Test GetBlob with null params
    uint8_t* outBlob = nullptr;
    uint32_t count = 0;
    ret = OH_PreferencesValue_GetBlob(nullptr, &outBlob, &count);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_GetBlob(value, nullptr, &count);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    ret = OH_PreferencesValue_GetBlob(value, &outBlob, nullptr);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    
    // Test GetBlob success
    ret = OH_PreferencesValue_GetBlob(value, &outBlob, &count);
    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_EQ(count, 5u);
    for (uint32_t i = 0; i < count; ++i) {
        EXPECT_EQ(outBlob[i], blobData[i]);
    }
    
    free(outBlob);
    
    // Test type mismatch
    OH_PreferencesValue_SetInt(value, 123);
    ret = OH_PreferencesValue_GetBlob(value, &outBlob, &count);
    EXPECT_EQ(ret, PREFERENCES_ERROR_KEY_NOT_FOUND);
    
    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_EdgeCases_001
 * @tc.desc: Test edge cases and error conditions
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_EdgeCases_001, TestSize.Level0)
{
    // Test empty string array
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);
    
    const char* emptyArray[] = {};
    int ret = OH_PreferencesValue_SetStringArray(value, emptyArray, 0);
    EXPECT_EQ(ret, PREFERENCES_OK);
    
    char** outArray = nullptr;
    uint32_t count = 0;
    ret = OH_PreferencesValue_GetStringArray(value, &outArray, &count);
    EXPECT_EQ(ret, PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(count, 0u);
    
    OH_PreferencesValue_Destroy(value);
    
    // Test very large array (within uint32_t limits)
    value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);
    
    std::vector<int> largeArray(1000);
    for (size_t i = 0; i < largeArray.size(); ++i) {
        largeArray[i] = static_cast<int>(i);
    }
    
    ret = OH_PreferencesValue_SetIntArray(value, largeArray.data(), static_cast<uint32_t>(largeArray.size()));
    EXPECT_EQ(ret, PREFERENCES_OK);
    
    int* outLargeArray = nullptr;
    uint32_t largeCount = 0;
    ret = OH_PreferencesValue_GetIntArray(value, &outLargeArray, &largeCount);
    EXPECT_EQ(ret, PREFERENCES_OK);
    EXPECT_EQ(largeCount, 1000u);
    
    free(outLargeArray);
    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_GetValueType_001
 * @tc.desc: Test GetValueType with null object
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_GetValueType_001, TestSize.Level0)
{
    Preference_ValueType type = OH_PreferencesValue_GetValueType(nullptr);
    EXPECT_EQ(type, PREFERENCE_TYPE_NULL);
}

/**
 * @tc.name: NDKPreferencesValueTest_GetValueType_002
 * @tc.desc: Test GetValueType for all data types
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_GetValueType_002, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);

    OH_PreferencesValue_SetInt(value, 123);
    Preference_ValueType type = OH_PreferencesValue_GetValueType(value);
    EXPECT_EQ(type, PREFERENCE_TYPE_INT);

    OH_PreferencesValue_SetBool(value, true);
    type = OH_PreferencesValue_GetValueType(value);
    EXPECT_EQ(type, PREFERENCE_TYPE_BOOL);

    OH_PreferencesValue_SetString(value, "test string");
    type = OH_PreferencesValue_GetValueType(value);
    EXPECT_EQ(type, PREFERENCE_TYPE_STRING);

    OH_PreferencesValue_SetInt64(value, 1234567890LL);
    type = OH_PreferencesValue_GetValueType(value);
    EXPECT_EQ(type, PREFERENCE_TYPE_INT64);

    OH_PreferencesValue_SetDouble(value, 3.14159);
    type = OH_PreferencesValue_GetValueType(value);
    EXPECT_EQ(type, PREFERENCE_TYPE_DOUBLE);

    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_GetValueType_003
 * @tc.desc: Test GetValueType for array data types
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_GetValueType_003, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);

    int intArray[] = {1, 2, 3};
    OH_PreferencesValue_SetIntArray(value, intArray, 3);
    Preference_ValueType type = OH_PreferencesValue_GetValueType(value);
    EXPECT_EQ(type, PREFERENCE_TYPE_INT_ARRAY);

    bool boolArray[] = {true, false, true};
    OH_PreferencesValue_SetBoolArray(value, boolArray, 3);
    type = OH_PreferencesValue_GetValueType(value);
    EXPECT_EQ(type, PREFERENCE_TYPE_BOOL_ARRAY);

    const char* strArray[] = {"hello", "world"};
    OH_PreferencesValue_SetStringArray(value, strArray, 2);
    type = OH_PreferencesValue_GetValueType(value);
    EXPECT_EQ(type, PREFERENCE_TYPE_STRING_ARRAY);

    double doubleArray[] = {1.1, 2.2, 3.3};
    OH_PreferencesValue_SetDoubleArray(value, doubleArray, 3);
    type = OH_PreferencesValue_GetValueType(value);
    EXPECT_EQ(type, PREFERENCE_TYPE_DOUBLE_ARRAY);

    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_GetValueType_004
 * @tc.desc: Test GetValueType for blob and int64 array types
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_GetValueType_004, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);

    uint8_t blobData[] = {0x01, 0x02, 0x03};
    OH_PreferencesValue_SetBlob(value, blobData, 3);
    Preference_ValueType type = OH_PreferencesValue_GetValueType(value);
    EXPECT_EQ(type, PREFERENCE_TYPE_BLOB);

    int64_t int64Array[] = {1234567890LL, 9876543210LL};
    OH_PreferencesValue_SetInt64Array(value, int64Array, 2);
    type = OH_PreferencesValue_GetValueType(value);
    EXPECT_EQ(type, PREFERENCE_TYPE_INT64_ARRAY);

    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_GetValueType_005
 * @tc.desc: Test GetValueType for empty and default value
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_GetValueType_005, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);
    
    Preference_ValueType type = OH_PreferencesValue_GetValueType(value);
    EXPECT_EQ(type, PREFERENCE_TYPE_NULL);

    const char* emptyStrArray[] = {};
    OH_PreferencesValue_SetStringArray(value, emptyStrArray, 0);
    type = OH_PreferencesValue_GetValueType(value);
    EXPECT_EQ(type, PREFERENCE_TYPE_STRING_ARRAY);

    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_GetValueType_006
 * @tc.desc: Test GetValueType type transitions
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_GetValueType_006, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);
    EXPECT_EQ(OH_PreferencesValue_GetValueType(value), PREFERENCE_TYPE_NULL);

    OH_PreferencesValue_SetInt(value, 100);
    EXPECT_EQ(OH_PreferencesValue_GetValueType(value), PREFERENCE_TYPE_INT);

    OH_PreferencesValue_SetString(value, "transition test");
    EXPECT_EQ(OH_PreferencesValue_GetValueType(value), PREFERENCE_TYPE_STRING);

    OH_PreferencesValue_SetBool(value, false);
    EXPECT_EQ(OH_PreferencesValue_GetValueType(value), PREFERENCE_TYPE_BOOL);

    double doubleArray[] = {1.5, 2.5};
    OH_PreferencesValue_SetDoubleArray(value, doubleArray, 2);
    EXPECT_EQ(OH_PreferencesValue_GetValueType(value), PREFERENCE_TYPE_DOUBLE_ARRAY);

    bool boolArray[] = {true};
    OH_PreferencesValue_SetBoolArray(value, boolArray, 1);
    EXPECT_EQ(OH_PreferencesValue_GetValueType(value), PREFERENCE_TYPE_BOOL_ARRAY);

    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_GetValueType_007
 * @tc.desc: Test GetValueType with large data
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_GetValueType_007, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);

    std::string largeString(1024, 'A');
    OH_PreferencesValue_SetString(value, largeString.c_str());
    EXPECT_EQ(OH_PreferencesValue_GetValueType(value), PREFERENCE_TYPE_STRING);

    std::vector<int> largeArray(100);
    for (size_t i = 0; i < largeArray.size(); ++i) {
        largeArray[i] = static_cast<int>(i);
    }
    OH_PreferencesValue_SetIntArray(value, largeArray.data(), static_cast<uint32_t>(largeArray.size()));
    EXPECT_EQ(OH_PreferencesValue_GetValueType(value), PREFERENCE_TYPE_INT_ARRAY);

    std::vector<uint8_t> largeBlob(500);
    for (size_t i = 0; i < largeBlob.size(); ++i) {
        largeBlob[i] = static_cast<uint8_t>(i % 256);
    }
    OH_PreferencesValue_SetBlob(value, largeBlob.data(), static_cast<uint32_t>(largeBlob.size()));
    EXPECT_EQ(OH_PreferencesValue_GetValueType(value), PREFERENCE_TYPE_BLOB);

    OH_PreferencesValue_Destroy(value);
}

/**
 * @tc.name: NDKPreferencesValueTest_GetValueType_008
 * @tc.desc: Test GetValueType with single element arrays
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(PreferencesNdkValueTest, NDKPreferencesValueTest_GetValueType_008, TestSize.Level0)
{
    OH_PreferencesValue* value = OH_PreferencesValue_Create();
    EXPECT_NE(value, nullptr);

    // Test single element int array
    int singleIntArray[] = {42};
    OH_PreferencesValue_SetIntArray(value, singleIntArray, 1);
    EXPECT_EQ(OH_PreferencesValue_GetValueType(value), PREFERENCE_TYPE_INT_ARRAY);

    // Test single element string array
    const char* singleStrArray[] = {"single"};
    OH_PreferencesValue_SetStringArray(value, singleStrArray, 1);
    EXPECT_EQ(OH_PreferencesValue_GetValueType(value), PREFERENCE_TYPE_STRING_ARRAY);

    // Test single element bool array
    bool singleBoolArray[] = {true};
    OH_PreferencesValue_SetBoolArray(value, singleBoolArray, 1);
    EXPECT_EQ(OH_PreferencesValue_GetValueType(value), PREFERENCE_TYPE_BOOL_ARRAY);

    // Test single element double array
    double singleDoubleArray[] = {3.14};
    OH_PreferencesValue_SetDoubleArray(value, singleDoubleArray, 1);
    EXPECT_EQ(OH_PreferencesValue_GetValueType(value), PREFERENCE_TYPE_DOUBLE_ARRAY);

    // Test single element int64 array
    int64_t singleInt64Array[] = {123456789LL};
    OH_PreferencesValue_SetInt64Array(value, singleInt64Array, 1);
    EXPECT_EQ(OH_PreferencesValue_GetValueType(value), PREFERENCE_TYPE_INT64_ARRAY);

    OH_PreferencesValue_Destroy(value);
}
}
