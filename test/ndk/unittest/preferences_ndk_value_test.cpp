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
 
void PreferencesNdkValueTest::SetUpTestCase(void) {}
void PreferencesNdkValueTest::TearDownTestCase(void) {}

void PreferencesNdkValueTest::SetUp(void) {}

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
HWTEST_F(PreferencesNdkValueTest, DISABLED_NDKPreferencesTest_001, TestSize.Level1)
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
HWTEST_F(PreferencesNdkValueTest, DISABLED_NDKPreferencesTest_002, TestSize.Level1)
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
HWTEST_F(PreferencesNdkValueTest, DISABLED_NDKPreferencesTest_003, TestSize.Level1)
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
HWTEST_F(PreferencesNdkValueTest, DISABLED_NDKPreferencesTest_004, TestSize.Level1)
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
HWTEST_F(PreferencesNdkValueTest, DISABLED_NDKPreferencesTest_005, TestSize.Level1)
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
HWTEST_F(PreferencesNdkValueTest, DISABLED_NDKPreferencesTestEmptyValueTest001, TestSize.Level1)
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
 * @tc.name: NDKPreferencesTestEmptyValueTest001
 * @tc.desc: test key and value
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: bluhuang
 */
HWTEST_F(PreferencesNdkValueTest, DISABLED_NDKPreferencesTestTypeTest001, TestSize.Level1)
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
}
