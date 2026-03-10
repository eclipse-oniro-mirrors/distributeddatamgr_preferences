/*
* Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "preferences.h"
#include <gtest/gtest.h>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>

#include "log_print.h"
#include "preferences_errno.h"
#include "preferences_file_operation.h"
#include "preferences_helper.h"
#include "preferences_observer.h"
#include "preferences_utils.h"
#include "preferences_value.h"

using namespace testing::ext;
using namespace OHOS::NativePreferences;

namespace {
const std::string KEY_TEST_INT_ELEMENT = "key_test_int";
const std::string KEY_TEST_LONG_ELEMENT = "key_test_long";
const std::string KEY_TEST_FLOAT_ELEMENT = "key_test_float";
const std::string KEY_TEST_DOUBLE_ELEMENT = "key_test_double";
const std::string KEY_TEST_BOOL_ELEMENT = "key_test_bool";
const std::string KEY_TEST_STRING_ELEMENT = "key_test_string";
const std::string KEY_TEST_STRING_ARRAY_ELEMENT = "key_test_string_array";
const std::string KEY_TEST_BOOL_ARRAY_ELEMENT = "key_test_bool_array";
const std::string KEY_TEST_DOUBLE_ARRAY_ELEMENT = "key_test_double_array";
const std::string KEY_TEST_UINT8_ARRAY_ELEMENT = "key_test_uint8_array";
const std::string KEY_TEST_OBJECT_ELEMENT = "key_test_object";
const std::string KEY_TEST_BIGINT_ELEMENT = "key_test_bigint";

class PreferencesAdvancedTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static std::shared_ptr<Preferences> pref;
};

std::shared_ptr<Preferences> PreferencesAdvancedTest::pref = nullptr;

void PreferencesAdvancedTest::SetUpTestCase(void)
{
}

void PreferencesAdvancedTest::TearDownTestCase(void)
{
}

void PreferencesAdvancedTest::SetUp(void)
{
    int errCode = E_OK;
    pref = PreferencesHelper::GetPreferences("/data/test/advanced", errCode);
    EXPECT_EQ(errCode, E_OK);
}

void PreferencesAdvancedTest::TearDown(void)
{
    pref = nullptr;
    int ret = PreferencesHelper::DeletePreferences("/data/test/advanced");
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name PreferencesAdvancedTest_001
* @tc.desc test put and get string value
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_001, TestSize.Level0)
{
    std::string testValue = "hello world test string";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "default");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_002
* @tc.desc test put and get integer value
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_002, TestSize.Level0)
{
    int testValue = 1234567890;
    int ret = pref->PutInt(KEY_TEST_INT_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    int retrievedValue = pref->GetInt(KEY_TEST_INT_ELEMENT, 0);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_003
* @tc.desc test put and get float value
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_003, TestSize.Level0)
{
    float testValue = 1234.567f;
    int ret = pref->PutFloat(KEY_TEST_FLOAT_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    float retrievedValue = pref->GetFloat(KEY_TEST_FLOAT_ELEMENT, 0.0f);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_004
* @tc.desc test put and get boolean true
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_004, TestSize.Level0)
{
    bool testValue = true;
    int ret = pref->PutBool(KEY_TEST_BOOL_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    bool retrievedValue = pref->GetBool(KEY_TEST_BOOL_ELEMENT, false);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_005
* @tc.desc test put and get boolean false
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_005, TestSize.Level0)
{
    bool testValue = false;
    int ret = pref->PutBool(KEY_TEST_BOOL_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    bool retrievedValue = pref->GetBool(KEY_TEST_BOOL_ELEMENT, true);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_006
* @tc.desc test put and get long value
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_006, TestSize.Level0)
{
    int64_t testValue = 1234567890123LL;
    int ret = pref->PutLong(KEY_TEST_LONG_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    int64_t retrievedValue = pref->GetLong(KEY_TEST_LONG_ELEMENT, 0LL);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_010
* @tc.desc test clear preferences
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_010, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING_ELEMENT, "test value");
    pref->PutInt(KEY_TEST_INT_ELEMENT, 123);
    
    int ret = pref->Clear();
    EXPECT_EQ(ret, E_OK);
    
    bool hasString = pref->HasKey(KEY_TEST_STRING_ELEMENT);
    bool hasInt = pref->HasKey(KEY_TEST_INT_ELEMENT);
    EXPECT_EQ(hasString, false);
    EXPECT_EQ(hasInt, false);
}

/**
* @tc.name PreferencesAdvancedTest_011
* @tc.desc test flush preferences
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_011, TestSize.Level0)
{
    std::string testValue = "flush test value";
    pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    
    int ret = pref->FlushSync();
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_012
* @tc.desc test has key exists
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_012, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING_ELEMENT, "test");
    
    bool hasKey = pref->HasKey(KEY_TEST_STRING_ELEMENT);
    EXPECT_EQ(hasKey, true);
}

/**
* @tc.name PreferencesAdvancedTest_013
* @tc.desc test has key not exists
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_013, TestSize.Level0)
{
    bool hasKey = pref->HasKey("non_existent_key");
    EXPECT_EQ(hasKey, false);
}

/**
* @tc.name PreferencesAdvancedTest_014
* @tc.desc test get default value
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_014, TestSize.Level0)
{
    std::string defaultValue = "default_value_test";
    std::string retrievedValue = pref->GetString("nonexistent_key", defaultValue);
    EXPECT_EQ(retrievedValue, defaultValue);
}

/**
* @tc.name PreferencesAdvancedTest_015
* @tc.desc test update existing key
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_015, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING_ELEMENT, "initial");
    pref->PutString(KEY_TEST_STRING_ELEMENT, "updated");
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, "updated");
}

/**
* @tc.name PreferencesAdvancedTest_016
* @tc.desc test put empty string
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_016, TestSize.Level0)
{
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "default");
    EXPECT_EQ(retrievedValue, "");
}

/**
* @tc.name PreferencesAdvancedTest_017
* @tc.desc test put zero integer
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_017, TestSize.Level0)
{
    int ret = pref->PutInt(KEY_TEST_INT_ELEMENT, 0);
    EXPECT_EQ(ret, E_OK);
    
    int retrievedValue = pref->GetInt(KEY_TEST_INT_ELEMENT, -1);
    EXPECT_EQ(retrievedValue, 0);
}

/**
* @tc.name PreferencesAdvancedTest_018
* @tc.desc test put negative integer
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_018, TestSize.Level0)
{
    int testValue = -98765;
    int ret = pref->PutInt(KEY_TEST_INT_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    int retrievedValue = pref->GetInt(KEY_TEST_INT_ELEMENT, 0);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_019
* @tc.desc test put negative float
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_019, TestSize.Level0)
{
    float testValue = -123.456f;
    int ret = pref->PutFloat(KEY_TEST_FLOAT_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    float retrievedValue = pref->GetFloat(KEY_TEST_FLOAT_ELEMENT, 0.0f);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_020
* @tc.desc test put zero float
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_020, TestSize.Level0)
{
    float testValue = 0.0f;
    int ret = pref->PutFloat(KEY_TEST_FLOAT_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    float retrievedValue = pref->GetFloat(KEY_TEST_FLOAT_ELEMENT, 1.0f);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_021
* @tc.desc test put max integer
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_021, TestSize.Level0)
{
    int testValue = 2147483647;
    int ret = pref->PutInt(KEY_TEST_INT_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    int retrievedValue = pref->GetInt(KEY_TEST_INT_ELEMENT, 0);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_022
* @tc.desc test put min integer
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_022, TestSize.Level0)
{
    int testValue = -2147483648;
    int ret = pref->PutInt(KEY_TEST_INT_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    int retrievedValue = pref->GetInt(KEY_TEST_INT_ELEMENT, 0);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_023
* @tc.desc test put long string
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_023, TestSize.Level0)
{
    std::string longString(500, 'a');
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, longString);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue.length(), longString.length());
}

/**
* @tc.name PreferencesAdvancedTest_024
* @tc.desc test put special chars
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_024, TestSize.Level0)
{
    std::string testValue = "!@#$%^&*()_+-={}[]|\\:;\"'<>?,./~`";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_025
* @tc.desc test put unicode string
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_025, TestSize.Level0)
{
    std::string testValue = "测试中文αβγδ日本語";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_030
* @tc.desc test get all
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_030, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING_ELEMENT, "string");
    pref->PutInt(KEY_TEST_INT_ELEMENT, 123);
    pref->PutFloat(KEY_TEST_FLOAT_ELEMENT, 1.23f);
    
    std::map<std::string, OHOS::NativePreferences::PreferencesValue> allData;
    allData = pref->GetAll();
    EXPECT_EQ(allData.size(), 3);
}

/**
* @tc.name PreferencesAdvancedTest_032
* @tc.desc test multiple put same key
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_032, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT_ELEMENT, 10);
    pref->PutInt(KEY_TEST_INT_ELEMENT, 20);
    pref->PutInt(KEY_TEST_INT_ELEMENT, 30);
    
    int retrievedValue = pref->GetInt(KEY_TEST_INT_ELEMENT, 0);
    EXPECT_EQ(retrievedValue, 30);
}

/**
* @tc.name PreferencesAdvancedTest_033
* @tc.desc test alternating put get
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_033, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT_ELEMENT, 1);
    int value1 = pref->GetInt(KEY_TEST_INT_ELEMENT, 0);
    EXPECT_EQ(value1, 1);
    
    pref->PutInt(KEY_TEST_INT_ELEMENT, 2);
    int value2 = pref->GetInt(KEY_TEST_INT_ELEMENT, 0);
    EXPECT_EQ(value2, 2);
}

/**
* @tc.name PreferencesAdvancedTest_034
* @tc.desc test different types same key
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_034, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING_ELEMENT, "string");
    pref->PutInt(KEY_TEST_STRING_ELEMENT, 123);
    
    int retrievedValue = pref->GetInt(KEY_TEST_STRING_ELEMENT, 0);
    EXPECT_EQ(retrievedValue, 123);
}

/**
* @tc.name PreferencesAdvancedTest_035
* @tc.desc test persistence after flush
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_035, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING_ELEMENT, "persist");
    pref->FlushSync();
    
    pref = nullptr;
    int errCode = E_OK;
    pref = PreferencesHelper::GetPreferences("/data/test/advanced", errCode);
    std::string value = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(value, "persist");
}

/**
* @tc.name PreferencesAdvancedTest_036
* @tc.desc test multiple flush
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_036, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING_ELEMENT, "test1");
    pref->FlushSync();
    
    pref->PutInt(KEY_TEST_INT_ELEMENT, 123);
    pref->FlushSync();
    
    pref = nullptr;
    int errCode = E_OK;
    pref = PreferencesHelper::GetPreferences("/data/test/advanced", errCode);
    
    std::string stringValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    int intValue = pref->GetInt(KEY_TEST_INT_ELEMENT, 0);
    EXPECT_EQ(stringValue, "test1");
    EXPECT_EQ(intValue, 123);
}

/**
* @tc.name PreferencesAdvancedTest_037
* @tc.desc test many keys
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_037, TestSize.Level0)
{
    int keyCount = 30;
    for (int i = 0; i < keyCount; i++) {
        std::string key = "key_" + std::to_string(i);
        std::string value = "value_" + std::to_string(i);
        pref->PutString(key, value);
    }
    
    std::map<std::string, OHOS::NativePreferences::PreferencesValue> allData;
    allData = pref->GetAll();
    EXPECT_EQ(allData.size(), keyCount);
}

/**
* @tc.name PreferencesAdvancedTest_038
* @tc.desc test clear and verify
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_038, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING_ELEMENT, "test");
    pref->PutInt(KEY_TEST_INT_ELEMENT, 123);
    pref->Clear();
    
    bool hasString = pref->HasKey(KEY_TEST_STRING_ELEMENT);
    bool hasInt = pref->HasKey(KEY_TEST_INT_ELEMENT);
    EXPECT_EQ(hasString, false);
    EXPECT_EQ(hasInt, false);
}

/**
* @tc.name PreferencesAdvancedTest_045
* @tc.desc test float decimal precision
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_045, TestSize.Level0)
{
    float testValue = 0.123456789f;
    int ret = pref->PutFloat(KEY_TEST_FLOAT_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    float retrievedValue = pref->GetFloat(KEY_TEST_FLOAT_ELEMENT, 0.0f);
    EXPECT_FLOAT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_046
* @tc.desc test float very small
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_046, TestSize.Level0)
{
    float testValue = 1.23e-10f;
    int ret = pref->PutFloat(KEY_TEST_FLOAT_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    float retrievedValue = pref->GetFloat(KEY_TEST_FLOAT_ELEMENT, 0.0f);
    EXPECT_FLOAT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_047
* @tc.desc test long max value
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_047, TestSize.Level0)
{
    int64_t testValue = 9223372036854775807LL;
    int ret = pref->PutLong(KEY_TEST_LONG_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    int64_t retrievedValue = pref->GetLong(KEY_TEST_LONG_ELEMENT, 0LL);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_048
* @tc.desc test long min value
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_048, TestSize.Level0)
{
    int64_t testValue = -9223372036854775LL;
    int ret = pref->PutLong(KEY_TEST_LONG_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    int64_t retrievedValue = pref->GetLong(KEY_TEST_LONG_ELEMENT, 0LL);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_049
* @tc.desc test repeated operations
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_049, TestSize.Level0)
{
    for (int i = 0; i < 5; i++) {
        pref->PutInt(KEY_TEST_INT_ELEMENT, i);
        int value = pref->GetInt(KEY_TEST_INT_ELEMENT, 0);
        EXPECT_EQ(value, i);
    }
}

/**
* @tc.name PreferencesAdvancedTest_051
* @tc.desc test delete then get default
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_051, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING_ELEMENT, "to_be_deleted");
    pref->FlushSync();
    
    pref->Delete(KEY_TEST_STRING_ELEMENT);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "default");
    EXPECT_EQ(retrievedValue, "default");
}

/**
* @tc.name PreferencesAdvancedTest_052
* @tc.desc test has after delete
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_052, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING_ELEMENT, "test");
    pref->PutInt(KEY_TEST_INT_ELEMENT, 123);
    pref->Clear();
    
    bool hasString = pref->HasKey(KEY_TEST_STRING_ELEMENT);
    bool hasInt = pref->HasKey(KEY_TEST_INT_ELEMENT);
    EXPECT_EQ(hasString, false);
    EXPECT_EQ(hasInt, false);
}

/**
* @tc.name PreferencesAdvancedTest_053
* @tc.desc test flush after multiple puts
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_053, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING_ELEMENT, "value1");
    pref->PutInt(KEY_TEST_INT_ELEMENT, 100);
    pref->PutFloat(KEY_TEST_FLOAT_ELEMENT, 1.5f);
    pref->FlushSync();
    
    std::string stringValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    int intValue = pref->GetInt(KEY_TEST_INT_ELEMENT, 0);
    float floatValue = pref->GetFloat(KEY_TEST_FLOAT_ELEMENT, 0.0f);
    
    EXPECT_EQ(stringValue, "value1");
    EXPECT_EQ(intValue, 100);
    EXPECT_FLOAT_EQ(floatValue, 1.5f);
}

/**
* @tc.name PreferencesAdvancedTest_057
* @tc.desc test long overflow
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_057, TestSize.Level0)
{
    int64_t testValue = 9223372036854775807LL;
    int ret = pref->PutLong(KEY_TEST_LONG_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    int64_t retrievedValue = pref->GetLong(KEY_TEST_LONG_ELEMENT, 0LL);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_058
* @tc.desc test long underflow
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_058, TestSize.Level0)
{
    int64_t testValue = -9223372036854775LL;
    int ret = pref->PutLong(KEY_TEST_LONG_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    int64_t retrievedValue = pref->GetLong(KEY_TEST_LONG_ELEMENT, 0LL);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_059
* @tc.desc test int max boundary
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_059, TestSize.Level0)
{
    int testValue = 2147483647;
    int ret = pref->PutInt(KEY_TEST_INT_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    int retrievedValue = pref->GetInt(KEY_TEST_INT_ELEMENT, 0);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_060
* @tc.desc test int min boundary
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_060, TestSize.Level0)
{
    int testValue = -2147483648;
    int ret = pref->PutInt(KEY_TEST_INT_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    int retrievedValue = pref->GetInt(KEY_TEST_INT_ELEMENT, 0);
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_061
* @tc.desc test float max boundary
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_061, TestSize.Level0)
{
    float testValue = std::numeric_limits<float>::max();
    int ret = pref->PutFloat(KEY_TEST_FLOAT_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    float retrievedValue = pref->GetFloat(KEY_TEST_FLOAT_ELEMENT, 0.0f);
    EXPECT_FLOAT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_062
* @tc.desc test float min boundary
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_062, TestSize.Level0)
{
    float testValue = std::numeric_limits<float>::lowest();
    int ret = pref->PutFloat(KEY_TEST_FLOAT_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    float retrievedValue = pref->GetFloat(KEY_TEST_FLOAT_ELEMENT, 0.0f);
    EXPECT_FLOAT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_063
* @tc.desc test string special characters
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_063, TestSize.Level0)
{
    std::string testValue = "\n\t\r\0";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_064
* @tc.desc test string emoji
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_064, TestSize.Level0)
{
    std::string testValue = "😀😁😂🤣😃😄😅😆😉😊😋😌";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_065
* @tc.desc test string mixed case
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_065, TestSize.Level0)
{
    std::string testValue = "HelloWorldMixedCaseTest";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_066
* @tc.desc test string numbers
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_066, TestSize.Level0)
{
    std::string testValue = "9876543210";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_067
* @tc.desc test string html tags
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_067, TestSize.Level0)
{
    std::string testValue = "<div><p>test</p></div>";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_068
* @tc.desc test string url
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_068, TestSize.Level0)
{
    std::string testValue = "https://example.com/path?query=value";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_069
* @tc.desc test string json
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_069, TestSize.Level0)
{
    std::string testValue = "{\"key\":\"value\",\"number\":123}";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_070
* @tc.desc test string xml
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_070, TestSize.Level0)
{
    std::string testValue = "<root><item>test</item></root>";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_071
* @tc.desc test string base64
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_071, TestSize.Level0)
{
    std::string testValue = "SGVsbG8gV29ybGQ=";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_072
* @tc.desc test string hex
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_072, TestSize.Level0)
{
    std::string testValue = "48656C6C6F20576F726C64";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_073
* @tc.desc test string email
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_073, TestSize.Level0)
{
    std::string testValue = "user@example.com";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_074
* @tc.desc test string phone
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_074, TestSize.Level0)
{
    std::string testValue = "+1234567890";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_075
* @tc.desc test string date
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_075, TestSize.Level0)
{
    std::string testValue = "2024-01-01T00:00:00.000Z";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_076
* @tc.desc test string uuid
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_076, TestSize.Level0)
{
    std::string testValue = "123e4567-e89b-12d3-a456-426614174000";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_077
* @tc.desc test string mac
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_077, TestSize.Level0)
{
    std::string testValue = "00:1A:2B:3C:4D:5E";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_078
* @tc.desc test string ip
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_078, TestSize.Level0)
{
    std::string testValue = "192.168.1.100";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_079
* @tc.desc test string ipv6
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_079, TestSize.Level0)
{
    std::string testValue = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_080
* @tc.desc test string color
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_080, TestSize.Level0)
{
    std::string testValue = "#FF5733";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_081
* @tc.desc test string css
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_081, TestSize.Level0)
{
    std::string testValue = ".test { color: red; }";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_082
* @tc.desc test string sql
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_082, TestSize.Level0)
{
    std::string testValue = "SELECT * FROM table WHERE id = 1";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_083
* @tc.desc test string regex
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_083, TestSize.Level0)
{
    std::string testValue = "^[a-zA-Z0-9]+$";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_084
* @tc.desc test string markdown
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_084, TestSize.Level0)
{
    std::string testValue = "# Heading\n\n**bold** text";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_085
* @tc.desc test string yaml
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_085, TestSize.Level0)
{
    std::string testValue = "key: value\nnumber: 123";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_086
* @tc.desc test string csv
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_086, TestSize.Level0)
{
    std::string testValue = "name,age,city\nJohn,30,NYC";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_087
* @tc.desc test string tsv
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_087, TestSize.Level0)
{
    std::string testValue = "name\tage\tcity\nJohn\t30\tNYC";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_088
* @tc.desc test string ini
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_088, TestSize.Level0)
{
    std::string testValue = "[section]\nkey=value";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_089
* @tc.desc test string properties
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_089, TestSize.Level0)
{
    std::string testValue = "key1=value1\nkey2=value2";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_090
* @tc.desc test string command
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_090, TestSize.Level0)
{
    std::string testValue = "command --arg1 value1 --arg2 value2";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_091
* @tc.desc test string user agent
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_091, TestSize.Level0)
{
    std::string testValue = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_092
* @tc.desc test string cookie
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_092, TestSize.Level0)
{
    std::string testValue = "session=abc123; user=john";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_093
* @tc.desc test string header
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_093, TestSize.Level0)
{
    std::string testValue = "Content-Type: application/json";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_094
* @tc.desc test string mime
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_094, TestSize.Level0)
{
    std::string testValue = "multipart/form-data";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_095
* @tc.desc test string encoding
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_095, TestSize.Level0)
{
    std::string testValue = "UTF-8, UTF-16, ASCII";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_096
* @tc.desc test string locale
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_096, TestSize.Level0)
{
    std::string testValue = "en-US, zh-CN, ja-JP";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_097
* @tc.desc test string timezone
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_097, TestSize.Level0)
{
    std::string testValue = "America/New_York";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_098
* @tc.desc test string currency
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_098, TestSize.Level0)
{
    std::string testValue = "USD, EUR, CNY, JPY";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_099
* @tc.desc test string version
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_099, TestSize.Level0)
{
    std::string testValue = "1.0.0.0";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_100
* @tc.desc test string build
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_100, TestSize.Level0)
{
    std::string testValue = "2024.01.01.001";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_101
* @tc.desc test string environment
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_101, TestSize.Level0)
{
    std::string testValue = "PATH=/usr/bin:/usr/local/bin";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_102
* @tc.desc test string config
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_102, TestSize.Level0)
{
    std::string testValue = "{\"debug\":true,\"port\":8080}";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_103
* @tc.desc test string log
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_103, TestSize.Level0)
{
    std::string testValue = "2024-01-01 12:00:00 INFO Test";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_104
* @tc.desc test string error
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_104, TestSize.Level0)
{
    std::string testValue = "Error: Something went wrong";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_105
* @tc.desc test string warning
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_105, TestSize.Level0)
{
    std::string testValue = "Warning: Low disk space";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_106
* @tc.desc test string info
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_106, TestSize.Level0)
{
    std::string testValue = "Info: Operation completed";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_107
* @tc.desc test string debug
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_107, TestSize.Level0)
{
    std::string testValue = "Debug: Variable value is 123";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_108
* @tc.desc test string trace
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_108, TestSize.Level0)
{
    std::string testValue = "Trace: Entering function";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_109
* @tc.desc test string success
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_109, TestSize.Level0)
{
    std::string testValue = "Success: Operation completed";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_110
* @tc.desc test string failure
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_110, TestSize.Level0)
{
    std::string testValue = "Failure: Operation failed";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_111
* @tc.desc test string pending
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_111, TestSize.Level0)
{
    std::string testValue = "Pending: Awaiting response";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_112
* @tc.desc test string complete
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_112, TestSize.Level0)
{
    std::string testValue = "Complete: All tasks done";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_113
* @tc.desc test string running
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_113, TestSize.Level0)
{
    std::string testValue = "Running: Process active";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}

/**
* @tc.name PreferencesAdvancedTest_114
* @tc.desc test string stopped
* @tc.type: FUNC
* @tc.author: advanced_test
*/
HWTEST_F(PreferencesAdvancedTest, PreferencesAdvancedTest_114, TestSize.Level0)
{
    std::string testValue = "Stopped: Process halted";
    int ret = pref->PutString(KEY_TEST_STRING_ELEMENT, testValue);
    EXPECT_EQ(ret, E_OK);
    
    std::string retrievedValue = pref->GetString(KEY_TEST_STRING_ELEMENT, "");
    EXPECT_EQ(retrievedValue, testValue);
}
}