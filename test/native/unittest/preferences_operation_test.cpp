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

#include <cctype>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>

#include "log_print.h"
#include "preferences_errno.h"
#include "preferences_file_operation.h"
#include "preferences_helper.h"
#include "preferences_observer.h"
#include "preferences_value.h"

using namespace testing::ext;
using namespace OHOS::NativePreferences;

namespace {
const std::string TEST_LONG_KEY = std::string(Preferences::MAX_KEY_LENGTH, std::toupper('b'));
const std::string TEST_INT_KEY = "test_int_key_new";
const std::string TEST_LONG_KEY_NAME = "test_long_key_new";
const std::string TEST_FLOAT_KEY = "test_float_key_new";
const std::string TEST_DOUBLE_KEY = "test_double_key_new";
const std::string TEST_BOOL_KEY = "test_bool_key_new";
const std::string TEST_STRING_KEY = "test_string_key_new";
const std::string TEST_STRING_ARRAY_KEY = "test_string_array_key_new";
const std::string TEST_BOOL_ARRAY_KEY = "test_bool_array_key_new";
const std::string TEST_DOUBLE_ARRAY_KEY = "test_double_array_key_new";
const std::string TEST_UINT8_ARRAY_KEY = "test_uint8_array_key_new";

class PreferencesOperationTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static std::shared_ptr<Preferences> prefInstance;
};

std::shared_ptr<Preferences> PreferencesOperationTest::prefInstance = nullptr;

void PreferencesOperationTest::SetUpTestCase(void)
{
}

void PreferencesOperationTest::TearDownTestCase(void)
{
}

void PreferencesOperationTest::SetUp(void)
{
    int errCode = E_OK;
    prefInstance = PreferencesHelper::GetPreferences("/data/test/pref_op_test", errCode);
    EXPECT_EQ(errCode, E_OK);
}

void PreferencesOperationTest::TearDown(void)
{
    prefInstance = nullptr;
    int ret = PreferencesHelper::DeletePreferences("/data/test/pref_op_test");
    EXPECT_EQ(ret, E_OK);
}

class TestObserverCounter : public PreferencesObserver {
public:
    virtual ~TestObserverCounter();
    void OnChange(const std::string &key) override;
    void OnChange(const std::map<std::string, OHOS::NativePreferences::PreferencesValue> &records) override;

    std::atomic_int changeCount;
    static const std::vector<std::string> OBSERVE_KEYS_LIST;
};

TestObserverCounter::~TestObserverCounter()
{
}

void TestObserverCounter::OnChange(const std::string &key)
{
    for (auto it = OBSERVE_KEYS_LIST.cbegin(); it != OBSERVE_KEYS_LIST.cend(); it++) {
        if (key.compare(*it)) {
            changeCount++;
            break;
        }
    }
}

void TestObserverCounter::OnChange(
    const std::map<std::string, OHOS::NativePreferences::PreferencesValue> &records)
{
    for (auto it = OBSERVE_KEYS_LIST.cbegin(); it != OBSERVE_KEYS_LIST.cend(); it++) {
        for (auto iter = records.begin(); iter != records.end(); iter++) {
            std::string key = iter->first;
            if (key.compare(*it)) {
                changeCount++;
                return;
            }
        }
    }
}

const std::vector<std::string> TestObserverCounter::OBSERVE_KEYS_LIST = { TEST_INT_KEY,
    TEST_LONG_KEY_NAME, TEST_FLOAT_KEY, TEST_BOOL_KEY, TEST_STRING_KEY };

/**
 * @tc.name: PreferencesOperationTest_001
 * @tc.desc: normal testcase for PutInt and GetInt operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_001, TestSize.Level0)
{
    prefInstance->PutInt(TEST_INT_KEY, 100);
    prefInstance->FlushSync();
    int ret = prefInstance->GetInt(TEST_INT_KEY, 0);
    EXPECT_EQ(ret, 100);

    prefInstance->PutInt(TEST_INT_KEY, 200);
    prefInstance->FlushSync();
    ret = prefInstance->GetInt(TEST_INT_KEY, 0);
    EXPECT_EQ(ret, 200);

    ret = prefInstance->GetInt("non_exist_key", 999);
    EXPECT_EQ(ret, 999);
}

/**
 * @tc.name: PreferencesOperationTest_002
 * @tc.desc: normal testcase for PutString and GetString operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_002, TestSize.Level0)
{
    std::string testValue = "hello_world_test";
    prefInstance->PutString(TEST_STRING_KEY, testValue);
    prefInstance->FlushSync();
    std::string ret = prefInstance->GetString(TEST_STRING_KEY, "");
    EXPECT_EQ(ret, testValue);

    std::string newValue = "new_value_test";
    prefInstance->PutString(TEST_STRING_KEY, newValue);
    prefInstance->FlushSync();
    ret = prefInstance->GetString(TEST_STRING_KEY, "");
    EXPECT_EQ(ret, newValue);

    ret = prefInstance->GetString("non_exist_key", "default_val");
    EXPECT_EQ(ret, "default_val");
}

/**
 * @tc.name: PreferencesOperationTest_003
 * @tc.desc: normal testcase for PutBool and GetBool operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_003, TestSize.Level0)
{
    prefInstance->PutBool(TEST_BOOL_KEY, true);
    prefInstance->FlushSync();
    bool ret = prefInstance->GetBool(TEST_BOOL_KEY, false);
    EXPECT_EQ(ret, true);

    prefInstance->PutBool(TEST_BOOL_KEY, false);
    prefInstance->FlushSync();
    ret = prefInstance->GetBool(TEST_BOOL_KEY, true);
    EXPECT_EQ(ret, false);

    ret = prefInstance->GetBool("non_exist_key", true);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: PreferencesOperationTest_004
 * @tc.desc: normal testcase for PutFloat and GetFloat operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_004, TestSize.Level0)
{
    float testValue = 3.14159f;
    prefInstance->PutFloat(TEST_FLOAT_KEY, testValue);
    prefInstance->FlushSync();
    float ret = prefInstance->GetFloat(TEST_FLOAT_KEY, 0.0f);
    EXPECT_FLOAT_EQ(ret, testValue);

    float newValue = 2.71828f;
    prefInstance->PutFloat(TEST_FLOAT_KEY, newValue);
    prefInstance->FlushSync();
    ret = prefInstance->GetFloat(TEST_FLOAT_KEY, 0.0f);
    EXPECT_FLOAT_EQ(ret, newValue);

    ret = prefInstance->GetFloat("non_exist_key", 1.0f);
    EXPECT_FLOAT_EQ(ret, 1.0f);
}

/**
 * @tc.name: PreferencesOperationTest_005
 * @tc.desc: normal testcase for PutDouble and GetDouble operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_005, TestSize.Level0)
{
    double testValue = 3.141592653589793;
    prefInstance->PutDouble(TEST_DOUBLE_KEY, testValue);
    prefInstance->FlushSync();
    double ret = prefInstance->GetDouble(TEST_DOUBLE_KEY, 0.0);
    EXPECT_DOUBLE_EQ(ret, testValue);

    double newValue = 2.718281828459045;
    prefInstance->PutDouble(TEST_DOUBLE_KEY, newValue);
    prefInstance->FlushSync();
    ret = prefInstance->GetDouble(TEST_DOUBLE_KEY, 0.0);
    EXPECT_DOUBLE_EQ(ret, newValue);

    ret = prefInstance->GetDouble("non_exist_key", 1.0);
    EXPECT_DOUBLE_EQ(ret, 1.0);
}

/**
 * @tc.name: PreferencesOperationTest_006
 * @tc.desc: normal testcase for PutLong and GetLong operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_006, TestSize.Level0)
{
    int64_t testValue = 9876543210LL;
    prefInstance->PutLong(TEST_LONG_KEY_NAME, testValue);
    prefInstance->FlushSync();
    int64_t ret = prefInstance->GetLong(TEST_LONG_KEY_NAME, 0LL);
    EXPECT_EQ(ret, testValue);

    int64_t newValue = 1234567890123LL;
    prefInstance->PutLong(TEST_LONG_KEY_NAME, newValue);
    prefInstance->FlushSync();
    ret = prefInstance->GetLong(TEST_LONG_KEY_NAME, 0LL);
    EXPECT_EQ(ret, newValue);

    ret = prefInstance->GetLong("non_exist_key", 100LL);
    EXPECT_EQ(ret, 100LL);
}

/**
 * @tc.name: PreferencesOperationTest_007
 * @tc.desc: normal testcase for HasKey operation
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_007, TestSize.Level0)
{
    bool ret = prefInstance->HasKey(TEST_INT_KEY);
    EXPECT_EQ(ret, false);

    prefInstance->PutInt(TEST_INT_KEY, 42);
    ret = prefInstance->HasKey(TEST_INT_KEY);
    EXPECT_EQ(ret, true);

    prefInstance->FlushSync();
    ret = prefInstance->HasKey(TEST_INT_KEY);
    EXPECT_EQ(ret, true);

    ret = prefInstance->HasKey("non_exist_key");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: PreferencesOperationTest_008
 * @tc.desc: normal testcase for Delete operation
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_008, TestSize.Level0)
{
    prefInstance->PutString(TEST_STRING_KEY, "test_delete");
    prefInstance->FlushSync();
    bool ret = prefInstance->HasKey(TEST_STRING_KEY);
    EXPECT_EQ(ret, true);

    int result = prefInstance->Delete(TEST_STRING_KEY);
    EXPECT_EQ(result, E_OK);
    ret = prefInstance->HasKey(TEST_STRING_KEY);
    EXPECT_EQ(ret, false);

    prefInstance->FlushSync();
    ret = prefInstance->HasKey(TEST_STRING_KEY);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: PreferencesOperationTest_009
 * @tc.desc: normal testcase for Clear operation
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_009, TestSize.Level0)
{
    prefInstance->PutInt(TEST_INT_KEY, 100);
    prefInstance->PutString(TEST_STRING_KEY, "test_clear");
    prefInstance->PutBool(TEST_BOOL_KEY, true);
    prefInstance->FlushSync();

    int result = prefInstance->Clear();
    EXPECT_EQ(result, E_OK);

    bool ret = prefInstance->HasKey(TEST_INT_KEY);
    EXPECT_EQ(ret, false);
    ret = prefInstance->HasKey(TEST_STRING_KEY);
    EXPECT_EQ(ret, false);
    ret = prefInstance->HasKey(TEST_BOOL_KEY);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: PreferencesOperationTest_010
 * @tc.desc: normal testcase for GetAll operation
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_010, TestSize.Level0)
{
    prefInstance->PutInt(TEST_INT_KEY, 100);
    prefInstance->PutString(TEST_STRING_KEY, "test_get_all");
    prefInstance->PutBool(TEST_BOOL_KEY, true);
    prefInstance->FlushSync();

    auto allData = prefInstance->GetAll();
    EXPECT_GE(allData.size(), 3);

    auto it = allData.find(TEST_INT_KEY);
    EXPECT_NE(it, allData.end());
    EXPECT_EQ(static_cast<int>(it->second), 100);

    it = allData.find(TEST_STRING_KEY);
    EXPECT_NE(it, allData.end());
    EXPECT_EQ(static_cast<std::string>(it->second), "test_get_all");
}

/**
 * @tc.name: PreferencesOperationTest_011
 * @tc.desc: normal testcase for string array operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_011, TestSize.Level0)
{
    std::vector<std::string> stringArray = { "item1", "item2", "item3" };
    prefInstance->Put(TEST_STRING_ARRAY_KEY, stringArray);
    prefInstance->FlushSync();

    PreferencesValue defValue(static_cast<int64_t>(0));
    PreferencesValue result = prefInstance->Get(TEST_STRING_ARRAY_KEY, defValue);
    EXPECT_EQ(result.IsStringArray(), true);

    auto retrievedArray = static_cast<std::vector<std::string>>(result);
    EXPECT_EQ(retrievedArray.size(), stringArray.size());
    for (size_t i = 0; i < stringArray.size(); i++) {
        EXPECT_EQ(retrievedArray[i], stringArray[i]);
    }
}

/**
 * @tc.name: PreferencesOperationTest_012
 * @tc.desc: normal testcase for bool array operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_012, TestSize.Level0)
{
    std::vector<bool> boolArray = { true, false, true, false, true };
    prefInstance->Put(TEST_BOOL_ARRAY_KEY, boolArray);
    prefInstance->FlushSync();

    PreferencesValue defValue(static_cast<int64_t>(0));
    PreferencesValue result = prefInstance->Get(TEST_BOOL_ARRAY_KEY, defValue);
    EXPECT_EQ(result.IsBoolArray(), true);

    auto retrievedArray = static_cast<std::vector<bool>>(result);
    EXPECT_EQ(retrievedArray.size(), boolArray.size());
    for (size_t i = 0; i < boolArray.size(); i++) {
        EXPECT_EQ(retrievedArray[i], boolArray[i]);
    }
}

/**
 * @tc.name: PreferencesOperationTest_013
 * @tc.desc: normal testcase for double array operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_013, TestSize.Level0)
{
    std::vector<double> doubleArray = { 1.1, 2.2, 3.3, 4.4, 5.5 };
    prefInstance->Put(TEST_DOUBLE_ARRAY_KEY, doubleArray);
    prefInstance->FlushSync();

    PreferencesValue defValue(static_cast<int64_t>(0));
    PreferencesValue result = prefInstance->Get(TEST_DOUBLE_ARRAY_KEY, defValue);
    EXPECT_EQ(result.IsDoubleArray(), true);

    auto retrievedArray = static_cast<std::vector<double>>(result);
    EXPECT_EQ(retrievedArray.size(), doubleArray.size());
    for (size_t i = 0; i < doubleArray.size(); i++) {
        EXPECT_DOUBLE_EQ(retrievedArray[i], doubleArray[i]);
    }
}

/**
 * @tc.name: PreferencesOperationTest_014
 * @tc.desc: normal testcase for uint8 array operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_014, TestSize.Level0)
{
    std::vector<uint8_t> uint8Array = { 10, 20, 30, 40, 50 };
    prefInstance->Put(TEST_UINT8_ARRAY_KEY, uint8Array);
    prefInstance->FlushSync();

    PreferencesValue defValue(static_cast<int64_t>(0));
    PreferencesValue result = prefInstance->Get(TEST_UINT8_ARRAY_KEY, defValue);
    EXPECT_EQ(result.IsUint8Array(), true);

    auto retrievedArray = static_cast<std::vector<uint8_t>>(result);
    EXPECT_EQ(retrievedArray.size(), uint8Array.size());
    for (size_t i = 0; i < uint8Array.size(); i++) {
        EXPECT_EQ(retrievedArray[i], uint8Array[i]);
    }
}

/**
 * @tc.name: PreferencesOperationTest_015
 * @tc.desc: normal testcase for observer registration
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_015, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<TestObserverCounter>();
    prefInstance->RegisterObserver(observer);

    prefInstance->PutInt(TEST_INT_KEY, 100);
    prefInstance->FlushSync();
    EXPECT_EQ(static_cast<TestObserverCounter *>(observer.get())->changeCount, 1);

    prefInstance->PutString(TEST_STRING_KEY, "observer_test");
    prefInstance->FlushSync();
    EXPECT_EQ(static_cast<TestObserverCounter *>(observer.get())->changeCount, 2);

    prefInstance->UnRegisterObserver(observer);
}

/**
 * @tc.name: PreferencesOperationTest_017
 * @tc.desc: normal testcase for multiple put operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_017, TestSize.Level0)
{
    for (int i = 0; i < 10; i++) {
        std::string key = "multi_key_" + std::to_string(i);
        prefInstance->PutInt(key, i * 10);
    }
    prefInstance->FlushSync();

    for (int i = 0; i < 10; i++) {
        std::string key = "multi_key_" + std::to_string(i);
        int value = prefInstance->GetInt(key, -1);
        EXPECT_EQ(value, i * 10);
    }
}

/**
 * @tc.name: PreferencesOperationTest_018
 * @tc.desc: normal testcase for update existing key
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_018, TestSize.Level0)
{
    prefInstance->PutInt(TEST_INT_KEY, 100);
    prefInstance->FlushSync();
    int value = prefInstance->GetInt(TEST_INT_KEY, 0);
    EXPECT_EQ(value, 100);

    prefInstance->PutInt(TEST_INT_KEY, 200);
    prefInstance->FlushSync();
    value = prefInstance->GetInt(TEST_INT_KEY, 0);
    EXPECT_EQ(value, 200);

    prefInstance->PutInt(TEST_INT_KEY, 300);
    prefInstance->FlushSync();
    value = prefInstance->GetInt(TEST_INT_KEY, 0);
    EXPECT_EQ(value, 300);
}

/**
 * @tc.name: PreferencesOperationTest_019
 * @tc.desc: normal testcase for empty string value
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_019, TestSize.Level0)
{
    prefInstance->PutString(TEST_STRING_KEY, "");
    prefInstance->FlushSync();
    std::string value = prefInstance->GetString(TEST_STRING_KEY, "default");
    EXPECT_EQ(value, "");

    prefInstance->PutString(TEST_STRING_KEY, "non_empty");
    prefInstance->FlushSync();
    value = prefInstance->GetString(TEST_STRING_KEY, "");
    EXPECT_EQ(value, "non_empty");
}

/**
 * @tc.name: PreferencesOperationTest_020
 * @tc.desc: normal testcase for special characters in string
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_020, TestSize.Level0)
{
    std::string specialChars = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
    prefInstance->PutString(TEST_STRING_KEY, specialChars);
    prefInstance->FlushSync();
    std::string value = prefInstance->GetString(TEST_STRING_KEY, "");
    EXPECT_EQ(value, specialChars);

    std::string unicodeStr = "Hello World! \u4e2d\u6587";
    prefInstance->PutString(TEST_STRING_KEY, unicodeStr);
    prefInstance->FlushSync();
    value = prefInstance->GetString(TEST_STRING_KEY, "");
    EXPECT_EQ(value, unicodeStr);
}

/**
 * @tc.name: PreferencesOperationTest_021
 * @tc.desc: normal testcase for max key length
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_021, TestSize.Level0)
{
    prefInstance->PutInt(TEST_LONG_KEY, 12345);
    prefInstance->FlushSync();
    int value = prefInstance->GetInt(TEST_LONG_KEY, 0);
    EXPECT_EQ(value, 12345);

    bool hasKey = prefInstance->HasKey(TEST_LONG_KEY);
    EXPECT_EQ(hasKey, true);
}

/**
 * @tc.name: PreferencesOperationTest_022
 * @tc.desc: normal testcase for invalid key
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_022, TestSize.Level0)
{
    int value = prefInstance->GetInt("", 999);
    EXPECT_EQ(value, 999);

    std::string strValue = prefInstance->GetString("", "default");
    EXPECT_EQ(strValue, "default");

    bool hasKey = prefInstance->HasKey("");
    EXPECT_EQ(hasKey, false);
}

/**
 * @tc.name: PreferencesOperationTest_023
 * @tc.desc: normal testcase for PreferencesValue operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_023, TestSize.Level0)
{
    PreferencesValue intValue(100);
    EXPECT_EQ(static_cast<int>(intValue), 100);

    PreferencesValue strValue("test_string");
    EXPECT_EQ(static_cast<std::string>(strValue), "test_string");

    PreferencesValue boolValue(true);
    EXPECT_EQ(static_cast<bool>(boolValue), true);

    PreferencesValue floatValue(3.14f);
    EXPECT_FLOAT_EQ(static_cast<float>(floatValue), 3.14f);

    PreferencesValue doubleValue(3.14159);
    EXPECT_DOUBLE_EQ(static_cast<double>(doubleValue), 3.14159);
}

/**
 * @tc.name: PreferencesOperationTest_024
 * @tc.desc: normal testcase for Get operation with default value
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_024, TestSize.Level0)
{
    PreferencesValue defValue(static_cast<int64_t>(999));
    PreferencesValue result = prefInstance->Get("non_exist_key", defValue);
    EXPECT_EQ(static_cast<int64_t>(result), 999);

    prefInstance->PutInt(TEST_INT_KEY, 100);
    PreferencesValue defValue2(static_cast<int64_t>(0));
    result = prefInstance->Get(TEST_INT_KEY, defValue2);
    EXPECT_EQ(static_cast<int>(result), 100);
}

/**
 * @tc.name: PreferencesOperationTest_025
 * @tc.desc: normal testcase for GetAllData operation
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_025, TestSize.Level0)
{
    int errCode;
    auto pref = PreferencesHelper::GetPreferences("/data/test/test_all_data", errCode);
    EXPECT_EQ(errCode, E_OK);

    pref->PutInt("key_a", 1);
    pref->PutString("key_b", "value_b");
    pref->PutBool("key_c", true);

    auto ret = pref->GetAllData();
    EXPECT_EQ(ret.first, E_OK);
    EXPECT_GE(ret.second.size(), 3);

    auto iter = ret.second.find("key_a");
    EXPECT_NE(iter, ret.second.end());
    EXPECT_EQ(static_cast<int>(iter->second), 1);

    PreferencesHelper::DeletePreferences("/data/test/test_all_data");
}

/**
 * @tc.name: PreferencesOperationTest_026
 * @tc.desc: normal testcase for GetAllDatas operation
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_026, TestSize.Level0)
{
    int errCode;
    auto pref = PreferencesHelper::GetPreferences("/data/test/test_all_datas", errCode);
    EXPECT_EQ(errCode, E_OK);

    pref->PutInt("key_x", 10);
    pref->PutString("key_y", "value_y");
    pref->PutBool("key_z", false);

    auto ret = pref->GetAllDatas();
    EXPECT_GE(ret.size(), 3);

    auto iter = ret.find("key_x");
    EXPECT_NE(iter, ret.end());
    EXPECT_EQ(static_cast<int>(iter->second), 10);

    PreferencesHelper::DeletePreferences("/data/test/test_all_datas");
}

/**
 * @tc.name: PreferencesOperationTest_027
 * @tc.desc: normal testcase for GetValue operation
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_027, TestSize.Level0)
{
    int errCode;
    auto pref = PreferencesHelper::GetPreferences("/data/test/test_get_value", errCode);
    EXPECT_EQ(errCode, E_OK);

    pref->PutInt("value_key", 42);
    PreferencesValue defValue(static_cast<int64_t>(0));
    auto res = pref->GetValue("value_key", defValue);
    EXPECT_EQ(res.first, E_OK);
    EXPECT_EQ(static_cast<int>(res.second), 42);

    res = pref->GetValue("non_exist_key", defValue);
    EXPECT_EQ(static_cast<int64_t>(res.second), 0);

    PreferencesHelper::DeletePreferences("/data/test/test_get_value");
}

/**
 * @tc.name: PreferencesOperationTest_028
 * @tc.desc: normal testcase for FlushSync with large data
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_028, TestSize.Level0)
{
    int errCode;
    auto pref = PreferencesHelper::GetPreferences("/data/test/test_large_data", errCode);
    EXPECT_EQ(errCode, E_OK);

    for (int i = 0; i < 100; i++) {
        pref->PutString("large_key_" + std::to_string(i), "large_value_" + std::to_string(i));
    }
    int ret = pref->FlushSync();
    EXPECT_EQ(ret, E_OK);

    for (int i = 0; i < 100; i++) {
        std::string value = pref->GetString("large_key_" + std::to_string(i), "");
        EXPECT_EQ(value, "large_value_" + std::to_string(i));
    }

    PreferencesHelper::DeletePreferences("/data/test/test_large_data");
}

/**
 * @tc.name: PreferencesOperationTest_029
 * @tc.desc: normal testcase for cache remove and reload
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_029, TestSize.Level0)
{
    int errCode;
    std::string path = "/data/test/test_cache_reload";
    auto pref = PreferencesHelper::GetPreferences(path, errCode);
    EXPECT_EQ(errCode, E_OK);

    pref->PutInt("cache_key", 555);
    pref->FlushSync();

    int ret = PreferencesHelper::RemovePreferencesFromCache(path);
    EXPECT_EQ(ret, E_OK);

    pref = PreferencesHelper::GetPreferences(path, errCode);
    EXPECT_EQ(errCode, E_OK);
    int value = pref->GetInt("cache_key", 0);
    EXPECT_EQ(value, 555);

    PreferencesHelper::DeletePreferences(path);
}

/**
 * @tc.name: PreferencesOperationTest_030
 * @tc.desc: normal testcase for multiple preferences instances
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_030, TestSize.Level0)
{
    int errCode1, errCode2;
    std::string path1 = "/data/test/test_multi_1";
    std::string path2 = "/data/test/test_multi_2";

    auto pref1 = PreferencesHelper::GetPreferences(path1, errCode1);
    auto pref2 = PreferencesHelper::GetPreferences(path2, errCode2);
    EXPECT_EQ(errCode1, E_OK);
    EXPECT_EQ(errCode2, E_OK);

    pref1->PutInt("multi_key", 111);
    pref2->PutInt("multi_key", 222);
    pref1->FlushSync();
    pref2->FlushSync();

    EXPECT_EQ(pref1->GetInt("multi_key", 0), 111);
    EXPECT_EQ(pref2->GetInt("multi_key", 0), 222);

    PreferencesHelper::DeletePreferences(path1);
    PreferencesHelper::DeletePreferences(path2);
}

/**
 * @tc.name: PreferencesOperationTest_031
 * @tc.desc: normal testcase for Options with bundle name
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_031, TestSize.Level0)
{
    int errCode;
    std::string path = "/data/test/test_options_bundle";
    Options option = Options(path, "com.test.bundle", "");
    auto pref = PreferencesHelper::GetPreferences(option, errCode);
    EXPECT_EQ(errCode, E_OK);

    pref->PutString("bundle_key", "bundle_value");
    pref->FlushSync();
    EXPECT_EQ(pref->GetString("bundle_key", ""), "bundle_value");

    PreferencesHelper::DeletePreferences(path);
}

/**
 * @tc.name: PreferencesOperationTest_032
 * @tc.desc: normal testcase for Options with data group id
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_032, TestSize.Level0)
{
    int errCode;
    std::string path = "/data/test/test_options_group";
    Options option = Options(path, "com.test.bundle", "1001001");
    auto pref = PreferencesHelper::GetPreferences(option, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(pref->GetGroupId(), "1001001");

    PreferencesHelper::DeletePreferences(path);
}

/**
 * @tc.name: PreferencesOperationTest_033
 * @tc.desc: normal testcase for negative int value
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_033, TestSize.Level0)
{
    prefInstance->PutInt(TEST_INT_KEY, -100);
    prefInstance->FlushSync();
    int value = prefInstance->GetInt(TEST_INT_KEY, 0);
    EXPECT_EQ(value, -100);

    prefInstance->PutInt(TEST_INT_KEY, -2147483648);
    prefInstance->FlushSync();
    value = prefInstance->GetInt(TEST_INT_KEY, 0);
    EXPECT_EQ(value, -2147483648);
}

/**
 * @tc.name: PreferencesOperationTest_034
 * @tc.desc: normal testcase for negative long value
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_034, TestSize.Level0)
{
    int64_t negValue = -9223372036854775807LL;
    prefInstance->PutLong(TEST_LONG_KEY_NAME, negValue);
    prefInstance->FlushSync();
    int64_t value = prefInstance->GetLong(TEST_LONG_KEY_NAME, 0LL);
    EXPECT_EQ(value, negValue);

    prefInstance->PutLong(TEST_LONG_KEY_NAME, -1LL);
    prefInstance->FlushSync();
    value = prefInstance->GetLong(TEST_LONG_KEY_NAME, 0LL);
    EXPECT_EQ(value, -1LL);
}

/**
 * @tc.name: PreferencesOperationTest_035
 * @tc.desc: normal testcase for zero values
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_035, TestSize.Level0)
{
    prefInstance->PutInt(TEST_INT_KEY, 0);
    prefInstance->PutLong(TEST_LONG_KEY_NAME, 0LL);
    prefInstance->PutFloat(TEST_FLOAT_KEY, 0.0f);
    prefInstance->PutDouble(TEST_DOUBLE_KEY, 0.0);
    prefInstance->PutBool(TEST_BOOL_KEY, false);
    prefInstance->FlushSync();

    EXPECT_EQ(prefInstance->GetInt(TEST_INT_KEY, -1), 0);
    EXPECT_EQ(prefInstance->GetLong(TEST_LONG_KEY_NAME, -1LL), 0LL);
    EXPECT_FLOAT_EQ(prefInstance->GetFloat(TEST_FLOAT_KEY, -1.0f), 0.0f);
    EXPECT_DOUBLE_EQ(prefInstance->GetDouble(TEST_DOUBLE_KEY, -1.0), 0.0);
    EXPECT_EQ(prefInstance->GetBool(TEST_BOOL_KEY, true), false);
}

/**
 * @tc.name: PreferencesOperationTest_036
 * @tc.desc: normal testcase for empty array
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_036, TestSize.Level0)
{
    std::vector<std::string> emptyStringArray = {};
    prefInstance->Put(TEST_STRING_ARRAY_KEY, emptyStringArray);
    prefInstance->FlushSync();

    PreferencesValue defValue(static_cast<int64_t>(0));
    PreferencesValue result = prefInstance->Get(TEST_STRING_ARRAY_KEY, defValue);
    EXPECT_EQ(result.IsStringArray(), true);
    auto retrievedArray = static_cast<std::vector<std::string>>(result);
    EXPECT_EQ(retrievedArray.empty(), true);
}

/**
 * @tc.name: PreferencesOperationTest_037
 * @tc.desc: normal testcase for large string value
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_037, TestSize.Level0)
{
    std::string largeString(10000, 'x');
    prefInstance->PutString(TEST_STRING_KEY, largeString);
    prefInstance->FlushSync();
    std::string value = prefInstance->GetString(TEST_STRING_KEY, "");
    EXPECT_EQ(value.size(), largeString.size());
    EXPECT_EQ(value, largeString);
}

/**
 * @tc.name: PreferencesOperationTest_038
 * @tc.desc: normal testcase for RegisterDataObserver
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_038, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<TestObserverCounter>();
    std::vector<std::string> keys = { TEST_STRING_KEY };
    prefInstance->RegisterDataObserver(observer, keys);
    prefInstance->PutString(TEST_STRING_KEY, "data_observer_test");
    prefInstance->FlushSync();
    EXPECT_EQ(static_cast<TestObserverCounter *>(observer.get())->changeCount, 1);
}

/**
 * @tc.name: PreferencesOperationTest_040
 * @tc.desc: normal testcase for PreferencesValue type checking
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_040, TestSize.Level0)
{
    PreferencesValue intValue(100);
    EXPECT_EQ(intValue.IsInt(), true);

    PreferencesValue strValue("test");
    EXPECT_EQ(strValue.IsString(), true);

    PreferencesValue boolValue(true);
    EXPECT_EQ(boolValue.IsBool(), true);

    PreferencesValue floatValue(1.0f);
    EXPECT_EQ(floatValue.IsFloat(), true);

    PreferencesValue doubleValue(1.0);
    EXPECT_EQ(doubleValue.IsDouble(), true);
}

/**
 * @tc.name: PreferencesOperationTest_041
 * @tc.desc: normal testcase for DeletePreferences error cases
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_041, TestSize.Level0)
{
    int ret = PreferencesHelper::DeletePreferences("");
    EXPECT_EQ(ret, E_EMPTY_FILE_PATH);

    ret = PreferencesHelper::RemovePreferencesFromCache("");
    EXPECT_EQ(ret, E_EMPTY_FILE_PATH);
}

/**
 * @tc.name: PreferencesOperationTest_042
 * @tc.desc: normal testcase for GetPreferences error cases
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_042, TestSize.Level0)
{
    int errCode = E_OK;
    auto pref = PreferencesHelper::GetPreferences("", errCode);
    EXPECT_EQ(errCode, E_EMPTY_FILE_PATH);

    pref = PreferencesHelper::GetPreferences("relative_path", errCode);
    EXPECT_EQ(errCode, E_RELATIVE_PATH);

    std::string longPath = "/data/test/" + std::string(4096, 'a');
    pref = PreferencesHelper::GetPreferences(longPath, errCode);
    EXPECT_EQ(errCode, E_PATH_EXCEED_MAX_LENGTH);
}

/**
 * @tc.name: PreferencesOperationTest_043
 * @tc.desc: normal testcase for bool array with all true
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_043, TestSize.Level0)
{
    std::vector<bool> allTrueArray(10, true);
    prefInstance->Put(TEST_BOOL_ARRAY_KEY, allTrueArray);
    prefInstance->FlushSync();

    PreferencesValue defValue(static_cast<int64_t>(0));
    PreferencesValue result = prefInstance->Get(TEST_BOOL_ARRAY_KEY, defValue);
    auto retrievedArray = static_cast<std::vector<bool>>(result);
    EXPECT_EQ(retrievedArray.size(), allTrueArray.size());
    for (size_t i = 0; i < retrievedArray.size(); i++) {
        EXPECT_EQ(retrievedArray[i], true);
    }
}

/**
 * @tc.name: PreferencesOperationTest_044
 * @tc.desc: normal testcase for double array with precision
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_044, TestSize.Level0)
{
    std::vector<double> precisionArray = { 0.123456789, 1.234567890, 12.345678901 };
    prefInstance->Put(TEST_DOUBLE_ARRAY_KEY, precisionArray);
    prefInstance->FlushSync();

    PreferencesValue defValue(static_cast<int64_t>(0));
    PreferencesValue result = prefInstance->Get(TEST_DOUBLE_ARRAY_KEY, defValue);
    auto retrievedArray = static_cast<std::vector<double>>(result);
    EXPECT_EQ(retrievedArray.size(), precisionArray.size());
    for (size_t i = 0; i < precisionArray.size(); i++) {
        EXPECT_DOUBLE_EQ(retrievedArray[i], precisionArray[i]);
    }
}

/**
 * @tc.name: PreferencesOperationTest_045
 * @tc.desc: normal testcase for repeated flush operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_045, TestSize.Level0)
{
    for (int i = 0; i < 5; i++) {
        prefInstance->PutInt(TEST_INT_KEY, i);
        int ret = prefInstance->FlushSync();
        EXPECT_EQ(ret, E_OK);
        EXPECT_EQ(prefInstance->GetInt(TEST_INT_KEY, -1), i);
    }
}

/**
 * @tc.name: PreferencesOperationTest_046
 * @tc.desc: normal testcase for Delete non-existent key
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_046, TestSize.Level0)
{
    int ret = prefInstance->Delete("non_existent_key_for_delete");
    EXPECT_EQ(ret, E_OK);

    bool hasKey = prefInstance->HasKey("non_existent_key_for_delete");
    EXPECT_EQ(hasKey, false);
}

/**
 * @tc.name: PreferencesOperationTest_047
 * @tc.desc: normal testcase for string array with empty elements
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_047, TestSize.Level0)
{
    std::vector<std::string> arrayWithEmpty = { "first", "", "third", "", "fifth" };
    prefInstance->Put(TEST_STRING_ARRAY_KEY, arrayWithEmpty);
    prefInstance->FlushSync();

    PreferencesValue defValue(static_cast<int64_t>(0));
    PreferencesValue result = prefInstance->Get(TEST_STRING_ARRAY_KEY, defValue);
    auto retrievedArray = static_cast<std::vector<std::string>>(result);
    EXPECT_EQ(retrievedArray.size(), arrayWithEmpty.size());
    EXPECT_EQ(retrievedArray[0], "first");
    EXPECT_EQ(retrievedArray[1], "");
    EXPECT_EQ(retrievedArray[2], "third");
}

/**
 * @tc.name: PreferencesOperationTest_049
 * @tc.desc: normal testcase for int64_t PreferencesValue
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_049, TestSize.Level0)
{
    int64_t largeValue = 9223372036854775807LL;
    PreferencesValue int64Value(largeValue);
    EXPECT_EQ(static_cast<int64_t>(int64Value), largeValue);
    EXPECT_EQ(int64Value.IsLong(), true);
}

/**
 * @tc.name: PreferencesOperationTest_050
 * @tc.desc: normal testcase for Options default constructor
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_050, TestSize.Level0)
{
    int errCode;
    std::string path = "/data/test/test_default_options";
    Options option(path);
    auto pref = PreferencesHelper::GetPreferences(option, errCode);
    EXPECT_EQ(errCode, E_OK);

    pref->PutInt("option_key", 123);
    pref->FlushSync();
    EXPECT_EQ(pref->GetInt("option_key", 0), 123);

    PreferencesHelper::DeletePreferences(path);
}

/**
 * @tc.name: PreferencesOperationTest_051
 * @tc.desc: normal testcase for maximum int value
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_051, TestSize.Level0)
{
    int maxValue = 2147483647;
    prefInstance->PutInt(TEST_INT_KEY, maxValue);
    prefInstance->FlushSync();
    int value = prefInstance->GetInt(TEST_INT_KEY, 0);
    EXPECT_EQ(value, maxValue);
}

/**
 * @tc.name: PreferencesOperationTest_052
 * @tc.desc: normal testcase for maximum long value
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_052, TestSize.Level0)
{
    int64_t maxLong = 9223372036854775807LL;
    prefInstance->PutLong(TEST_LONG_KEY_NAME, maxLong);
    prefInstance->FlushSync();
    int64_t value = prefInstance->GetLong(TEST_LONG_KEY_NAME, 0LL);
    EXPECT_EQ(value, maxLong);
}

/**
 * @tc.name: PreferencesOperationTest_053
 * @tc.desc: normal testcase for double max value
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_053, TestSize.Level0)
{
    double maxDouble = (std::numeric_limits<double>::max)();
    prefInstance->PutDouble(TEST_DOUBLE_KEY, maxDouble);
    prefInstance->FlushSync();
    double value = prefInstance->GetDouble(TEST_DOUBLE_KEY, 0.0);
    EXPECT_EQ(value, maxDouble);
}

/**
 * @tc.name: PreferencesOperationTest_054
 * @tc.desc: normal testcase for multiple observers
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_054, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer1 = std::make_shared<TestObserverCounter>();
    std::shared_ptr<PreferencesObserver> observer2 = std::make_shared<TestObserverCounter>();

    prefInstance->RegisterObserver(observer1);
    prefInstance->RegisterObserver(observer2);

    prefInstance->PutInt(TEST_INT_KEY, 100);
    prefInstance->FlushSync();

    EXPECT_EQ(static_cast<TestObserverCounter *>(observer1.get())->changeCount, 1);
    EXPECT_EQ(static_cast<TestObserverCounter *>(observer2.get())->changeCount, 1);

    prefInstance->UnRegisterObserver(observer1);
    prefInstance->UnRegisterObserver(observer2);
}

/**
 * @tc.name: PreferencesOperationTest_055
 * @tc.desc: normal testcase for uint8 array with max values
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_055, TestSize.Level0)
{
    std::vector<uint8_t> maxUint8Array = { 0, 127, 255, 128, 64 };
    prefInstance->Put(TEST_UINT8_ARRAY_KEY, maxUint8Array);
    prefInstance->FlushSync();

    PreferencesValue defValue(static_cast<int64_t>(0));
    PreferencesValue result = prefInstance->Get(TEST_UINT8_ARRAY_KEY, defValue);
    auto retrievedArray = static_cast<std::vector<uint8_t>>(result);
    EXPECT_EQ(retrievedArray.size(), maxUint8Array.size());
    for (size_t i = 0; i < maxUint8Array.size(); i++) {
        EXPECT_EQ(retrievedArray[i], maxUint8Array[i]);
    }
}

/**
 * @tc.name: PreferencesOperationTest_056
 * @tc.desc: normal testcase for repeated Clear operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_056, TestSize.Level0)
{
    prefInstance->PutInt(TEST_INT_KEY, 100);
    prefInstance->FlushSync();

    int ret = prefInstance->Clear();
    EXPECT_EQ(ret, E_OK);
    ret = prefInstance->Clear();
    EXPECT_EQ(ret, E_OK);

    bool hasKey = prefInstance->HasKey(TEST_INT_KEY);
    EXPECT_EQ(hasKey, false);
}

/**
 * @tc.name: PreferencesOperationTest_057
 * @tc.desc: normal testcase for PreferencesValue equality
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_057, TestSize.Level0)
{
    PreferencesValue value1(100);
    PreferencesValue value2(100);
    EXPECT_EQ(value1 == value2, true);

    PreferencesValue value3("test");
    PreferencesValue value4("test");
    EXPECT_EQ(value3 == value4, true);

    PreferencesValue value5(true);
    PreferencesValue value6(true);
    EXPECT_EQ(value5 == value6, true);
}

/**
 * @tc.name: PreferencesOperationTest_058
 * @tc.desc: normal testcase for long string key
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_058, TestSize.Level0)
{
    std::string longKey = "very_long_key_name_for_testing_purpose_" + std::string(100, 'k');
    prefInstance->PutString(longKey, "long_key_value");
    prefInstance->FlushSync();
    std::string value = prefInstance->GetString(longKey, "");
    EXPECT_EQ(value, "long_key_value");
}

/**
 * @tc.name: PreferencesOperationTest_059
 * @tc.desc: normal testcase for float precision
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_059, TestSize.Level0)
{
    float preciseValue = 0.000001f;
    prefInstance->PutFloat(TEST_FLOAT_KEY, preciseValue);
    prefInstance->FlushSync();
    float value = prefInstance->GetFloat(TEST_FLOAT_KEY, 0.0f);
    EXPECT_FLOAT_EQ(value, preciseValue);
}

/**
 * @tc.name: PreferencesOperationTest_060
 * @tc.desc: normal testcase for multiple delete operations
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesOperationTest, PreferencesOperationTest_060, TestSize.Level0)
{
    for (int i = 0; i < 5; i++) {
        std::string key = "delete_test_key_" + std::to_string(i);
        prefInstance->PutInt(key, i);
    }
    prefInstance->FlushSync();

    for (int i = 0; i < 5; i++) {
        std::string key = "delete_test_key_" + std::to_string(i);
        int ret = prefInstance->Delete(key);
        EXPECT_EQ(ret, E_OK);
        bool hasKey = prefInstance->HasKey(key);
        EXPECT_EQ(hasKey, false);
    }
}

} // namespace
