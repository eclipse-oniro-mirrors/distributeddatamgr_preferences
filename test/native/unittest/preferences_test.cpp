/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "preferences.h"

#include <gtest/gtest.h>

#include <cctype>
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
const std::string LONG_KEY = std::string(Preferences::MAX_KEY_LENGTH, std::toupper('a'));
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
class PreferencesTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static std::shared_ptr<Preferences> pref;
};

std::shared_ptr<Preferences> PreferencesTest::pref = nullptr;

void PreferencesTest::SetUpTestCase(void)
{
}

void PreferencesTest::TearDownTestCase(void)
{
}

void PreferencesTest::SetUp(void)
{
    int errCode = E_OK;
    pref = PreferencesHelper::GetPreferences("/data/test/test", errCode);
    EXPECT_EQ(errCode, E_OK);
}

void PreferencesTest::TearDown(void)
{
    pref = nullptr;
    int ret = PreferencesHelper::DeletePreferences("/data/test/test");
    EXPECT_EQ(ret, E_OK);
}

class PreferencesObserverCounter : public PreferencesObserver {
public:
    virtual ~PreferencesObserverCounter();
    void OnChange(const std::string &key) override;
    void OnChange(const std::map<std::string, OHOS::NativePreferences::PreferencesValue> &records) override;

    std::atomic_int notifyTimes;
    static const std::vector<std::string> NOTIFY_KEYS_VECTOR;
};

PreferencesObserverCounter::~PreferencesObserverCounter()
{
}

void PreferencesObserverCounter::OnChange(const std::string &key)
{
    for (auto it = NOTIFY_KEYS_VECTOR.cbegin(); it != NOTIFY_KEYS_VECTOR.cend(); it++) {
        if (key.compare(*it)) {
            notifyTimes++;
            break;
        }
    }
}

void PreferencesObserverCounter::OnChange(
    const std::map<std::string, OHOS::NativePreferences::PreferencesValue> &records)
{
    for (auto it = NOTIFY_KEYS_VECTOR.cbegin(); it != NOTIFY_KEYS_VECTOR.cend(); it++) {
        for (auto iter = records.begin(); iter != records.end(); iter++) {
            std::string key = iter->first;
            if (key.compare(*it)) {
                notifyTimes++;
                return;
            }
        }
    }
}

const std::vector<std::string> PreferencesObserverCounter::NOTIFY_KEYS_VECTOR = { KEY_TEST_INT_ELEMENT,
    KEY_TEST_LONG_ELEMENT, KEY_TEST_FLOAT_ELEMENT, KEY_TEST_BOOL_ELEMENT, KEY_TEST_STRING_ELEMENT };

class PreferencesObserverCrossProcess : public PreferencesObserver {
public:
    virtual ~PreferencesObserverCrossProcess();
    void OnChange(const std::string &key) override;
    void Wait();

    std::mutex mut;
    std::condition_variable cond;
    std::string notifyKey;
    bool result;
};

PreferencesObserverCrossProcess::~PreferencesObserverCrossProcess()
{
}

void PreferencesObserverCrossProcess::Wait()
{
    std::unique_lock<std::mutex> lock(mut);
    if (!result) {
        cond.wait(lock, [this] { return result; });
    }
}

void PreferencesObserverCrossProcess::OnChange(const std::string &key)
{
    std::unique_lock<std::mutex> lock(mut);
    notifyKey = key;
    result = true;
    cond.notify_all();
}

/**
 * @tc.name: NativePreferencesGroupIdTest_001
 * @tc.desc: normal testcase of GetGroupId
 * @tc.type: FUNC
 * @tc.author: lirui
 */
HWTEST_F(PreferencesTest, NativePreferencesGroupIdTest_001, TestSize.Level0)
{
    int errCode = E_OK;
    Options option = Options("/data/test/test1", "ohos.test.demo", "2002001");
    std::shared_ptr<Preferences> preferences = PreferencesHelper::GetPreferences(option, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(preferences->GetGroupId(), "2002001");
    EXPECT_EQ(preferences->GetBundleName(), "ohos.test.demo");

    preferences = nullptr;
    int ret = PreferencesHelper::DeletePreferences("/data/test/test1");
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: NativePreferencesTest_001
 * @tc.desc: normal testcase of FlushSync
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT_ELEMENT, 2);
    pref->PutString(KEY_TEST_STRING_ELEMENT, "test");
    pref->FlushSync();

    int ret1 = pref->GetInt(KEY_TEST_INT_ELEMENT, 6);
    EXPECT_EQ(ret1, 2);
    std::string ret2 = pref->GetString(KEY_TEST_STRING_ELEMENT, "test1");
    EXPECT_EQ(ret2, "test");
}

/**
 * @tc.name: NativePreferencesTest_002
 * @tc.desc: normal testcase of HasKey
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_002, TestSize.Level0)
{
    bool ret = pref->HasKey(LONG_KEY + 'x');
    EXPECT_EQ(ret, false);

    ret = pref->HasKey(std::string());
    EXPECT_EQ(ret, false);

    pref->PutString(KEY_TEST_STRING_ELEMENT, "test");
    ret = pref->HasKey(KEY_TEST_STRING_ELEMENT);
    EXPECT_EQ(ret, true);

    pref->FlushSync();
    ret = pref->HasKey(KEY_TEST_STRING_ELEMENT);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: NativePreferencesTest_003
 * @tc.desc: normal testcase of pref
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_003, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING_ELEMENT, "test1");

    std::string ret = pref->GetString(KEY_TEST_STRING_ELEMENT, "defaultvalue");
    EXPECT_EQ(ret, "test1");

    pref->FlushSync();
    ret = pref->GetString(KEY_TEST_STRING_ELEMENT, "defaultvalue");
    EXPECT_EQ(ret, "test1");
}

/**
 * @tc.name: NativePreferencesTest_004
 * @tc.desc: normal testcase of GetBool
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_004, TestSize.Level0)
{
    bool ret = pref->GetBool(LONG_KEY + 'x', true);
    EXPECT_EQ(ret, true);

    ret = pref->GetBool("", true);
    EXPECT_EQ(ret, true);

    pref->PutBool(KEY_TEST_BOOL_ELEMENT, false);
    pref->PutString(KEY_TEST_STRING_ELEMENT, "false");
    pref->FlushSync();

    ret = pref->GetBool(KEY_TEST_BOOL_ELEMENT, true);
    EXPECT_EQ(ret, false);

    ret = pref->GetBool(KEY_TEST_STRING_ELEMENT, true);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: NativePreferencesTest_005
 * @tc.desc: normal testcase of GetFloat
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_005, TestSize.Level0)
{
    float ret = pref->GetFloat(LONG_KEY + 'x', 3.0f);
    EXPECT_EQ(ret, 3.0f);

    ret = pref->GetFloat("", 3.0f);
    EXPECT_EQ(ret, 3.0f);

    pref->PutFloat(KEY_TEST_FLOAT_ELEMENT, 5.0f);
    pref->PutString(KEY_TEST_STRING_ELEMENT, "5.0");
    pref->FlushSync();

    ret = pref->GetFloat(KEY_TEST_FLOAT_ELEMENT, true);
    EXPECT_EQ(ret, 5.0f);

    ret = pref->GetFloat(KEY_TEST_STRING_ELEMENT, 3.0f);
    EXPECT_EQ(ret, 3.0f);
}

/**
 * @tc.name: NativePreferencesTest_006
 * @tc.desc: normal testcase of GetInt
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_006, TestSize.Level0)
{
    int ret = pref->GetInt(LONG_KEY + 'x', 35);
    EXPECT_EQ(ret, 35);

    ret = pref->GetInt("", 35);
    EXPECT_EQ(ret, 35);

    pref->PutInt(KEY_TEST_INT_ELEMENT, 5);
    pref->PutString(KEY_TEST_STRING_ELEMENT, "5");
    pref->FlushSync();

    ret = pref->GetInt(KEY_TEST_INT_ELEMENT, 3);
    EXPECT_EQ(ret, 5);

    ret = pref->GetInt(KEY_TEST_STRING_ELEMENT, 3);
    EXPECT_EQ(ret, 3);
}

/**
 * @tc.name: NativePreferencesTest_007
 * @tc.desc: normal testcase of GetLong
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_007, TestSize.Level0)
{
    int64_t ret = pref->GetLong(LONG_KEY + 'x', 35L);
    EXPECT_EQ(ret, 35L);

    ret = pref->GetLong("", 35L);
    EXPECT_EQ(ret, 35L);

    pref->PutInt(KEY_TEST_INT_ELEMENT, 5);
    pref->PutLong(KEY_TEST_LONG_ELEMENT, 5L);
    pref->FlushSync();

    ret = pref->GetLong(KEY_TEST_INT_ELEMENT, 3L);
    EXPECT_EQ(ret, 3L);

    ret = pref->GetLong(KEY_TEST_LONG_ELEMENT, 3L);
    EXPECT_EQ(ret, 5L);
}

/**
 * @tc.name: NativePreferencesTest_008
 * @tc.desc: normal testcase of GetString
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_008, TestSize.Level0)
{
    std::string ret = pref->GetString(LONG_KEY + 'x', "test");
    EXPECT_EQ(ret, "test");

    ret = pref->GetString("", "test");
    EXPECT_EQ(ret, "test");

    pref->PutInt(KEY_TEST_INT_ELEMENT, 5);
    pref->PutString(KEY_TEST_LONG_ELEMENT, "test");
    pref->FlushSync();

    ret = pref->GetString(KEY_TEST_INT_ELEMENT, "defaultvalue");
    EXPECT_EQ(ret, "defaultvalue");

    ret = pref->GetString(KEY_TEST_LONG_ELEMENT, "defaultvalue");
    EXPECT_EQ(ret, "test");
}

/**
 * @tc.name: NativePreferencesTest_009
 * @tc.desc: normal testcase of GetDefValue
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_009, TestSize.Level0)
{
    int ret0 = pref->GetInt(KEY_TEST_INT_ELEMENT, -1);
    EXPECT_EQ(ret0, -1);

    float ret1 = pref->GetFloat(KEY_TEST_FLOAT_ELEMENT, 1.0f);
    EXPECT_EQ(ret1, 1.0f);

    int64_t ret2 = pref->GetLong(KEY_TEST_LONG_ELEMENT, 10000L);
    EXPECT_EQ(ret2, 10000L);

    bool ret3 = pref->GetBool(KEY_TEST_BOOL_ELEMENT, true);
    EXPECT_EQ(ret3, true);

    std::string ret4 = pref->GetString(KEY_TEST_STRING_ELEMENT, "test");
    EXPECT_EQ(ret4, "test");
}

/**
 * @tc.name: NativePreferencesTest_010
 * @tc.desc: normal testcase of PutBool
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_010, TestSize.Level0)
{
    pref->PutBool(LONG_KEY + 'x', true);
    pref->PutBool("", true);
    pref->FlushSync();

    bool ret = pref->GetBool(LONG_KEY + 'x', false);
    EXPECT_EQ(ret, false);
    ret = pref->GetBool("", false);
    EXPECT_EQ(ret, false);

    pref->PutBool(LONG_KEY, true);
    pref->PutBool(KEY_TEST_BOOL_ELEMENT, true);
    pref->FlushSync();

    ret = pref->GetBool(LONG_KEY, false);
    EXPECT_EQ(ret, true);
    ret = pref->GetBool(KEY_TEST_BOOL_ELEMENT, false);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: NativePreferencesTest_011
 * @tc.desc: normal testcase of PutFloat
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_011, TestSize.Level0)
{
    pref->PutFloat(LONG_KEY + 'x', 3.0f);
    pref->PutFloat("", 3.0f);
    pref->FlushSync();

    float ret = pref->GetFloat(LONG_KEY + 'x', 1.0f);
    EXPECT_EQ(ret, 1.0f);
    ret = pref->GetFloat("", 1.0f);
    EXPECT_EQ(ret, 1.0f);

    pref->PutFloat(LONG_KEY, 3.0f);
    pref->PutFloat(KEY_TEST_FLOAT_ELEMENT, 3.0f);
    pref->FlushSync();

    ret = pref->GetFloat(LONG_KEY, 1.0f);
    EXPECT_EQ(ret, 3.0f);
    ret = pref->GetFloat(KEY_TEST_FLOAT_ELEMENT, 1.0f);
    EXPECT_EQ(ret, 3.0f);
}

/**
 * @tc.name: NativePreferencesTest_012
 * @tc.desc: normal testcase of PutInt
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_012, TestSize.Level0)
{
    pref->PutInt(LONG_KEY + 'x', 3);
    pref->PutInt("", 3);
    pref->FlushSync();

    int ret = pref->GetInt(LONG_KEY + 'x', 1);
    EXPECT_EQ(ret, 1);
    ret = pref->GetInt("", 1);
    EXPECT_EQ(ret, 1);

    pref->PutInt(LONG_KEY, 3);
    pref->PutInt(KEY_TEST_INT_ELEMENT, 3);
    pref->FlushSync();

    ret = pref->GetInt(LONG_KEY, 1);
    EXPECT_EQ(ret, 3);
    ret = pref->GetInt(KEY_TEST_INT_ELEMENT, 1);
    EXPECT_EQ(ret, 3);
}

/**
 * @tc.name: NativePreferencesTest_013
 * @tc.desc: normal testcase of PutLong
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_013, TestSize.Level0)
{
    pref->PutLong(LONG_KEY + 'x', 3L);
    pref->PutLong("", 3L);
    pref->FlushSync();

    int64_t ret = pref->GetLong(LONG_KEY + 'x', 1L);
    EXPECT_EQ(ret, 1L);
    ret = pref->GetLong("", 1L);
    EXPECT_EQ(ret, 1L);

    pref->PutLong(LONG_KEY, 3L);
    pref->PutLong(KEY_TEST_LONG_ELEMENT, 3L);
    pref->FlushSync();

    ret = pref->GetLong(LONG_KEY, 1L);
    EXPECT_EQ(ret, 3L);
    ret = pref->GetLong(KEY_TEST_LONG_ELEMENT, 1L);
    EXPECT_EQ(ret, 3L);
}

/**
 * @tc.name: NativePreferencesTest_014
 * @tc.desc: normal testcase of PutString
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_014, TestSize.Level0)
{
    pref->PutString(LONG_KEY + 'x', "test");
    pref->PutString("", "test");
    pref->FlushSync();

    std::string ret = pref->GetString(LONG_KEY + 'x', "defaultValue");
    EXPECT_EQ(ret, "defaultValue");
    ret = pref->GetString("", "defaultValue");
    EXPECT_EQ(ret, "defaultValue");

    pref->PutString(LONG_KEY, "test");
    pref->PutString(KEY_TEST_STRING_ELEMENT, "test");
    pref->FlushSync();

    ret = pref->GetString(LONG_KEY, "defaultValue");
    EXPECT_EQ(ret, "test");
    ret = pref->GetString(KEY_TEST_STRING_ELEMENT, "defaultValue");
    EXPECT_EQ(ret, "test");
}

/**
 * @tc.name: NativePreferencesTest_015
 * @tc.desc: normal testcase of Delete
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_015, TestSize.Level0)
{
    pref->PutString("test", "remove");
    pref->FlushSync();

    std::string ret = pref->GetString("test", "defaultValue");
    EXPECT_EQ(ret, "remove");

    pref->Delete("test");
    pref->FlushSync();
    ret = pref->GetString("test", "defaultValue");
    EXPECT_EQ(ret, "defaultValue");
    int res = pref->Delete("");
    EXPECT_EQ(res, E_KEY_EMPTY);
}

/**
 * @tc.name: NativePreferencesTest_016
 * @tc.desc: normal testcase of RegisterPreferencesObserver
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_016, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> counter = std::make_shared<PreferencesObserverCounter>();
    pref->RegisterObserver(counter);

    pref->PutString(KEY_TEST_STRING_ELEMENT, "test");
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverCounter *>(counter.get())->notifyTimes, 1);

    /* same value */
    pref->PutInt(KEY_TEST_INT_ELEMENT, 2);
    pref->PutString(KEY_TEST_STRING_ELEMENT, "test");
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverCounter *>(counter.get())->notifyTimes, 2);

    pref->UnRegisterObserver(counter);
}

/**
 * @tc.name: NativePreferencesTest_017
 * @tc.desc: normal testcase of UnRegisterPreferencesObserver
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_017, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> counter = std::make_shared<PreferencesObserverCounter>();
    pref->RegisterObserver(counter);

    pref->PutInt(KEY_TEST_INT_ELEMENT, 2);
    pref->PutString(KEY_TEST_STRING_ELEMENT, "test");
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverCounter *>(counter.get())->notifyTimes, 2);

    pref->UnRegisterObserver(counter);

    pref->PutInt(KEY_TEST_INT_ELEMENT, 6);
    pref->PutString(KEY_TEST_STRING_ELEMENT, "test1");
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverCounter *>(counter.get())->notifyTimes, 2);
}

/**
 * @tc.name: NativePreferencesTest_018
 * @tc.desc: normal testcase of Clear
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_018, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING_ELEMENT, "test");
    pref->PutInt(KEY_TEST_INT_ELEMENT, 3);
    pref->FlushSync();

    pref->Clear();
    std::string ret = pref->GetString(KEY_TEST_STRING_ELEMENT, "defaultvalue");
    EXPECT_EQ(ret, "defaultvalue");
    int ret1 = pref->GetInt(KEY_TEST_INT_ELEMENT, 0);
    EXPECT_EQ(ret1, 0);

    pref->FlushSync();
    ret = pref->GetString(KEY_TEST_STRING_ELEMENT, "defaultvalue");
    EXPECT_EQ(ret, "defaultvalue");
    ret1 = pref->GetInt(KEY_TEST_INT_ELEMENT, 0);
    EXPECT_EQ(ret1, 0);
}

/**
 * @tc.name: NativePreferencesTest_019
 * @tc.desc: normal testcase of GetDouble
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: mang tsang
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_019, TestSize.Level0)
{
    double ret = pref->GetDouble(LONG_KEY + 'x', 35.99999);
    EXPECT_EQ(ret, 35.99999);

    ret = pref->GetDouble("", 35.99999);
    EXPECT_EQ(ret, 35.99999);

    pref->PutDouble(KEY_TEST_DOUBLE_ELEMENT, (std::numeric_limits<double>::max)());
    pref->PutString(KEY_TEST_STRING_ELEMENT, "5.99");
    pref->FlushSync();

    ret = pref->GetDouble(KEY_TEST_DOUBLE_ELEMENT, 3.99);
    EXPECT_EQ(ret, (std::numeric_limits<double>::max)());

    ret = pref->GetDouble(KEY_TEST_STRING_ELEMENT, 3.99);
    EXPECT_EQ(ret, 3.99);
}

/**
 * @tc.name: NativePreferencesTest_020
 * @tc.desc: normal testcase of GetDouble without defaultValue
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: lijuntao
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_020, TestSize.Level0)
{
    int errCode;
    std::shared_ptr<Preferences> pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);
    pref1->PutDouble(KEY_TEST_DOUBLE_ELEMENT, (std::numeric_limits<double>::max)());
    pref1->FlushSync();
    PreferencesHelper::RemovePreferencesFromCache("/data/test/test1");
    pref1.reset();
    pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);
    double ret = pref1->GetDouble(KEY_TEST_DOUBLE_ELEMENT);
    EXPECT_EQ(ret, (std::numeric_limits<double>::max)());
    PreferencesHelper::DeletePreferences("/data/test/test1");
}

/**
 * @tc.name: NativePreferencesTest_021
 * @tc.desc: normal testcase of GetString without defaultValue
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: lijuntao
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_021, TestSize.Level0)
{
    int errCode;
    auto pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);
    pref1->PutString(LONG_KEY, "test");
    pref1->PutString(KEY_TEST_STRING_ELEMENT, "test1 test2");
    pref1->FlushSync();

    PreferencesHelper::RemovePreferencesFromCache("/data/test/test1");
    pref1.reset();
    pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);

    std::string ret = pref1->GetString(LONG_KEY);
    EXPECT_EQ(ret, "test");
    ret = pref1->GetString(KEY_TEST_STRING_ELEMENT);
    EXPECT_EQ(ret, "test1 test2");
    PreferencesHelper::DeletePreferences("/data/test/test1");
}

/**
 * @tc.name: NativePreferencesTest_022
 * @tc.desc: normal testcase of GetLong without defaultValue
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: lijuntao
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_022, TestSize.Level0)
{
    int errCode;
    auto pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);
    pref1->PutLong(LONG_KEY, 3L);
    pref1->PutLong(KEY_TEST_LONG_ELEMENT, 3L);
    pref1->FlushSync();

    PreferencesHelper::RemovePreferencesFromCache("/data/test/test1");
    pref1.reset();
    pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);

    int64_t ret = pref1->GetLong(LONG_KEY);
    EXPECT_EQ(ret, 3L);
    ret = pref1->GetLong(KEY_TEST_LONG_ELEMENT);
    EXPECT_EQ(ret, 3L);
    PreferencesHelper::DeletePreferences("/data/test/test1");
}

/**
 * @tc.name: NativePreferencesTest_023
 * @tc.desc: normal testcase of GetInt without defaultValue
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: lijuntao
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_023, TestSize.Level0)
{
    int errCode;
    auto pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);
    pref1->PutInt(LONG_KEY, 3);
    pref1->PutInt(KEY_TEST_INT_ELEMENT, 3);
    pref1->FlushSync();

    PreferencesHelper::RemovePreferencesFromCache("/data/test/test1");
    pref1.reset();
    pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);

    int32_t ret = pref1->GetInt(LONG_KEY);
    EXPECT_EQ(ret, 3);
    ret = pref1->GetInt(KEY_TEST_INT_ELEMENT);
    EXPECT_EQ(ret, 3);
    PreferencesHelper::DeletePreferences("/data/test/test1");
}

/**
 * @tc.name: NativePreferencesTest_024
 * @tc.desc: normal testcase of GetFloat without defaultValue
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: lijuntao
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_024, TestSize.Level0)
{
    int errCode;
    auto pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);
    pref1->PutFloat(LONG_KEY, 3.0f);
    pref1->PutFloat(KEY_TEST_FLOAT_ELEMENT, 3.0f);
    pref1->FlushSync();

    PreferencesHelper::RemovePreferencesFromCache("/data/test/test1");
    pref1.reset();
    pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);

    float ret = pref1->GetFloat(LONG_KEY);
    EXPECT_EQ(ret, 3.0f);
    ret = pref1->GetFloat(KEY_TEST_FLOAT_ELEMENT);
    EXPECT_EQ(ret, 3.0f);
    PreferencesHelper::DeletePreferences("/data/test/test1");
}

/**
 * @tc.name: NativePreferencesTest_025
 * @tc.desc: normal testcase of GetBool without defaultValue
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: lijuntao
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_025, TestSize.Level0)
{
    int errCode;
    auto pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);
    pref1->PutBool(LONG_KEY, true);
    pref1->PutBool(KEY_TEST_BOOL_ELEMENT, true);
    pref1->FlushSync();

    PreferencesHelper::RemovePreferencesFromCache("/data/test/test1");
    pref1.reset();
    pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);

    bool ret = pref1->GetBool(LONG_KEY);
    EXPECT_EQ(ret, true);
    ret = pref1->GetBool(KEY_TEST_BOOL_ELEMENT);
    EXPECT_EQ(ret, true);
    PreferencesHelper::DeletePreferences("/data/test/test1");
}

/**
 * @tc.name: NativePreferencesTest_026
 * @tc.desc: normal testcase of GetArray
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: changjiaxing
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_026, TestSize.Level0)
{
    int errCode;
    auto pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);
    std::vector<std::string> stringArray = { "str1", "str2" };
    std::vector<bool> boolArray = { false, true };
    std::vector<double> doubleArray = { 0.1, 0.2 };
    std::vector<uint8_t> uint8Array = { 1, 2, 3, 4, 5, 6, 7 };
    pref1->Put(KEY_TEST_STRING_ARRAY_ELEMENT, stringArray);
    pref1->Put(KEY_TEST_BOOL_ARRAY_ELEMENT, boolArray);
    pref1->Put(KEY_TEST_DOUBLE_ARRAY_ELEMENT, doubleArray);
    pref1->Put(KEY_TEST_UINT8_ARRAY_ELEMENT, uint8Array);
    pref1->FlushSync();

    PreferencesHelper::RemovePreferencesFromCache("/data/test/test1");
    pref1.reset();
    pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);

    PreferencesValue defValue(static_cast<int64_t>(0));
    PreferencesValue stringArrayRes = pref1->Get(KEY_TEST_STRING_ARRAY_ELEMENT, defValue);
    EXPECT_EQ(stringArrayRes.IsStringArray(), true);
    EXPECT_EQ(static_cast<std::vector<std::string>>(stringArrayRes), stringArray);

    PreferencesValue boolArrayRes = pref1->Get(KEY_TEST_BOOL_ARRAY_ELEMENT, defValue);
    EXPECT_EQ(boolArrayRes.IsBoolArray(), true);
    EXPECT_EQ(static_cast<std::vector<bool>>(boolArrayRes), boolArray);

    PreferencesValue doubleArrayRes = pref1->Get(KEY_TEST_DOUBLE_ARRAY_ELEMENT, defValue);
    EXPECT_EQ(doubleArrayRes.IsDoubleArray(), true);
    EXPECT_EQ(static_cast<std::vector<double>>(doubleArrayRes), doubleArray);

    PreferencesValue uint8ArrayRes = pref1->Get(KEY_TEST_UINT8_ARRAY_ELEMENT, defValue);
    EXPECT_EQ(uint8ArrayRes.IsUint8Array(), true);
    EXPECT_EQ(static_cast<std::vector<uint8_t>>(uint8ArrayRes), uint8Array);
    PreferencesHelper::DeletePreferences("/data/test/test1");
}

/**
 * @tc.name: NativePreferencesTest_027
 * @tc.desc: normal testcase of GetAll
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: changjiaxing
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_027, TestSize.Level0)
{
    int errCode;
    auto pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);

    std::map<std::string, PreferencesValue> map = { { KEY_TEST_INT_ELEMENT, 1 }, { KEY_TEST_FLOAT_ELEMENT, 0.1 },
        { KEY_TEST_BOOL_ELEMENT, false }, { KEY_TEST_STRING_ELEMENT, "test" } };

    for (auto i : map) {
        pref1->Put(i.first, i.second);
    }

    auto ret = pref1->GetAll();

    EXPECT_EQ(map.size(), ret.size());
    auto iter1 = map.begin();
    auto iter2 = ret.begin();
    for (;iter1 != map.end(); ++iter1, ++iter2) {
        EXPECT_EQ(iter1->first, iter2->first);
        bool isequa = false;
        if (iter1->second == iter2->second) {
            isequa = true;
        }
        EXPECT_TRUE(isequa);
    }
    PreferencesHelper::DeletePreferences("/data/test/test1");
}

/**
 * @tc.name: NativePreferencesTest_028
 * @tc.desc: Cross process subscription testing
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: changjiaxing
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_028, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserverCrossProcess> counter = std::make_shared<PreferencesObserverCrossProcess>();
    int ret = pref->RegisterObserver(counter, RegisterMode::MULTI_PRECESS_CHANGE);
    EXPECT_EQ(ret, E_OK);
    pref->PutString(KEY_TEST_STRING_ELEMENT, "test");
    pref->FlushSync();
    counter->Wait();
    EXPECT_EQ(counter->notifyKey, KEY_TEST_STRING_ELEMENT);

    ret = pref->UnRegisterObserver(counter, RegisterMode::MULTI_PRECESS_CHANGE);
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: NativePreferencesTest_029
 * @tc.desc: normal testcase of GetBigInt without defaultValue
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: changjiaxing
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_029, TestSize.Level0)
{
    int errCode;
    auto pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);
    std::vector<uint64_t> words = { 1, 2, 3 };
    BigInt bigint1(words, 0);
    BigInt bigint2(words, 1);
    pref1->Put(LONG_KEY, bigint1);
    pref1->Put(KEY_TEST_BIGINT_ELEMENT, bigint2);
    pref1->FlushSync();

    PreferencesHelper::RemovePreferencesFromCache("/data/test/test1");
    pref1.reset();
    pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);

    BigInt ret = pref1->Get(LONG_KEY, BigInt());
    EXPECT_EQ(ret, bigint1);
    ret = pref1->Get(KEY_TEST_BIGINT_ELEMENT, BigInt());
    EXPECT_EQ(ret, bigint2);
    PreferencesHelper::DeletePreferences("/data/test/test1");
}

/**
 * @tc.name: NativePreferencesTest_030
 * @tc.desc: normal testcase of GetBigInt without defaultValue
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: changjiaxing
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_030, TestSize.Level0)
{
    int errCode;
    auto pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);
    std::vector<uint64_t> words = {};
    BigInt bigint1(words, 0);
    errCode = pref1->Put(LONG_KEY, bigint1);
    EXPECT_EQ(errCode, E_ERROR);

    PreferencesHelper::DeletePreferences("/data/test/test1");
}

/**
 * @tc.name: NativePreferencesTest_031
 * @tc.desc: normal testcase of get object
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: bty
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_031, TestSize.Level0)
{
    int errCode;
    auto pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);
    Object object("{\"key1\":\"value1\",\"key2\":222}");
    EXPECT_EQ(pref1->Put(KEY_TEST_OBJECT_ELEMENT, object), E_OK);
    pref1->FlushSync();

    PreferencesHelper::RemovePreferencesFromCache("/data/test/test1");
    pref1.reset();
    pref1 = PreferencesHelper::GetPreferences("/data/test/test1", errCode);
    PreferencesValue defValue(static_cast<int64_t>(0));
    PreferencesValue res = pref1->Get(KEY_TEST_OBJECT_ELEMENT, defValue);
    EXPECT_EQ(static_cast<Object>(res), object);
    PreferencesHelper::DeletePreferences("/data/test/test1");
}

/**
 * @tc.name: NativePreferencesTest_032
 * @tc.desc: normal testcase of OnChange DataChange
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: lirui
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_032, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> counter = std::make_shared<PreferencesObserverCounter>();
    std::vector<std::string> keys = { KEY_TEST_STRING_ELEMENT };
    pref->RegisterDataObserver(counter, keys);
    pref->PutString(KEY_TEST_STRING_ELEMENT, "test");
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverCounter *>(counter.get())->notifyTimes, 1);
}

/**
 * @tc.name: NativePreferencesTest_033
 * @tc.desc: RegisterObserver testing
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_033, TestSize.Level0)
{
    vector<std::shared_ptr<PreferencesObserverCrossProcess>> counters;
    for (int i = 0; i <= 50; i++) {
        std::shared_ptr<PreferencesObserverCrossProcess> counter = std::make_shared<PreferencesObserverCrossProcess>();
        counters.push_back(counter);
        int ret = pref->RegisterObserver(counter, RegisterMode::MULTI_PRECESS_CHANGE);
        EXPECT_EQ(ret, E_OK);
    }
    std::shared_ptr<PreferencesObserverCrossProcess> counter = std::make_shared<PreferencesObserverCrossProcess>();
    int ret = pref->RegisterObserver(counter, RegisterMode::MULTI_PRECESS_CHANGE);
    EXPECT_NE(ret, E_OK);
    for (auto counter : counters) {
        ret = pref->UnRegisterObserver(counter, RegisterMode::MULTI_PRECESS_CHANGE);
        EXPECT_EQ(ret, E_OK);
    }
}

/**
 * @tc.name: OperatorTest_001
 * @tc.desc: normal testcase of PreferencesValue Operator
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesTest, PreferencesValueTest_001, TestSize.Level0)
{
    int valueInt = 1;
    int retInt = PreferencesValue(valueInt);
    EXPECT_EQ(valueInt, retInt);

    int64_t valueInt64 = 1;
    int64_t retInt64 = PreferencesValue(valueInt64);
    EXPECT_EQ(valueInt64, retInt64);

    float valueFloat = 1.0;
    float retFloat = PreferencesValue(valueFloat);
    EXPECT_EQ(valueFloat, retFloat);

    double valueDouble = 1.0;
    double retDouble = PreferencesValue(valueDouble);
    EXPECT_EQ(valueDouble, retDouble);

    bool valueBool = true;
    bool retBool = PreferencesValue(valueBool);
    EXPECT_EQ(valueBool, retBool);

    string valueString = "test";
    string retString = PreferencesValue(valueString);
    EXPECT_EQ(valueString, retString);

    std::vector<bool> valueVectorBool(2, true);
    std::vector<bool> retVectorBool = PreferencesValue(valueVectorBool);
    EXPECT_EQ(valueVectorBool, retVectorBool);

    std::vector<double> valueVectorDouble(2, 1.0);
    std::vector<double> retVectorDouble = PreferencesValue(valueVectorDouble);
    EXPECT_EQ(valueVectorDouble, retVectorDouble);

    std::vector<string> valueVectorString(2, "test");
    std::vector<string> retVectorString = PreferencesValue(valueVectorString);
    EXPECT_EQ(valueVectorString, retVectorString);

    std::vector<uint8_t> valueVectorUint8(3, 1);
    std::vector<uint8_t> retVectorUint8 = PreferencesValue(valueVectorUint8);
    EXPECT_EQ(valueVectorUint8, retVectorUint8);

    Object object("{\"key1\":\"value1\",\"key2\":222}");
    Object retObjecte = PreferencesValue(object);
    EXPECT_EQ(object, retObjecte);

    std::vector<uint64_t> words = { 1, 2, 3 };
    BigInt bigint(words, 0);
    BigInt retBigint = PreferencesValue(bigint);
    EXPECT_EQ(bigint, retBigint);
}

/**
 * @tc.name: NativePreferencesTest_035
 * @tc.desc: normal testcase of getAllData
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: bty
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_035, TestSize.Level0)
{
    int errCode;
    auto pref1 = PreferencesHelper::GetPreferences("/data/test/test035", errCode);

    std::map<std::string, PreferencesValue> map = { { KEY_TEST_INT_ELEMENT, 1 }, { KEY_TEST_FLOAT_ELEMENT, 0.1 },
        { KEY_TEST_BOOL_ELEMENT, false }, { KEY_TEST_STRING_ELEMENT, "test" } };

    for (auto i : map) {
        pref1->Put(i.first, i.second);
    }

    auto ret = pref1->GetAllData();

    EXPECT_EQ(map.size(), ret.second.size());
    for (auto iter1 = ret.second.begin(); iter1 != ret.second.end(); ++iter1) {
        auto iter2 = map.find(iter1->first);
        EXPECT_NE(iter2, map.end());
        bool isequa = false;
        if (iter1->second == iter2->second) {
            isequa = true;
        }
        EXPECT_TRUE(isequa);
    }
    pref1->Clear();
    ret = pref1->GetAllData();
    EXPECT_EQ(ret.second.size(), 0);
    PreferencesHelper::DeletePreferences("/data/test/test035");
}

/**
 * @tc.name: NativePreferencesTest_036
 * @tc.desc: normal testcase of getAllDatas
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author: Na
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_036, TestSize.Level0)
{
    int errCode;
    auto pref1 = PreferencesHelper::GetPreferences("/data/test/test036", errCode);

    std::map<std::string, PreferencesValue> map = { { KEY_TEST_INT_ELEMENT, 1 }, { KEY_TEST_FLOAT_ELEMENT, 0.1 },
        { KEY_TEST_BOOL_ELEMENT, false }, { KEY_TEST_STRING_ELEMENT, "test" } };

    for (auto i : map) {
        pref1->Put(i.first, i.second);
    }

    auto ret = pref1->GetAllDatas();

    EXPECT_EQ(map.size(), ret.size());
    for (auto iter1 = ret.begin(); iter1 != ret.end(); ++iter1) {
        auto iter2 = map.find(iter1->first);
        EXPECT_NE(iter2, map.end());
        bool isequa = false;
        if (iter1->second == iter2->second) {
            isequa = true;
        }
        EXPECT_TRUE(isequa);
    }
    pref1->Clear();
    ret = pref1->GetAllDatas();
    EXPECT_EQ(ret.size(), 0);
    PreferencesHelper::DeletePreferences("/data/test/test036");
}

/**
 * @tc.name: NativePreferencesTest_037
 * @tc.desc: normal testcase of get value
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author:
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_037, TestSize.Level0)
{
    int errCode;
    auto pref1 = PreferencesHelper::GetPreferences("/data/test/test037", errCode);

    std::map<std::string, PreferencesValue> map = { { KEY_TEST_INT_ELEMENT, 1 }, { KEY_TEST_FLOAT_ELEMENT, 0.1 },
        { KEY_TEST_BOOL_ELEMENT, false }, { KEY_TEST_STRING_ELEMENT, "test" } };

    for (auto i : map) {
        pref1->Put(i.first, i.second);
    }

    PreferencesValue defValue(static_cast<int64_t>(0));
    auto ret = pref1->GetValue("", defValue);
    EXPECT_EQ(static_cast<int64_t>(ret.second), static_cast<int64_t>(defValue));
    auto res = pref1->GetValue("test", defValue);
    EXPECT_EQ(static_cast<int64_t>(res.second), static_cast<int64_t>(defValue));
    res = pref1->GetValue(KEY_TEST_INT_ELEMENT, 0);
    int val = res.second;
    EXPECT_EQ(val, 1);
    pref1->Clear();
    res = pref1->GetValue(KEY_TEST_STRING_ELEMENT, "default");
    std::string value = res.second;
    EXPECT_EQ(value, "default");

    PreferencesHelper::DeletePreferences("/data/test/test037");
}

/**
 * @tc.name: NativePreferencesTest_038
 * @tc.desc: normal testcase of has key
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author:
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_038, TestSize.Level0)
{
    int errCode;
    auto pref1 = PreferencesHelper::GetPreferences("/data/test/test038", errCode);

    std::map<std::string, PreferencesValue> map = { { KEY_TEST_INT_ELEMENT, 1 }, { KEY_TEST_FLOAT_ELEMENT, 0.1 },
        { KEY_TEST_BOOL_ELEMENT, false }, { KEY_TEST_STRING_ELEMENT, "test" } };

    for (auto i : map) {
        pref1->Put(i.first, i.second);
    }

    bool ret = pref1->HasKey(std::string());
    EXPECT_EQ(ret, false);
    ret = pref1->HasKey("test");
    EXPECT_EQ(ret, false);
    ret = pref1->HasKey(KEY_TEST_INT_ELEMENT);
    EXPECT_EQ(ret, true);
    pref1->Clear();
    ret = pref1->HasKey(KEY_TEST_STRING_ELEMENT);
    EXPECT_EQ(ret, false);

    PreferencesHelper::DeletePreferences("/data/test/test038");
}

/**
 * @tc.name: NativePreferencesTest_039
 * @tc.desc: normal testcase of delete key
 * @tc.type: FUNC
 * @tc.require: Na
 * @tc.author:
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_039, TestSize.Level0)
{
    int errCode;
    auto pref1 = PreferencesHelper::GetPreferences("/data/test/test038", errCode);

    std::map<std::string, PreferencesValue> map = { { KEY_TEST_INT_ELEMENT, 1 }, { KEY_TEST_FLOAT_ELEMENT, 0.1 },
        { KEY_TEST_BOOL_ELEMENT, false }, { KEY_TEST_STRING_ELEMENT, "test" } };

    for (auto i : map) {
        pref1->Put(i.first, i.second);
    }

    int ret = pref1->Delete(std::string());
    EXPECT_EQ(ret, E_KEY_EMPTY);
    ret = pref1->Delete("test");
    EXPECT_EQ(ret, E_OK);
    ret = pref1->Delete(KEY_TEST_INT_ELEMENT);
    EXPECT_EQ(ret, E_OK);
    pref1->Clear();
    ret = pref1->Delete(KEY_TEST_STRING_ELEMENT);
    EXPECT_EQ(ret, E_OK);

    PreferencesHelper::DeletePreferences("/data/test/test038");
}

/**
 * @tc.name: NativePreferencesTest_040
 * @tc.desc: normal testcase of report object type
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_040, TestSize.Level0)
{
    std::string path = "/data/test/test040";
    std::string testKey = "testKey";
    int errCode;
    auto pref = PreferencesHelper::GetPreferences(path, errCode);
    EXPECT_NE(pref, nullptr);
    EXPECT_EQ(errCode, E_OK);

    Object object("{\"key1\":\"value1\",\"key2\":222}");
    pref->Put(testKey, "testValue");
    pref->Put(testKey, object);
    pref->Put(testKey, object);
    pref->Put(testKey, "testValue");
    // Waiting for asynchronous task to create file
    sleep(1);
    std::string flagFilePath = PreferencesUtils::MakeFilePath(path, PreferencesUtils::STR_OBJECT_FLAG);
    EXPECT_EQ(Access(flagFilePath), 0);

    PreferencesHelper::RemovePreferencesFromCache(path);
    pref = PreferencesHelper::GetPreferences(path, errCode);
    // There is a flag file created previously
    pref->Put(testKey, object);

    PreferencesHelper::DeletePreferences(path);
    pref = nullptr;
    EXPECT_NE(Access(flagFilePath), 0);
}

/**
 * @tc.name: NativePreferencesTest_041
 * @tc.desc: abnormal testcase of report object type
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesTest, NativePreferencesTest_041, TestSize.Level0)
{
    std::string path = "/invalid/test/test041";
    std::string testKey = "testKey";
    int errCode;
    auto pref = PreferencesHelper::GetPreferences(path, errCode);
    EXPECT_NE(pref, nullptr);
    EXPECT_EQ(errCode, E_OK);

    Object object("{\"key1\":\"value1\",\"key2\":222}");
    pref->Put(testKey, object);
    std::string flagFilePath = PreferencesUtils::MakeFilePath(path, PreferencesUtils::STR_OBJECT_FLAG);
    EXPECT_NE(Access(flagFilePath), 0);

    PreferencesHelper::DeletePreferences(path);
    pref = nullptr;
}

/**
 * @tc.name: PreferencesValueTest_002
 * @tc.desc: normal testcase of PreferencesValue Operator
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesTest, PreferencesValueTest_002, TestSize.Level0)
{
    string valueString = "test_str";
    string retString = PreferencesValue(valueString);
    EXPECT_EQ(valueString, retString);

    string retNull = PreferencesValue(nullptr);
    EXPECT_EQ(retNull, "");
}

/**
 * @tc.name: NativePreferencesRegisterTest
 * @tc.desc: normal testcase of Register Observer and Notify
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesTest, NativePreferencesRegisterTest, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverCounter>();
    ASSERT_NE(pref, nullptr);

    pref->PutString(KEY_TEST_STRING_ELEMENT, "string_value");
    pref->FlushSync();
    auto observerPtr = static_cast<PreferencesObserverCounter *>(observer.get());
    ASSERT_NE(observerPtr, nullptr);
    EXPECT_EQ(observerPtr->notifyTimes, 0);
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT_ELEMENT, 999);
    pref->PutString(KEY_TEST_STRING_ELEMENT, "string_value_2");
    pref->PutBool(KEY_TEST_BOOL_ELEMENT, true);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverCounter *>(observer.get())->notifyTimes, 3);
    int retInt = pref->GetInt(KEY_TEST_INT_ELEMENT, 0);
    EXPECT_EQ(retInt, 999);

    std::string retStr = pref->GetString(KEY_TEST_STRING_ELEMENT, "default");
    EXPECT_EQ(retStr, "string_value_2");

    bool retBool = pref->GetBool(KEY_TEST_BOOL_ELEMENT, false);
    EXPECT_EQ(retBool, true);
    pref->UnRegisterObserver(observer);
    // after UnRegisterObserver, notifyTimes should not change
    pref->PutInt(KEY_TEST_INT_ELEMENT, 99999);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverCounter *>(observer.get())->notifyTimes, 3);
}
} // namespace
