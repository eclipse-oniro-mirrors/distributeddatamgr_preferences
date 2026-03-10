/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <set>

#include "log_print.h"
#include "preferences_errno.h"
#include "preferences_helper.h"
#include "preferences_observer.h"
#include "preferences_utils.h"
#include "preferences_value.h"

using namespace testing::ext;
using namespace OHOS::NativePreferences;

namespace {
const std::string KEY_TEST_INT = "key_test_int_v2";
const std::string KEY_TEST_LONG = "key_test_long_v2";
const std::string KEY_TEST_FLOAT = "key_test_float_v2";
const std::string KEY_TEST_DOUBLE = "key_test_double_v2";
const std::string KEY_TEST_BOOL = "key_test_bool_v2";
const std::string KEY_TEST_STRING = "key_test_string_v2";
const std::string KEY_TEST_STRING_ARRAY = "key_test_string_array_v2";
const std::string KEY_TEST_BOOL_ARRAY = "key_test_bool_array_v2";
const std::string KEY_TEST_DOUBLE_ARRAY = "key_test_double_array_v2";
const std::string KEY_TEST_UINT8_ARRAY = "key_test_uint8_array_v2";
const std::string KEY_TEST_OBJECT = "key_test_object_v2";
const std::string KEY_TEST_BIGINT = "key_test_bigint_v2";

class PreferencesComprehensiveTestV2 : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static std::shared_ptr<Preferences> pref;
};

std::shared_ptr<Preferences> PreferencesComprehensiveTestV2::pref = nullptr;

void PreferencesComprehensiveTestV2::SetUpTestCase(void)
{
}

void PreferencesComprehensiveTestV2::TearDownTestCase(void)
{
}

void PreferencesComprehensiveTestV2::SetUp(void)
{
    int errCode = E_OK;
    pref = PreferencesHelper::GetPreferences("/data/test_comprehensive_v2", errCode);
    EXPECT_EQ(errCode, E_OK);
}

void PreferencesComprehensiveTestV2::TearDown(void)
{
    pref = nullptr;
    int ret = PreferencesHelper::DeletePreferences("/data/test_comprehensive_v2");
    EXPECT_EQ(ret, E_OK);
}

class PreferencesObserverV2 : public PreferencesObserver {
public:
    virtual ~PreferencesObserverV2();
    void OnChange(const std::string &key) override;
    void OnChange(const std::map<std::string, OHOS::NativePreferences::PreferencesValue> &records) override;

    std::atomic_int notifyTimes;
};

PreferencesObserverV2::~PreferencesObserverV2()
{
}

void PreferencesObserverV2::OnChange(const std::string &key)
{
    notifyTimes++;
}

void PreferencesObserverV2::OnChange(
    const std::map<std::string, OHOS::NativePreferences::PreferencesValue> &records)
{
    notifyTimes += records.size();
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutInt_V2_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    int ret = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret, 100);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutInt_V2_002, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 999);
    pref->FlushSync();
    int ret = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret, 999);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutInt_V2_003, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, -999);
    pref->FlushSync();
    int ret = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret, -999);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutInt_V2_004, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 500);
    pref->FlushSync();
    int ret = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret, 500);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutInt_V2_005, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, -500);
    pref->FlushSync();
    int ret = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret, -500);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutLong_V2_001, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, 10000L);
    pref->FlushSync();
    int64_t ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, 10000L);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutLong_V2_002, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, -10000L);
    pref->FlushSync();
    int64_t ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, -10000L);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutLong_V2_003, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, 5000L);
    pref->FlushSync();
    int64_t ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, 5000L);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutLong_V2_004, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, -5000L);
    pref->FlushSync();
    int64_t ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, -5000L);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutLong_V2_005, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, 2500L);
    pref->FlushSync();
    int64_t ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, 2500L);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutFloat_V2_001, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, 100.25f);
    pref->FlushSync();
    float ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, 100.25f);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutFloat_V2_002, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, -100.25f);
    pref->FlushSync();
    float ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, -100.25f);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutFloat_V2_003, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, 250.5f);
    pref->FlushSync();
    float ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, 250.5f);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutFloat_V2_004, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, -250.5f);
    pref->FlushSync();
    float ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, -250.5f);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutFloat_V2_005, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, 125.75f);
    pref->FlushSync();
    float ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, 125.75f);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutDouble_V2_001, TestSize.Level0)
{
    pref->PutDouble(KEY_TEST_DOUBLE, 1000.125);
    pref->FlushSync();
    double ret = pref->GetDouble(KEY_TEST_DOUBLE, 0.0);
    EXPECT_EQ(ret, 1000.125);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutDouble_V2_002, TestSize.Level0)
{
    pref->PutDouble(KEY_TEST_DOUBLE, -1000.125);
    pref->FlushSync();
    double ret = pref->GetDouble(KEY_TEST_DOUBLE, 0.0);
    EXPECT_EQ(ret, -1000.125);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutDouble_V2_003, TestSize.Level0)
{
    pref->PutDouble(KEY_TEST_DOUBLE, 2500.25);
    pref->FlushSync();
    double ret = pref->GetDouble(KEY_TEST_DOUBLE, 0.0);
    EXPECT_EQ(ret, 2500.25);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutDouble_V2_004, TestSize.Level0)
{
    pref->PutDouble(KEY_TEST_DOUBLE, -2500.25);
    pref->FlushSync();
    double ret = pref->GetDouble(KEY_TEST_DOUBLE, 0.0);
    EXPECT_EQ(ret, -2500.25);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutDouble_V2_005, TestSize.Level0)
{
    pref->PutDouble(KEY_TEST_DOUBLE, 1250.375);
    pref->FlushSync();
    double ret = pref->GetDouble(KEY_TEST_DOUBLE, 0.0);
    EXPECT_EQ(ret, 1250.375);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutBool_V2_001, TestSize.Level0)
{
    pref->PutBool(KEY_TEST_BOOL, true);
    pref->FlushSync();
    bool ret = pref->GetBool(KEY_TEST_BOOL, false);
    EXPECT_EQ(ret, true);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutBool_V2_002, TestSize.Level0)
{
    pref->PutBool(KEY_TEST_BOOL, false);
    pref->FlushSync();
    bool ret = pref->GetBool(KEY_TEST_BOOL, true);
    EXPECT_EQ(ret, false);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutString_V2_001, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "test_string_v2");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "test_string_v2");
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutString_V2_002, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "hello_world_v2");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "hello_world_v2");
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutString_V2_003, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "test_data_v2");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "test_data_v2");
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutString_V2_004, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "preferences_test_v2");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "preferences_test_v2");
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutString_V2_005, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "comprehensive_test_v2");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "comprehensive_test_v2");
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutStringArray_V2_001, TestSize.Level0)
{
    std::vector<std::string> array = { "one", "two", "three" };
    pref->Put(KEY_TEST_STRING_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_STRING_ARRAY, defValue);
    EXPECT_EQ(ret.IsStringArray(), true);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutStringArray_V2_002, TestSize.Level0)
{
    std::vector<std::string> array = { "alpha", "beta", "gamma", "delta" };
    pref->Put(KEY_TEST_STRING_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_STRING_ARRAY, defValue);
    EXPECT_EQ(ret.IsStringArray(), true);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutStringArray_V2_003, TestSize.Level0)
{
    std::vector<std::string> array = { "first", "second", "third", "fourth", "fifth" };
    pref->Put(KEY_TEST_STRING_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_STRING_ARRAY, defValue);
    EXPECT_EQ(ret.IsStringArray(), true);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutStringArray_V2_004, TestSize.Level0)
{
    std::vector<std::string> array = { "red", "green", "blue", "yellow", "purple" };
    pref->Put(KEY_TEST_STRING_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_STRING_ARRAY, defValue);
    EXPECT_EQ(ret.IsStringArray(), true);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutStringArray_V2_005, TestSize.Level0)
{
    std::vector<std::string> array = { "spring", "summer", "autumn", "winter" };
    pref->Put(KEY_TEST_STRING_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_STRING_ARRAY, defValue);
    EXPECT_EQ(ret.IsStringArray(), true);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutBoolArray_V2_001, TestSize.Level0)
{
    std::vector<bool> array = { false, true, false, true };
    pref->Put(KEY_TEST_BOOL_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_BOOL_ARRAY, defValue);
    EXPECT_EQ(ret.IsBoolArray(), true);
    EXPECT_EQ(static_cast<std::vector<bool>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutBoolArray_V2_002, TestSize.Level0)
{
    std::vector<bool> array = { false, false, false, false, false };
    pref->Put(KEY_TEST_BOOL_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_BOOL_ARRAY, defValue);
    EXPECT_EQ(ret.IsBoolArray(), true);
    EXPECT_EQ(static_cast<std::vector<bool>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutBoolArray_V2_003, TestSize.Level0)
{
    std::vector<bool> array = { true, true, true, true, true, true };
    pref->Put(KEY_TEST_BOOL_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_BOOL_ARRAY, defValue);
    EXPECT_EQ(ret.IsBoolArray(), true);
    EXPECT_EQ(static_cast<std::vector<bool>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutBoolArray_V2_004, TestSize.Level0)
{
    std::vector<bool> array = { true, false, true, false, true, false, true };
    pref->Put(KEY_TEST_BOOL_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_BOOL_ARRAY, defValue);
    EXPECT_EQ(ret.IsBoolArray(), true);
    EXPECT_EQ(static_cast<std::vector<bool>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutBoolArray_V2_005, TestSize.Level0)
{
    std::vector<bool> array = { false, true, false };
    pref->Put(KEY_TEST_BOOL_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_BOOL_ARRAY, defValue);
    EXPECT_EQ(ret.IsBoolArray(), true);
    EXPECT_EQ(static_cast<std::vector<bool>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutDoubleArray_V2_001, TestSize.Level0)
{
    std::vector<double> array = { 10.1, 20.2, 30.3 };
    pref->Put(KEY_TEST_DOUBLE_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_DOUBLE_ARRAY, defValue);
    EXPECT_EQ(ret.IsDoubleArray(), true);
    EXPECT_EQ(static_cast<std::vector<double>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutDoubleArray_V2_002, TestSize.Level0)
{
    std::vector<double> array = { 100.5, 200.5, 300.5, 400.5 };
    pref->Put(KEY_TEST_DOUBLE_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_DOUBLE_ARRAY, defValue);
    EXPECT_EQ(ret.IsDoubleArray(), true);
    EXPECT_EQ(static_cast<std::vector<double>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutDoubleArray_V2_003, TestSize.Level0)
{
    std::vector<double> array = { -10.5, -20.5, -30.5, -40.5, -50.5 };
    pref->Put(KEY_TEST_DOUBLE_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_DOUBLE_ARRAY, defValue);
    EXPECT_EQ(ret.IsDoubleArray(), true);
    EXPECT_EQ(static_cast<std::vector<double>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutDoubleArray_V2_004, TestSize.Level0)
{
    std::vector<double> array = { 1.5, 2.5, 3.5, 4.5, 5.5, 6.5 };
    pref->Put(KEY_TEST_DOUBLE_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_DOUBLE_ARRAY, defValue);
    EXPECT_EQ(ret.IsDoubleArray(), true);
    EXPECT_EQ(static_cast<std::vector<double>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutDoubleArray_V2_005, TestSize.Level0)
{
    std::vector<double> array = { 0.5, 1.5, 2.5 };
    pref->Put(KEY_TEST_DOUBLE_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_DOUBLE_ARRAY, defValue);
    EXPECT_EQ(ret.IsDoubleArray(), true);
    EXPECT_EQ(static_cast<std::vector<double>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutUint8Array_V2_001, TestSize.Level0)
{
    std::vector<uint8_t> array = { 10, 20, 30, 40 };
    pref->Put(KEY_TEST_UINT8_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_UINT8_ARRAY, defValue);
    EXPECT_EQ(ret.IsUint8Array(), true);
    EXPECT_EQ(static_cast<std::vector<uint8_t>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutUint8Array_V2_002, TestSize.Level0)
{
    std::vector<uint8_t> array = { 5, 10, 15, 20, 25 };
    pref->Put(KEY_TEST_UINT8_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_UINT8_ARRAY, defValue);
    EXPECT_EQ(ret.IsUint8Array(), true);
    EXPECT_EQ(static_cast<std::vector<uint8_t>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutUint8Array_V2_003, TestSize.Level0)
{
    std::vector<uint8_t> array = { 100, 150, 200, 250 };
    pref->Put(KEY_TEST_UINT8_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_UINT8_ARRAY, defValue);
    EXPECT_EQ(ret.IsUint8Array(), true);
    EXPECT_EQ(static_cast<std::vector<uint8_t>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutUint8Array_V2_004, TestSize.Level0)
{
    std::vector<uint8_t> array = { 1, 2, 3, 4, 5, 6, 7 };
    pref->Put(KEY_TEST_UINT8_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_UINT8_ARRAY, defValue);
    EXPECT_EQ(ret.IsUint8Array(), true);
    EXPECT_EQ(static_cast<std::vector<uint8_t>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutUint8Array_V2_005, TestSize.Level0)
{
    std::vector<uint8_t> array = { 50, 100, 150 };
    pref->Put(KEY_TEST_UINT8_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_UINT8_ARRAY, defValue);
    EXPECT_EQ(ret.IsUint8Array(), true);
    EXPECT_EQ(static_cast<std::vector<uint8_t>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutBigInt_V2_001, TestSize.Level0)
{
    std::vector<uint64_t> words = { 10, 20, 30 };
    BigInt bigint(words, 0);
    pref->Put(KEY_TEST_BIGINT, bigint);
    pref->FlushSync();
    BigInt ret = pref->Get(KEY_TEST_BIGINT, BigInt());
    EXPECT_EQ(ret, bigint);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutBigInt_V2_002, TestSize.Level0)
{
    std::vector<uint64_t> words = { 100, 200 };
    BigInt bigint(words, 0);
    pref->Put(KEY_TEST_BIGINT, bigint);
    pref->FlushSync();
    BigInt ret = pref->Get(KEY_TEST_BIGINT, BigInt());
    EXPECT_EQ(ret, bigint);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutBigInt_V2_003, TestSize.Level0)
{
    std::vector<uint64_t> words = { 50, 60, 70, 80 };
    BigInt bigint(words, 0);
    pref->Put(KEY_TEST_BIGINT, bigint);
    pref->FlushSync();
    BigInt ret = pref->Get(KEY_TEST_BIGINT, BigInt());
    EXPECT_EQ(ret, bigint);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutBigInt_V2_004, TestSize.Level0)
{
    std::vector<uint64_t> words = { 5, 10, 15, 20, 25 };
    BigInt bigint(words, 0);
    pref->Put(KEY_TEST_BIGINT, bigint);
    pref->FlushSync();
    BigInt ret = pref->Get(KEY_TEST_BIGINT, BigInt());
    EXPECT_EQ(ret, bigint);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutBigInt_V2_005, TestSize.Level0)
{
    std::vector<uint64_t> words = { 1, 2, 3, 4, 5, 6 };
    BigInt bigint(words, 1);
    pref->Put(KEY_TEST_BIGINT, bigint);
    pref->FlushSync();
    BigInt ret = pref->Get(KEY_TEST_BIGINT, BigInt());
    EXPECT_EQ(ret, bigint);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutObject_V2_001, TestSize.Level0)
{
    Object object("{\"name\":\"test\",\"value\":100}");
    pref->Put(KEY_TEST_OBJECT, object);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_OBJECT, defValue);
    EXPECT_EQ(static_cast<Object>(ret), object);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutObject_V2_002, TestSize.Level0)
{
    Object object("{\"x\":10,\"y\":20,\"z\":30}");
    pref->Put(KEY_TEST_OBJECT, object);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_OBJECT, defValue);
    EXPECT_EQ(static_cast<Object>(ret), object);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutObject_V2_003, TestSize.Level0)
{
    Object object("{\"status\":\"active\",\"count\":5}");
    pref->Put(KEY_TEST_OBJECT, object);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_OBJECT, defValue);
    EXPECT_EQ(static_cast<Object>(ret), object);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutObject_V2_004, TestSize.Level0)
{
    Object object("{\"level\":\"high\",\"priority\":1}");
    pref->Put(KEY_TEST_OBJECT, object);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_OBJECT, defValue);
    EXPECT_EQ(static_cast<Object>(ret), object);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutObject_V2_005, TestSize.Level0)
{
    Object object("{\"mode\":\"test\",\"enabled\":true}");
    pref->Put(KEY_TEST_OBJECT, object);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_OBJECT, defValue);
    EXPECT_EQ(static_cast<Object>(ret), object);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_HasKey_V2_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    bool ret = pref->HasKey(KEY_TEST_INT);
    EXPECT_EQ(ret, true);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_HasKey_V2_002, TestSize.Level0)
{
    bool ret = pref->HasKey(KEY_TEST_INT);
    EXPECT_EQ(ret, false);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_HasKey_V2_003, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "test_v2");
    pref->FlushSync();
    bool ret = pref->HasKey(KEY_TEST_STRING);
    EXPECT_EQ(ret, true);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_HasKey_V2_004, TestSize.Level0)
{
    pref->PutBool(KEY_TEST_BOOL, false);
    pref->FlushSync();
    bool ret = pref->HasKey(KEY_TEST_BOOL);
    EXPECT_EQ(ret, true);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_HasKey_V2_005, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, 2.5f);
    pref->FlushSync();
    bool ret = pref->HasKey(KEY_TEST_FLOAT);
    EXPECT_EQ(ret, true);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Delete_V2_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    int ret = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret, 100);
    pref->Delete(KEY_TEST_INT);
    pref->FlushSync();
    ret = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Delete_V2_002, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "test_v2");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "test_v2");
    pref->Delete(KEY_TEST_STRING);
    pref->FlushSync();
    ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "default");
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Delete_V2_003, TestSize.Level0)
{
    pref->PutBool(KEY_TEST_BOOL, true);
    pref->FlushSync();
    bool ret = pref->GetBool(KEY_TEST_BOOL, false);
    EXPECT_EQ(ret, true);
    pref->Delete(KEY_TEST_BOOL);
    pref->FlushSync();
    ret = pref->GetBool(KEY_TEST_BOOL, false);
    EXPECT_EQ(ret, false);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Delete_V2_004, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, 10000L);
    pref->FlushSync();
    int64_t ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, 10000L);
    pref->Delete(KEY_TEST_LONG);
    pref->FlushSync();
    ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, 0L);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Delete_V2_005, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, 2.5f);
    pref->FlushSync();
    float ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, 2.5f);
    pref->Delete(KEY_TEST_FLOAT);
    pref->FlushSync();
    ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, 0.0f);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Clear_V2_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutString(KEY_TEST_STRING, "test_v2");
    pref->PutBool(KEY_TEST_BOOL, false);
    pref->FlushSync();
    EXPECT_EQ(pref->HasKey(KEY_TEST_INT), true);
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING), true);
    EXPECT_EQ(pref->HasKey(KEY_TEST_BOOL), true);
    pref->Clear();
    pref->FlushSync();
    EXPECT_EQ(pref->HasKey(KEY_TEST_INT), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_BOOL), false);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Clear_V2_002, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, 10000L);
    pref->PutFloat(KEY_TEST_FLOAT, 2.5f);
    pref->PutDouble(KEY_TEST_DOUBLE, 3.5);
    pref->FlushSync();
    pref->Clear();
    pref->FlushSync();
    EXPECT_EQ(pref->HasKey(KEY_TEST_LONG), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_FLOAT), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_DOUBLE), false);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Clear_V2_003, TestSize.Level0)
{
    pref->Clear();
    pref->FlushSync();
    EXPECT_EQ(pref->HasKey(KEY_TEST_INT), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING), false);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_RegisterObserver_V2_001, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV2>();
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV2 *>(observer.get())->notifyTimes, 1);
    pref->UnRegisterObserver(observer);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_RegisterObserver_V2_002, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV2>();
    pref->RegisterObserver(observer);
    pref->PutString(KEY_TEST_STRING, "test_v2");
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV2 *>(observer.get())->notifyTimes, 2);
    pref->UnRegisterObserver(observer);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_RegisterObserver_V2_003, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV2>();
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV2 *>(observer.get())->notifyTimes, 1);
    pref->PutInt(KEY_TEST_INT, 200);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV2 *>(observer.get())->notifyTimes, 2);
    pref->UnRegisterObserver(observer);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_RegisterObserver_V2_004, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV2>();
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutString(KEY_TEST_STRING, "test_v2");
    pref->PutBool(KEY_TEST_BOOL, false);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV2 *>(observer.get())->notifyTimes, 3);
    pref->UnRegisterObserver(observer);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_RegisterObserver_V2_005, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV2>();
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV2 *>(observer.get())->notifyTimes, 1);
    pref->UnRegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 200);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV2 *>(observer.get())->notifyTimes, 1);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_GetAll_V2_001, TestSize.Level0)
{
    std::map<std::string, PreferencesValue> data = {
        { KEY_TEST_INT, 100 },
        { KEY_TEST_STRING, "test_v2" },
        { KEY_TEST_BOOL, false }
    };
    for (auto &item : data) {
        pref->Put(item.first, item.second);
    }
    pref->FlushSync();
    auto ret = pref->GetAll();
    EXPECT_EQ(ret.size(), data.size());
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_GetAll_V2_002, TestSize.Level0)
{
    auto ret = pref->GetAll();
    EXPECT_EQ(ret.size(), 0);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_GetAll_V2_003, TestSize.Level0)
{
    std::map<std::string, PreferencesValue> data = {
        { KEY_TEST_INT, 100 },
        { KEY_TEST_LONG, 10000LL },
        { KEY_TEST_FLOAT, 2.5f },
        { KEY_TEST_DOUBLE, 3.5 }
    };
    for (auto &item : data) {
        pref->Put(item.first, item.second);
    }
    pref->FlushSync();
    auto ret = pref->GetAll();
    EXPECT_EQ(ret.size(), data.size());
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_GetAll_V2_004, TestSize.Level0)
{
    std::map<std::string, PreferencesValue> data = {
        { KEY_TEST_STRING, "test1_v2" },
        { KEY_TEST_STRING + "_2", "test2_v2" },
        { KEY_TEST_STRING + "_3", "test3_v2" }
    };
    for (auto &item : data) {
        pref->Put(item.first, item.second);
    }
    pref->FlushSync();
    auto ret = pref->GetAll();
    EXPECT_EQ(ret.size(), data.size());
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_GetAll_V2_005, TestSize.Level0)
{
    std::map<std::string, PreferencesValue> data = {
        { KEY_TEST_BOOL, false },
        { KEY_TEST_BOOL + "_2", true },
        { KEY_TEST_BOOL + "_3", false }
    };
    for (auto &item : data) {
        pref->Put(item.first, item.second);
    }
    pref->FlushSync();
    auto ret = pref->GetAll();
    EXPECT_EQ(ret.size(), data.size());
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutMultiple_V2_001, TestSize.Level0)
{
    for (int i = 0; i < 15; i++) {
        pref->PutInt(KEY_TEST_INT + "_" + std::to_string(i), i * 10);
    }
    pref->FlushSync();
    for (int i = 0; i < 15; i++) {
        int ret = pref->GetInt(KEY_TEST_INT + "_" + std::to_string(i), -1);
        EXPECT_EQ(ret, i * 10);
    }
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutMultiple_V2_002, TestSize.Level0)
{
    for (int i = 0; i < 25; i++) {
        pref->PutString(KEY_TEST_STRING + "_" + std::to_string(i), "string_v2_" + std::to_string(i));
    }
    pref->FlushSync();
    for (int i = 0; i < 25; i++) {
        std::string ret = pref->GetString(KEY_TEST_STRING + "_" + std::to_string(i), "");
        EXPECT_EQ(ret, "string_v2_" + std::to_string(i));
    }
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutMultiple_V2_003, TestSize.Level0)
{
    for (int i = 0; i < 20; i++) {
        pref->PutLong(KEY_TEST_LONG + "_" + std::to_string(i), i * 10000L);
    }
    pref->FlushSync();
    for (int i = 0; i < 20; i++) {
        int64_t ret = pref->GetLong(KEY_TEST_LONG + "_" + std::to_string(i), 0L);
        EXPECT_EQ(ret, i * 10000L);
    }
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutMultiple_V2_004, TestSize.Level0)
{
    for (int i = 0; i < 30; i++) {
        pref->PutBool(KEY_TEST_BOOL + "_" + std::to_string(i), i % 2 == 0);
    }
    pref->FlushSync();
    for (int i = 0; i < 30; i++) {
        bool ret = pref->GetBool(KEY_TEST_BOOL + "_" + std::to_string(i), false);
        EXPECT_EQ(ret, i % 2 == 0);
    }
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_PutMultiple_V2_005, TestSize.Level0)
{
    for (int i = 0; i < 35; i++) {
        pref->PutFloat(KEY_TEST_FLOAT + "_" + std::to_string(i), i * 2.5f);
    }
    pref->FlushSync();
    for (int i = 0; i < 35; i++) {
        float ret = pref->GetFloat(KEY_TEST_FLOAT + "_" + std::to_string(i), 0.0f);
        EXPECT_EQ(ret, i * 2.5f);
    }
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Update_V2_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    int ret = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret, 100);
    pref->PutInt(KEY_TEST_INT, 200);
    pref->FlushSync();
    ret = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret, 200);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Update_V2_002, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "test1_v2");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "");
    EXPECT_EQ(ret, "test1_v2");
    pref->PutString(KEY_TEST_STRING, "test2_v2");
    pref->FlushSync();
    ret = pref->GetString(KEY_TEST_STRING, "");
    EXPECT_EQ(ret, "test2_v2");
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Update_V2_003, TestSize.Level0)
{
    pref->PutBool(KEY_TEST_BOOL, true);
    pref->FlushSync();
    bool ret = pref->GetBool(KEY_TEST_BOOL, false);
    EXPECT_EQ(ret, true);
    pref->PutBool(KEY_TEST_BOOL, false);
    pref->FlushSync();
    ret = pref->GetBool(KEY_TEST_BOOL, true);
    EXPECT_EQ(ret, false);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Update_V2_004, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, 10000L);
    pref->FlushSync();
    int64_t ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, 10000L);
    pref->PutLong(KEY_TEST_LONG, 20000L);
    pref->FlushSync();
    ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, 20000L);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Update_V2_005, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, 2.5f);
    pref->FlushSync();
    float ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, 2.5f);
    pref->PutFloat(KEY_TEST_FLOAT, 5.0f);
    pref->FlushSync();
    ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, 5.0f);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_MixedTypes_V2_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 200);
    pref->PutString(KEY_TEST_STRING, "test_v2");
    pref->PutBool(KEY_TEST_BOOL, false);
    pref->PutLong(KEY_TEST_LONG, 10000L);
    pref->PutFloat(KEY_TEST_FLOAT, 2.5f);
    pref->FlushSync();
    EXPECT_EQ(pref->GetInt(KEY_TEST_INT, 0), 200);
    EXPECT_EQ(pref->GetString(KEY_TEST_STRING, ""), "test_v2");
    EXPECT_EQ(pref->GetBool(KEY_TEST_BOOL, true), false);
    EXPECT_EQ(pref->GetLong(KEY_TEST_LONG, 0L), 10000L);
    EXPECT_EQ(pref->GetFloat(KEY_TEST_FLOAT, 0.0f), 2.5f);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_MixedTypes_V2_002, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 300);
    pref->PutString(KEY_TEST_STRING, "hello_v2");
    pref->PutBool(KEY_TEST_BOOL, true);
    pref->PutLong(KEY_TEST_LONG, 20000L);
    pref->PutFloat(KEY_TEST_FLOAT, 5.0f);
    pref->PutDouble(KEY_TEST_DOUBLE, 10.5);
    pref->FlushSync();
    EXPECT_EQ(pref->GetInt(KEY_TEST_INT, 0), 300);
    EXPECT_EQ(pref->GetString(KEY_TEST_STRING, ""), "hello_v2");
    EXPECT_EQ(pref->GetBool(KEY_TEST_BOOL, false), true);
    EXPECT_EQ(pref->GetLong(KEY_TEST_LONG, 0L), 20000L);
    EXPECT_EQ(pref->GetFloat(KEY_TEST_FLOAT, 0.0f), 5.0f);
    EXPECT_EQ(pref->GetDouble(KEY_TEST_DOUBLE, 0.0), 10.5);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_MixedTypes_V2_003, TestSize.Level0)
{
    std::vector<std::string> strArray = { "x", "y", "z" };
    std::vector<bool> boolArray = { false, true, false };
    std::vector<double> doubleArray = { 10.5, 20.5, 30.5 };
    pref->Put(KEY_TEST_STRING_ARRAY, strArray);
    pref->Put(KEY_TEST_BOOL_ARRAY, boolArray);
    pref->Put(KEY_TEST_DOUBLE_ARRAY, doubleArray);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue strRet = pref->Get(KEY_TEST_STRING_ARRAY, defValue);
    PreferencesValue boolRet = pref->Get(KEY_TEST_BOOL_ARRAY, defValue);
    PreferencesValue doubleRet = pref->Get(KEY_TEST_DOUBLE_ARRAY, defValue);
    EXPECT_EQ(strRet.IsStringArray(), true);
    EXPECT_EQ(boolRet.IsBoolArray(), true);
    EXPECT_EQ(doubleRet.IsDoubleArray(), true);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_MixedTypes_V2_004, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 400);
    pref->PutString(KEY_TEST_STRING, "world_v2");
    pref->PutBool(KEY_TEST_BOOL, false);
    pref->PutDouble(KEY_TEST_DOUBLE, 20.5);
    pref->FlushSync();
    auto all = pref->GetAll();
    EXPECT_EQ(all.size(), 4);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_MixedTypes_V2_005, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 500);
    pref->PutString(KEY_TEST_STRING, "data_v2");
    pref->FlushSync();
    pref->Clear();
    pref->PutLong(KEY_TEST_LONG, 50000L);
    pref->PutFloat(KEY_TEST_FLOAT, 10.0f);
    pref->FlushSync();
    EXPECT_EQ(pref->HasKey(KEY_TEST_INT), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_LONG), true);
    EXPECT_EQ(pref->HasKey(KEY_TEST_FLOAT), true);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_EdgeCases_V2_001, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "");
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_EdgeCases_V2_002, TestSize.Level0)
{
    std::string longString(2000, 'b');
    pref->PutString(KEY_TEST_STRING, longString);
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "");
    EXPECT_EQ(ret, longString);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_EdgeCases_V2_003, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 0);
    pref->PutLong(KEY_TEST_LONG, 0L);
    pref->PutFloat(KEY_TEST_FLOAT, 0.0f);
    pref->PutDouble(KEY_TEST_DOUBLE, 0.0);
    pref->FlushSync();
    EXPECT_EQ(pref->GetInt(KEY_TEST_INT, 1), 0);
    EXPECT_EQ(pref->GetLong(KEY_TEST_LONG, 1L), 0L);
    EXPECT_EQ(pref->GetFloat(KEY_TEST_FLOAT, 1.0f), 0.0f);
    EXPECT_EQ(pref->GetDouble(KEY_TEST_DOUBLE, 1.0), 0.0);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_EdgeCases_V2_004, TestSize.Level0)
{
    pref->PutBool(KEY_TEST_BOOL, false);
    pref->FlushSync();
    bool ret = pref->GetBool(KEY_TEST_BOOL, true);
    EXPECT_EQ(ret, false);
    ret = pref->GetBool(KEY_TEST_BOOL, false);
    EXPECT_EQ(ret, false);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_EdgeCases_V2_005, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, -1);
    pref->FlushSync();
    int ret = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret, -1);
    pref->PutInt(KEY_TEST_INT, 1);
    pref->FlushSync();
    ret = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret, 1);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_DeleteMultiple_V2_001, TestSize.Level0)
{
    for (int i = 0; i < 15; i++) {
        pref->PutInt(KEY_TEST_INT + "_" + std::to_string(i), i * 10);
    }
    pref->FlushSync();
    for (int i = 0; i < 15; i++) {
        pref->Delete(KEY_TEST_INT + "_" + std::to_string(i));
    }
    pref->FlushSync();
    for (int i = 0; i < 15; i++) {
        int ret = pref->GetInt(KEY_TEST_INT + "_" + std::to_string(i), -1);
        EXPECT_EQ(ret, -1);
    }
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_DeleteMultiple_V2_002, TestSize.Level0)
{
    for (int i = 0; i < 10; i++) {
        pref->PutString(KEY_TEST_STRING + "_" + std::to_string(i), "test_v2_" + std::to_string(i));
    }
    pref->FlushSync();
    pref->Delete(KEY_TEST_STRING + "_0");
    pref->Delete(KEY_TEST_STRING + "_3");
    pref->Delete(KEY_TEST_STRING + "_6");
    pref->Delete(KEY_TEST_STRING + "_9");
    pref->FlushSync();
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING + "_0"), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING + "_1"), true);
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING + "_3"), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING + "_6"), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING + "_9"), false);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_DeleteMultiple_V2_003, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutString(KEY_TEST_STRING, "test_v2");
    pref->PutBool(KEY_TEST_BOOL, false);
    pref->FlushSync();
    EXPECT_EQ(pref->GetAll().size(), 3);
    pref->Clear();
    pref->FlushSync();
    EXPECT_EQ(pref->GetAll().size(), 0);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_ObserverChanges_V2_001, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV2>();
    pref->RegisterObserver(observer);
    for (int i = 0; i < 15; i++) {
        pref->PutInt(KEY_TEST_INT, i * 10);
        pref->FlushSync();
    }
    EXPECT_EQ(static_cast<PreferencesObserverV2 *>(observer.get())->notifyTimes, 15);
    pref->UnRegisterObserver(observer);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_ObserverChanges_V2_002, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV2>();
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutString(KEY_TEST_STRING, "test_v2");
    pref->PutBool(KEY_TEST_BOOL, false);
    pref->PutLong(KEY_TEST_LONG, 10000L);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV2 *>(observer.get())->notifyTimes, 4);
    pref->UnRegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 200);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV2 *>(observer.get())->notifyTimes, 4);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_ObserverChanges_V2_003, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV2>();
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV2 *>(observer.get())->notifyTimes, 1);
    pref->UnRegisterObserver(observer);
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 200);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV2 *>(observer.get())->notifyTimes, 2);
    pref->UnRegisterObserver(observer);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_ObserverChanges_V2_004, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer1 = std::make_shared<PreferencesObserverV2>();
    std::shared_ptr<PreferencesObserver> observer2 = std::make_shared<PreferencesObserverV2>();
    pref->RegisterObserver(observer1);
    pref->RegisterObserver(observer2);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV2 *>(observer1.get())->notifyTimes, 1);
    EXPECT_EQ(static_cast<PreferencesObserverV2 *>(observer2.get())->notifyTimes, 1);
    pref->UnRegisterObserver(observer1);
    pref->UnRegisterObserver(observer2);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_ObserverChanges_V2_005, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV2>();
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    pref->Delete(KEY_TEST_INT);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV2 *>(observer.get())->notifyTimes, 2);
    pref->UnRegisterObserver(observer);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_ArrayOperations_V2_001, TestSize.Level0)
{
    std::vector<std::string> array1 = { "a", "b", "c" };
    std::vector<std::string> array2 = { "d", "e", "f" };
    pref->Put(KEY_TEST_STRING_ARRAY, array1);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_STRING_ARRAY, defValue);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret), array1);
    pref->Put(KEY_TEST_STRING_ARRAY, array2);
    pref->FlushSync();
    ret = pref->Get(KEY_TEST_STRING_ARRAY, defValue);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret), array2);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_ArrayOperations_V2_002, TestSize.Level0)
{
    std::vector<bool> array = { false, true, false, true, false };
    pref->Put(KEY_TEST_BOOL_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_BOOL_ARRAY, defValue);
    EXPECT_EQ(static_cast<std::vector<bool>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_ArrayOperations_V2_003, TestSize.Level0)
{
    std::vector<double> array = { 10.5, 20.5, 30.5, 40.5, 50.5 };
    pref->Put(KEY_TEST_DOUBLE_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_DOUBLE_ARRAY, defValue);
    EXPECT_EQ(static_cast<std::vector<double>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_ArrayOperations_V2_004, TestSize.Level0)
{
    std::vector<uint8_t> array = { 10, 20, 30, 40, 50, 60 };
    pref->Put(KEY_TEST_UINT8_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_UINT8_ARRAY, defValue);
    EXPECT_EQ(static_cast<std::vector<uint8_t>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_ArrayOperations_V2_005, TestSize.Level0)
{
    std::vector<std::string> array1 = { "x", "y", "z" };
    std::vector<std::string> array2 = { "p", "q", "r" };
    pref->Put(KEY_TEST_STRING_ARRAY, array1);
    pref->Put(KEY_TEST_STRING_ARRAY + "_2", array2);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret1 = pref->Get(KEY_TEST_STRING_ARRAY, defValue);
    PreferencesValue ret2 = pref->Get(KEY_TEST_STRING_ARRAY + "_2", defValue);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret1), array1);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret2), array2);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_GetAllData_V2_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutString(KEY_TEST_STRING, "test_v2");
    pref->FlushSync();
    auto ret = pref->GetAllData();
    EXPECT_EQ(ret.second.size(), 2);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_GetAllData_V2_002, TestSize.Level0)
{
    auto ret = pref->GetAllData();
    EXPECT_EQ(ret.second.size(), 0);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_GetAllData_V2_003, TestSize.Level0)
{
    for (int i = 0; i < 10; i++) {
        pref->PutInt(KEY_TEST_INT + "_" + std::to_string(i), i * 10);
    }
    pref->FlushSync();
    auto ret = pref->GetAllData();
    EXPECT_EQ(ret.second.size(), 10);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_GetAllData_V2_004, TestSize.Level0)
{
    std::vector<std::string> array = { "x", "y", "z" };
    pref->Put(KEY_TEST_STRING_ARRAY, array);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutString(KEY_TEST_STRING, "test_v2");
    pref->FlushSync();
    auto ret = pref->GetAllData();
    EXPECT_EQ(ret.second.size(), 3);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_GetAllData_V2_005, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutString(KEY_TEST_STRING, "test_v2");
    pref->FlushSync();
    pref->Clear();
    pref->FlushSync();
    auto ret = pref->GetAllData();
    EXPECT_EQ(ret.second.size(), 0);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Concurrent_V2_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 200);
    pref->PutInt(KEY_TEST_INT + "_2", 400);
    pref->PutInt(KEY_TEST_INT + "_3", 600);
    pref->FlushSync();
    EXPECT_EQ(pref->GetInt(KEY_TEST_INT, 0), 200);
    EXPECT_EQ(pref->GetInt(KEY_TEST_INT + "_2", 0), 400);
    EXPECT_EQ(pref->GetInt(KEY_TEST_INT + "_3", 0), 600);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Concurrent_V2_002, TestSize.Level0)
{
    for (int i = 0; i < 60; i++) {
        pref->PutInt(KEY_TEST_INT + "_" + std::to_string(i), i * 10);
    }
    pref->FlushSync();
    for (int i = 0; i < 60; i++) {
        int ret = pref->GetInt(KEY_TEST_INT + "_" + std::to_string(i), -1);
        EXPECT_EQ(ret, i * 10);
    }
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Concurrent_V2_003, TestSize.Level0)
{
    std::vector<std::string> array = { "x", "y", "z" };
    for (int i = 0; i < 15; i++) {
        pref->Put(KEY_TEST_STRING_ARRAY + "_" + std::to_string(i), array);
    }
    pref->FlushSync();
    PreferencesValue defValue(0);
    for (int i = 0; i < 15; i++) {
        PreferencesValue ret = pref->Get(KEY_TEST_STRING_ARRAY + "_" + std::to_string(i), defValue);
        EXPECT_EQ(ret.IsStringArray(), true);
    }
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Concurrent_V2_004, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 200);
    pref->FlushSync();
    pref->Delete(KEY_TEST_INT);
    pref->PutInt(KEY_TEST_INT, 400);
    pref->FlushSync();
    EXPECT_EQ(pref->GetInt(KEY_TEST_INT, 0), 400);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_Concurrent_V2_005, TestSize.Level0)
{
    for (int i = 0; i < 25; i++) {
        pref->PutString(KEY_TEST_STRING + "_" + std::to_string(i), "string_v2_" + std::to_string(i));
        pref->PutInt(KEY_TEST_INT + "_" + std::to_string(i), i * 10);
    }
    pref->FlushSync();
    for (int i = 0; i < 25; i++) {
        EXPECT_EQ(pref->GetString(KEY_TEST_STRING + "_" + std::to_string(i), ""), "string_v2_" + std::to_string(i));
        EXPECT_EQ(pref->GetInt(KEY_TEST_INT + "_" + std::to_string(i), -1), i * 10);
    }
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_SetOperations_V2_001, TestSize.Level0)
{
    std::set<std::string> keys = { KEY_TEST_INT, KEY_TEST_STRING, KEY_TEST_BOOL };
    for (auto key : keys) {
        pref->PutInt(key, 100);
    }
    pref->FlushSync();
    for (auto key : keys) {
        EXPECT_EQ(pref->HasKey(key), true);
    }
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_SetOperations_V2_002, TestSize.Level0)
{
    std::set<std::string> keys = { KEY_TEST_LONG, KEY_TEST_FLOAT, KEY_TEST_DOUBLE };
    for (auto key : keys) {
        pref->PutInt(key, 200);
    }
    pref->FlushSync();
    for (auto key : keys) {
        EXPECT_EQ(pref->HasKey(key), true);
    }
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_SetOperations_V2_003, TestSize.Level0)
{
    std::set<std::string> keys = { KEY_TEST_STRING_ARRAY, KEY_TEST_BOOL_ARRAY, KEY_TEST_DOUBLE_ARRAY };
    std::vector<std::string> strArray = { "a", "b" };
    for (auto key : keys) {
        pref->Put(key, strArray);
    }
    pref->FlushSync();
    for (auto key : keys) {
        EXPECT_EQ(pref->HasKey(key), true);
    }
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_SetOperations_V2_004, TestSize.Level0)
{
    std::set<std::string> keys = { KEY_TEST_INT + "_1", KEY_TEST_INT + "_2", KEY_TEST_INT + "_3" };
    for (auto key : keys) {
        pref->PutInt(key, 300);
    }
    pref->FlushSync();
    for (auto key : keys) {
        EXPECT_EQ(pref->HasKey(key), true);
    }
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_SetOperations_V2_005, TestSize.Level0)
{
    std::set<std::string> keys = { KEY_TEST_STRING + "_1", KEY_TEST_STRING + "_2", KEY_TEST_STRING + "_3" };
    for (auto key : keys) {
        pref->PutString(key, "test_v2");
    }
    pref->FlushSync();
    for (auto key : keys) {
        EXPECT_EQ(pref->HasKey(key), true);
    }
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_ValueConsistency_V2_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    int ret1 = pref->GetInt(KEY_TEST_INT, 0);
    int ret2 = pref->GetInt(KEY_TEST_INT, 0);
    int ret3 = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret1, 100);
    EXPECT_EQ(ret2, 100);
    EXPECT_EQ(ret3, 100);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_ValueConsistency_V2_002, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "test_v2");
    pref->FlushSync();
    std::string ret1 = pref->GetString(KEY_TEST_STRING, "");
    std::string ret2 = pref->GetString(KEY_TEST_STRING, "");
    std::string ret3 = pref->GetString(KEY_TEST_STRING, "");
    EXPECT_EQ(ret1, "test_v2");
    EXPECT_EQ(ret2, "test_v2");
    EXPECT_EQ(ret3, "test_v2");
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_ValueConsistency_V2_003, TestSize.Level0)
{
    pref->PutBool(KEY_TEST_BOOL, false);
    pref->FlushSync();
    bool ret1 = pref->GetBool(KEY_TEST_BOOL, true);
    bool ret2 = pref->GetBool(KEY_TEST_BOOL, true);
    bool ret3 = pref->GetBool(KEY_TEST_BOOL, true);
    EXPECT_EQ(ret1, false);
    EXPECT_EQ(ret2, false);
    EXPECT_EQ(ret3, false);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_ValueConsistency_V2_004, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, 10000L);
    pref->FlushSync();
    int64_t ret1 = pref->GetLong(KEY_TEST_LONG, 0L);
    int64_t ret2 = pref->GetLong(KEY_TEST_LONG, 0L);
    int64_t ret3 = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret1, 10000L);
    EXPECT_EQ(ret2, 10000L);
    EXPECT_EQ(ret3, 10000L);
}

HWTEST_F(PreferencesComprehensiveTestV2, Test_ValueConsistency_V2_005, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, 2.5f);
    pref->FlushSync();
    float ret1 = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    float ret2 = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    float ret3 = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret1, 2.5f);
    EXPECT_EQ(ret2, 2.5f);
    EXPECT_EQ(ret3, 2.5f);
}

} // namespace
