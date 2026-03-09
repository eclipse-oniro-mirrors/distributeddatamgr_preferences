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

#include "log_print.h"
#include "preferences_errno.h"
#include "preferences_helper.h"
#include "preferences_observer.h"
#include "preferences_utils.h"
#include "preferences_value.h"

using namespace testing::ext;
using namespace OHOS::NativePreferences;

namespace {
const std::string KEY_TEST_INT = "key_test_int_v1";
const std::string KEY_TEST_LONG = "key_test_long_v1";
const std::string KEY_TEST_FLOAT = "key_test_float_v1";
const std::string KEY_TEST_DOUBLE = "key_test_double_v1";
const std::string KEY_TEST_BOOL = "key_test_bool_v1";
const std::string KEY_TEST_STRING = "key_test_string_v1";
const std::string KEY_TEST_STRING_ARRAY = "key_test_string_array_v1";
const std::string KEY_TEST_BOOL_ARRAY = "key_test_bool_array_v1";
const std::string KEY_TEST_DOUBLE_ARRAY = "key_test_double_array_v1";
const std::string KEY_TEST_UINT8_ARRAY = "key_test_uint8_array_v1";
const std::string KEY_TEST_OBJECT = "key_test_object_v1";
const std::string KEY_TEST_BIGINT = "key_test_bigint_v1";

class PreferencesComprehensiveTestV1 : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static std::shared_ptr<Preferences> pref;
};

std::shared_ptr<Preferences> PreferencesComprehensiveTestV1::pref = nullptr;

void PreferencesComprehensiveTestV1::SetUpTestCase(void)
{
}

void PreferencesComprehensiveTestV1::TearDownTestCase(void)
{
}

void PreferencesComprehensiveTestV1::SetUp(void)
{
    int errCode = E_OK;
    pref = PreferencesHelper::GetPreferences("/data/test_comprehensive_v1", errCode);
    EXPECT_EQ(errCode, E_OK);
}

void PreferencesComprehensiveTestV1::TearDown(void)
{
    pref = nullptr;
    int ret = PreferencesHelper::DeletePreferences("/data/test_comprehensive_v1");
    EXPECT_EQ(ret, E_OK);
}

class PreferencesObserverV1 : public PreferencesObserver {
public:
    virtual ~PreferencesObserverV1();
    void OnChange(const std::string &key) override;
    void OnChange(const std::map<std::string, OHOS::NativePreferences::PreferencesValue> &records) override;

    std::atomic_int notifyTimes;
};

PreferencesObserverV1::~PreferencesObserverV1()
{
}

void PreferencesObserverV1::OnChange(const std::string &key)
{
    notifyTimes++;
}

void PreferencesObserverV1::OnChange(
    const std::map<std::string, OHOS::NativePreferences::PreferencesValue> &records)
{
    notifyTimes++;
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutInt_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    int ret = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret, 100);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutInt_002, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, -100);
    pref->FlushSync();
    int ret = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret, -100);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutInt_003, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 0);
    pref->FlushSync();
    int ret = pref->GetInt(KEY_TEST_INT, 1);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutInt_004, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 2147483647);
    pref->FlushSync();
    int ret = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret, 2147483647);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutInt_005, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, -2147483648);
    pref->FlushSync();
    int ret = pref->GetInt(KEY_TEST_INT, 0);
    EXPECT_EQ(ret, -2147483648);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutLong_001, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, 1000L);
    pref->FlushSync();
    int64_t ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, 1000L);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutLong_002, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, -1000L);
    pref->FlushSync();
    int64_t ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, -1000L);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutLong_003, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, 0L);
    pref->FlushSync();
    int64_t ret = pref->GetLong(KEY_TEST_LONG, 1L);
    EXPECT_EQ(ret, 0L);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutLong_004, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, 9223372036854775807L);
    pref->FlushSync();
    int64_t ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, 9223372036854775807L);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutLong_005, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, -9223372036854775808L);
    pref->FlushSync();
    int64_t ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, -9223372036854775808L);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutFloat_001, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, 100.5f);
    pref->FlushSync();
    float ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, 100.5f);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutFloat_002, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, -100.5f);
    pref->FlushSync();
    float ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, -100.5f);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutFloat_003, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, 0.0f);
    pref->FlushSync();
    float ret = pref->GetFloat(KEY_TEST_FLOAT, 1.0f);
    EXPECT_EQ(ret, 0.0f);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutFloat_004, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, 3.14159f);
    pref->FlushSync();
    float ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, 3.14159f);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutFloat_005, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, -3.14159f);
    pref->FlushSync();
    float ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, -3.14159f);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutDouble_001, TestSize.Level0)
{
    pref->PutDouble(KEY_TEST_DOUBLE, 1000.5);
    pref->FlushSync();
    double ret = pref->GetDouble(KEY_TEST_DOUBLE, 0.0);
    EXPECT_EQ(ret, 1000.5);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutDouble_002, TestSize.Level0)
{
    pref->PutDouble(KEY_TEST_DOUBLE, -1000.5);
    pref->FlushSync();
    double ret = pref->GetDouble(KEY_TEST_DOUBLE, 0.0);
    EXPECT_EQ(ret, -1000.5);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutDouble_003, TestSize.Level0)
{
    pref->PutDouble(KEY_TEST_DOUBLE, 0.0);
    pref->FlushSync();
    double ret = pref->GetDouble(KEY_TEST_DOUBLE, 1.0);
    EXPECT_EQ(ret, 0.0);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutDouble_004, TestSize.Level0)
{
    pref->PutDouble(KEY_TEST_DOUBLE, 3.14159265358979);
    pref->FlushSync();
    double ret = pref->GetDouble(KEY_TEST_DOUBLE, 0.0);
    EXPECT_EQ(ret, 3.14159265358979);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutDouble_005, TestSize.Level0)
{
    pref->PutDouble(KEY_TEST_DOUBLE, -3.14159265358979);
    pref->FlushSync();
    double ret = pref->GetDouble(KEY_TEST_DOUBLE, 0.0);
    EXPECT_EQ(ret, -3.14159265358979);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutBool_001, TestSize.Level0)
{
    pref->PutBool(KEY_TEST_BOOL, true);
    pref->FlushSync();
    bool ret = pref->GetBool(KEY_TEST_BOOL, false);
    EXPECT_EQ(ret, true);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutBool_002, TestSize.Level0)
{
    pref->PutBool(KEY_TEST_BOOL, false);
    pref->FlushSync();
    bool ret = pref->GetBool(KEY_TEST_BOOL, true);
    EXPECT_EQ(ret, false);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutString_001, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "test_string_v1");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "test_string_v1");
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutString_002, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "");
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutString_003, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "string with spaces");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "string with spaces");
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutString_004, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "string\twith\ttabs");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "string\twith\ttabs");
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutString_005, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "string\nwith\nnewlines");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "string\nwith\nnewlines");
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutStringArray_001, TestSize.Level0)
{
    std::vector<std::string> array = { "string1", "string2", "string3" };
    pref->Put(KEY_TEST_STRING_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_STRING_ARRAY, defValue);
    EXPECT_EQ(ret.IsStringArray(), true);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutStringArray_002, TestSize.Level0)
{
    std::vector<std::string> array = { "a", "b", "c", "d", "e" };
    pref->Put(KEY_TEST_STRING_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_STRING_ARRAY, defValue);
    EXPECT_EQ(ret.IsStringArray(), true);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutStringArray_003, TestSize.Level0)
{
    std::vector<std::string> array = { "" };
    pref->Put(KEY_TEST_STRING_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_STRING_ARRAY, defValue);
    EXPECT_EQ(ret.IsStringArray(), true);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutStringArray_004, TestSize.Level0)
{
    std::vector<std::string> array = { "string with spaces", "another string" };
    pref->Put(KEY_TEST_STRING_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_STRING_ARRAY, defValue);
    EXPECT_EQ(ret.IsStringArray(), true);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutStringArray_005, TestSize.Level0)
{
    std::vector<std::string> array = { "special!@#$%^&*()", "characters" };
    pref->Put(KEY_TEST_STRING_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_STRING_ARRAY, defValue);
    EXPECT_EQ(ret.IsStringArray(), true);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutBoolArray_001, TestSize.Level0)
{
    std::vector<bool> array = { true, false, true };
    pref->Put(KEY_TEST_BOOL_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_BOOL_ARRAY, defValue);
    EXPECT_EQ(ret.IsBoolArray(), true);
    EXPECT_EQ(static_cast<std::vector<bool>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutBoolArray_002, TestSize.Level0)
{
    std::vector<bool> array = { true, true, true, true, true };
    pref->Put(KEY_TEST_BOOL_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_BOOL_ARRAY, defValue);
    EXPECT_EQ(ret.IsBoolArray(), true);
    EXPECT_EQ(static_cast<std::vector<bool>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutBoolArray_003, TestSize.Level0)
{
    std::vector<bool> array = { false, false, false };
    pref->Put(KEY_TEST_BOOL_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_BOOL_ARRAY, defValue);
    EXPECT_EQ(ret.IsBoolArray(), true);
    EXPECT_EQ(static_cast<std::vector<bool>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutBoolArray_004, TestSize.Level0)
{
    std::vector<bool> array = { true, false, true, false, true, false };
    pref->Put(KEY_TEST_BOOL_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_BOOL_ARRAY, defValue);
    EXPECT_EQ(ret.IsBoolArray(), true);
    EXPECT_EQ(static_cast<std::vector<bool>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutBoolArray_005, TestSize.Level0)
{
    std::vector<bool> array = { false, true };
    pref->Put(KEY_TEST_BOOL_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_BOOL_ARRAY, defValue);
    EXPECT_EQ(ret.IsBoolArray(), true);
    EXPECT_EQ(static_cast<std::vector<bool>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutDoubleArray_001, TestSize.Level0)
{
    std::vector<double> array = { 1.1, 2.2, 3.3 };
    pref->Put(KEY_TEST_DOUBLE_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_DOUBLE_ARRAY, defValue);
    EXPECT_EQ(ret.IsDoubleArray(), true);
    EXPECT_EQ(static_cast<std::vector<double>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutDoubleArray_002, TestSize.Level0)
{
    std::vector<double> array = { 0.0, 0.0, 0.0 };
    pref->Put(KEY_TEST_DOUBLE_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_DOUBLE_ARRAY, defValue);
    EXPECT_EQ(ret.IsDoubleArray(), true);
    EXPECT_EQ(static_cast<std::vector<double>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutDoubleArray_003, TestSize.Level0)
{
    std::vector<double> array = { -1.5, -2.5, -3.5 };
    pref->Put(KEY_TEST_DOUBLE_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_DOUBLE_ARRAY, defValue);
    EXPECT_EQ(ret.IsDoubleArray(), true);
    EXPECT_EQ(static_cast<std::vector<double>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutDoubleArray_004, TestSize.Level0)
{
    std::vector<double> array = { 3.14159, 2.71828, 1.41421 };
    pref->Put(KEY_TEST_DOUBLE_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_DOUBLE_ARRAY, defValue);
    EXPECT_EQ(ret.IsDoubleArray(), true);
    EXPECT_EQ(static_cast<std::vector<double>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutDoubleArray_005, TestSize.Level0)
{
    std::vector<double> array = { 1.0e10, 1.0e-10, 1.0e0 };
    pref->Put(KEY_TEST_DOUBLE_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_DOUBLE_ARRAY, defValue);
    EXPECT_EQ(ret.IsDoubleArray(), true);
    EXPECT_EQ(static_cast<std::vector<double>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutUint8Array_001, TestSize.Level0)
{
    std::vector<uint8_t> array = { 1, 2, 3, 4, 5 };
    pref->Put(KEY_TEST_UINT8_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_UINT8_ARRAY, defValue);
    EXPECT_EQ(ret.IsUint8Array(), true);
    EXPECT_EQ(static_cast<std::vector<uint8_t>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutUint8Array_002, TestSize.Level0)
{
    std::vector<uint8_t> array = { 0, 0, 0 };
    pref->Put(KEY_TEST_UINT8_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_UINT8_ARRAY, defValue);
    EXPECT_EQ(ret.IsUint8Array(), true);
    EXPECT_EQ(static_cast<std::vector<uint8_t>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutUint8Array_003, TestSize.Level0)
{
    std::vector<uint8_t> array = { 255, 255, 255 };
    pref->Put(KEY_TEST_UINT8_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_UINT8_ARRAY, defValue);
    EXPECT_EQ(ret.IsUint8Array(), true);
    EXPECT_EQ(static_cast<std::vector<uint8_t>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutUint8Array_004, TestSize.Level0)
{
    std::vector<uint8_t> array = { 128, 64, 32, 16, 8, 4, 2, 1 };
    pref->Put(KEY_TEST_UINT8_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_UINT8_ARRAY, defValue);
    EXPECT_EQ(ret.IsUint8Array(), true);
    EXPECT_EQ(static_cast<std::vector<uint8_t>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutUint8Array_005, TestSize.Level0)
{
    std::vector<uint8_t> array = { 1 };
    pref->Put(KEY_TEST_UINT8_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_UINT8_ARRAY, defValue);
    EXPECT_EQ(ret.IsUint8Array(), true);
    EXPECT_EQ(static_cast<std::vector<uint8_t>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutBigInt_001, TestSize.Level0)
{
    std::vector<uint64_t> words = { 1, 2, 3 };
    BigInt bigint(words, 0);
    pref->Put(KEY_TEST_BIGINT, bigint);
    pref->FlushSync();
    BigInt ret = pref->Get(KEY_TEST_BIGINT, BigInt());
    EXPECT_EQ(ret, bigint);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutBigInt_002, TestSize.Level0)
{
    std::vector<uint64_t> words = { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF };
    BigInt bigint(words, 0);
    pref->Put(KEY_TEST_BIGINT, bigint);
    pref->FlushSync();
    BigInt ret = pref->Get(KEY_TEST_BIGINT, BigInt());
    EXPECT_EQ(ret, bigint);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutBigInt_003, TestSize.Level0)
{
    std::vector<uint64_t> words = { 1, 1, 1, 1, 1 };
    BigInt bigint(words, 1);
    pref->Put(KEY_TEST_BIGINT, bigint);
    pref->FlushSync();
    BigInt ret = pref->Get(KEY_TEST_BIGINT, BigInt());
    EXPECT_EQ(ret, bigint);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutBigInt_004, TestSize.Level0)
{
    std::vector<uint64_t> words = { 123456789 };
    BigInt bigint(words, 0);
    pref->Put(KEY_TEST_BIGINT, bigint);
    pref->FlushSync();
    BigInt ret = pref->Get(KEY_TEST_BIGINT, BigInt());
    EXPECT_EQ(ret, bigint);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutBigInt_005, TestSize.Level0)
{
    std::vector<uint64_t> words = { 9876543210 };
    BigInt bigint(words, 0);
    pref->Put(KEY_TEST_BIGINT, bigint);
    pref->FlushSync();
    BigInt ret = pref->Get(KEY_TEST_BIGINT, BigInt());
    EXPECT_EQ(ret, bigint);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutObject_001, TestSize.Level0)
{
    Object object("{\"key1\":\"value1\",\"key2\":123}");
    pref->Put(KEY_TEST_OBJECT, object);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_OBJECT, defValue);
    EXPECT_EQ(static_cast<Object>(ret), object);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutObject_002, TestSize.Level0)
{
    Object object("{\"a\":1,\"b\":2,\"c\":3,\"d\":4,\"e\":5}");
    pref->Put(KEY_TEST_OBJECT, object);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_OBJECT, defValue);
    EXPECT_EQ(static_cast<Object>(ret), object);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutObject_003, TestSize.Level0)
{
    Object object("{}");
    pref->Put(KEY_TEST_OBJECT, object);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_OBJECT, defValue);
    EXPECT_EQ(static_cast<Object>(ret), object);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutObject_004, TestSize.Level0)
{
    Object object("{\"nested\":{\"value\":42}}");
    pref->Put(KEY_TEST_OBJECT, object);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_OBJECT, defValue);
    EXPECT_EQ(static_cast<Object>(ret), object);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutObject_005, TestSize.Level0)
{
    Object object("{\"array\":[1,2,3,4,5]}");
    pref->Put(KEY_TEST_OBJECT, object);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_OBJECT, defValue);
    EXPECT_EQ(static_cast<Object>(ret), object);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_HasKey_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    bool ret = pref->HasKey(KEY_TEST_INT);
    EXPECT_EQ(ret, true);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_HasKey_002, TestSize.Level0)
{
    bool ret = pref->HasKey(KEY_TEST_INT);
    EXPECT_EQ(ret, false);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_HasKey_003, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "test");
    pref->FlushSync();
    bool ret = pref->HasKey(KEY_TEST_STRING);
    EXPECT_EQ(ret, true);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_HasKey_004, TestSize.Level0)
{
    pref->PutBool(KEY_TEST_BOOL, true);
    pref->FlushSync();
    bool ret = pref->HasKey(KEY_TEST_BOOL);
    EXPECT_EQ(ret, true);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_HasKey_005, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, 1.5f);
    pref->FlushSync();
    bool ret = pref->HasKey(KEY_TEST_FLOAT);
    EXPECT_EQ(ret, true);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_Delete_001, TestSize.Level0)
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

HWTEST_F(PreferencesComprehensiveTestV1, Test_Delete_002, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "test");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "test");
    pref->Delete(KEY_TEST_STRING);
    pref->FlushSync();
    ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "default");
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_Delete_003, TestSize.Level0)
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

HWTEST_F(PreferencesComprehensiveTestV1, Test_Delete_004, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, 1000L);
    pref->FlushSync();
    int64_t ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, 1000L);
    pref->Delete(KEY_TEST_LONG);
    pref->FlushSync();
    ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, 0L);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_Delete_005, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, 1.5f);
    pref->FlushSync();
    float ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, 1.5f);
    pref->Delete(KEY_TEST_FLOAT);
    pref->FlushSync();
    ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, 0.0f);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_Clear_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutString(KEY_TEST_STRING, "test");
    pref->PutBool(KEY_TEST_BOOL, true);
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

HWTEST_F(PreferencesComprehensiveTestV1, Test_Clear_002, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, 1000L);
    pref->PutFloat(KEY_TEST_FLOAT, 1.5f);
    pref->PutDouble(KEY_TEST_DOUBLE, 2.5);
    pref->FlushSync();
    pref->Clear();
    pref->FlushSync();
    EXPECT_EQ(pref->HasKey(KEY_TEST_LONG), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_FLOAT), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_DOUBLE), false);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_Clear_003, TestSize.Level0)
{
    pref->Clear();
    pref->FlushSync();
    EXPECT_EQ(pref->HasKey(KEY_TEST_INT), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING), false);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_RegisterObserver_001, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV1>();
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV1 *>(observer.get())->notifyTimes, 1);
    pref->UnRegisterObserver(observer);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_RegisterObserver_002, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV1>();
    pref->RegisterObserver(observer);
    pref->PutString(KEY_TEST_STRING, "test");
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV1 *>(observer.get())->notifyTimes, 2);
    pref->UnRegisterObserver(observer);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_RegisterObserver_003, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV1>();
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV1 *>(observer.get())->notifyTimes, 1);
    pref->PutInt(KEY_TEST_INT, 200);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV1 *>(observer.get())->notifyTimes, 2);
    pref->UnRegisterObserver(observer);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_RegisterObserver_004, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV1>();
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutString(KEY_TEST_STRING, "test");
    pref->PutBool(KEY_TEST_BOOL, true);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV1 *>(observer.get())->notifyTimes, 3);
    pref->UnRegisterObserver(observer);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_RegisterObserver_005, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV1>();
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV1 *>(observer.get())->notifyTimes, 1);
    pref->UnRegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 200);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV1 *>(observer.get())->notifyTimes, 1);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_GetAll_001, TestSize.Level0)
{
    std::map<std::string, PreferencesValue> data = {
        { KEY_TEST_INT, 100 },
        { KEY_TEST_STRING, "test" },
        { KEY_TEST_BOOL, true }
    };
    for (auto &item : data) {
        pref->Put(item.first, item.second);
    }
    pref->FlushSync();
    auto ret = pref->GetAll();
    EXPECT_EQ(ret.size(), data.size());
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_GetAll_002, TestSize.Level0)
{
    auto ret = pref->GetAll();
    EXPECT_EQ(ret.size(), 0);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_GetAll_003, TestSize.Level0)
{
    std::map<std::string, PreferencesValue> data = {
        { KEY_TEST_INT, 100 },
        { KEY_TEST_LONG, 1000L },
        { KEY_TEST_FLOAT, 1.5f },
        { KEY_TEST_DOUBLE, 2.5 }
    };
    for (auto &item : data) {
        pref->Put(item.first, item.second);
    }
    pref->FlushSync();
    auto ret = pref->GetAll();
    EXPECT_EQ(ret.size(), data.size());
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_GetAll_004, TestSize.Level0)
{
    std::map<std::string, PreferencesValue> data = {
        { KEY_TEST_STRING, "test1" },
        { KEY_TEST_STRING + "_2", "test2" },
        { KEY_TEST_STRING + "_3", "test3" }
    };
    for (auto &item : data) {
        pref->Put(item.first, item.second);
    }
    pref->FlushSync();
    auto ret = pref->GetAll();
    EXPECT_EQ(ret.size(), data.size());
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_GetAll_005, TestSize.Level0)
{
    std::map<std::string, PreferencesValue> data = {
        { KEY_TEST_BOOL, true },
        { KEY_TEST_BOOL + "_2", false },
        { KEY_TEST_BOOL + "_3", true }
    };
    for (auto &item : data) {
        pref->Put(item.first, item.second);
    }
    pref->FlushSync();
    auto ret = pref->GetAll();
    EXPECT_EQ(ret.size(), data.size());
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutMultiple_001, TestSize.Level0)
{
    for (int i = 0; i < 10; i++) {
        pref->PutInt(KEY_TEST_INT + "_" + std::to_string(i), i);
    }
    pref->FlushSync();
    for (int i = 0; i < 10; i++) {
        int ret = pref->GetInt(KEY_TEST_INT + "_" + std::to_string(i), -1);
        EXPECT_EQ(ret, i);
    }
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutMultiple_002, TestSize.Level0)
{
    for (int i = 0; i < 20; i++) {
        pref->PutString(KEY_TEST_STRING + "_" + std::to_string(i), "string_" + std::to_string(i));
    }
    pref->FlushSync();
    for (int i = 0; i < 20; i++) {
        std::string ret = pref->GetString(KEY_TEST_STRING + "_" + std::to_string(i), "");
        EXPECT_EQ(ret, "string_" + std::to_string(i));
    }
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutMultiple_003, TestSize.Level0)
{
    for (int i = 0; i < 15; i++) {
        pref->PutLong(KEY_TEST_LONG + "_" + std::to_string(i), i * 1000L);
    }
    pref->FlushSync();
    for (int i = 0; i < 15; i++) {
        int64_t ret = pref->GetLong(KEY_TEST_LONG + "_" + std::to_string(i), 0L);
        EXPECT_EQ(ret, i * 1000L);
    }
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutMultiple_004, TestSize.Level0)
{
    for (int i = 0; i < 25; i++) {
        pref->PutBool(KEY_TEST_BOOL + "_" + std::to_string(i), i % 2 == 0);
    }
    pref->FlushSync();
    for (int i = 0; i < 25; i++) {
        bool ret = pref->GetBool(KEY_TEST_BOOL + "_" + std::to_string(i), false);
        EXPECT_EQ(ret, i % 2 == 0);
    }
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_PutMultiple_005, TestSize.Level0)
{
    for (int i = 0; i < 30; i++) {
        pref->PutFloat(KEY_TEST_FLOAT + "_" + std::to_string(i), i * 1.5f);
    }
    pref->FlushSync();
    for (int i = 0; i < 30; i++) {
        float ret = pref->GetFloat(KEY_TEST_FLOAT + "_" + std::to_string(i), 0.0f);
        EXPECT_EQ(ret, i * 1.5f);
    }
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_Update_001, TestSize.Level0)
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

HWTEST_F(PreferencesComprehensiveTestV1, Test_Update_002, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "test1");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "");
    EXPECT_EQ(ret, "test1");
    pref->PutString(KEY_TEST_STRING, "test2");
    pref->FlushSync();
    ret = pref->GetString(KEY_TEST_STRING, "");
    EXPECT_EQ(ret, "test2");
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_Update_003, TestSize.Level0)
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

HWTEST_F(PreferencesComprehensiveTestV1, Test_Update_004, TestSize.Level0)
{
    pref->PutLong(KEY_TEST_LONG, 1000L);
    pref->FlushSync();
    int64_t ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, 1000L);
    pref->PutLong(KEY_TEST_LONG, 2000L);
    pref->FlushSync();
    ret = pref->GetLong(KEY_TEST_LONG, 0L);
    EXPECT_EQ(ret, 2000L);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_Update_005, TestSize.Level0)
{
    pref->PutFloat(KEY_TEST_FLOAT, 1.5f);
    pref->FlushSync();
    float ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, 1.5f);
    pref->PutFloat(KEY_TEST_FLOAT, 2.5f);
    pref->FlushSync();
    ret = pref->GetFloat(KEY_TEST_FLOAT, 0.0f);
    EXPECT_EQ(ret, 2.5f);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_MixedTypes_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutString(KEY_TEST_STRING, "test");
    pref->PutBool(KEY_TEST_BOOL, true);
    pref->PutLong(KEY_TEST_LONG, 1000L);
    pref->PutFloat(KEY_TEST_FLOAT, 1.5f);
    pref->FlushSync();
    EXPECT_EQ(pref->GetInt(KEY_TEST_INT, 0), 100);
    EXPECT_EQ(pref->GetString(KEY_TEST_STRING, ""), "test");
    EXPECT_EQ(pref->GetBool(KEY_TEST_BOOL, false), true);
    EXPECT_EQ(pref->GetLong(KEY_TEST_LONG, 0L), 1000L);
    EXPECT_EQ(pref->GetFloat(KEY_TEST_FLOAT, 0.0f), 1.5f);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_MixedTypes_002, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 200);
    pref->PutString(KEY_TEST_STRING, "test2");
    pref->PutBool(KEY_TEST_BOOL, false);
    pref->PutLong(KEY_TEST_LONG, 2000L);
    pref->PutFloat(KEY_TEST_FLOAT, 2.5f);
    pref->PutDouble(KEY_TEST_DOUBLE, 3.5);
    pref->FlushSync();
    EXPECT_EQ(pref->GetInt(KEY_TEST_INT, 0), 200);
    EXPECT_EQ(pref->GetString(KEY_TEST_STRING, ""), "test2");
    EXPECT_EQ(pref->GetBool(KEY_TEST_BOOL, true), false);
    EXPECT_EQ(pref->GetLong(KEY_TEST_LONG, 0L), 2000L);
    EXPECT_EQ(pref->GetFloat(KEY_TEST_FLOAT, 0.0f), 2.5f);
    EXPECT_EQ(pref->GetDouble(KEY_TEST_DOUBLE, 0.0), 3.5);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_MixedTypes_003, TestSize.Level0)
{
    std::vector<std::string> strArray = { "a", "b", "c" };
    std::vector<bool> boolArray = { true, false, true };
    std::vector<double> doubleArray = { 1.1, 2.2, 3.3 };
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

HWTEST_F(PreferencesComprehensiveTestV1, Test_MixedTypes_004, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 300);
    pref->PutString(KEY_TEST_STRING, "test3");
    pref->PutBool(KEY_TEST_BOOL, true);
    pref->PutDouble(KEY_TEST_DOUBLE, 4.5);
    pref->FlushSync();
    auto all = pref->GetAll();
    EXPECT_EQ(all.size(), 4);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_MixedTypes_005, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 400);
    pref->PutString(KEY_TEST_STRING, "test4");
    pref->FlushSync();
    pref->Clear();
    pref->PutLong(KEY_TEST_LONG, 4000L);
    pref->PutFloat(KEY_TEST_FLOAT, 4.5f);
    pref->FlushSync();
    EXPECT_EQ(pref->HasKey(KEY_TEST_INT), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_LONG), true);
    EXPECT_EQ(pref->HasKey(KEY_TEST_FLOAT), true);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_EdgeCases_001, TestSize.Level0)
{
    pref->PutString(KEY_TEST_STRING, "");
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "default");
    EXPECT_EQ(ret, "");
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_EdgeCases_002, TestSize.Level0)
{
    std::string longString(1000, 'a');
    pref->PutString(KEY_TEST_STRING, longString);
    pref->FlushSync();
    std::string ret = pref->GetString(KEY_TEST_STRING, "");
    EXPECT_EQ(ret, longString);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_EdgeCases_003, TestSize.Level0)
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

HWTEST_F(PreferencesComprehensiveTestV1, Test_EdgeCases_004, TestSize.Level0)
{
    pref->PutBool(KEY_TEST_BOOL, true);
    pref->FlushSync();
    bool ret = pref->GetBool(KEY_TEST_BOOL, false);
    EXPECT_EQ(ret, true);
    ret = pref->GetBool(KEY_TEST_BOOL, true);
    EXPECT_EQ(ret, true);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_EdgeCases_005, TestSize.Level0)
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

HWTEST_F(PreferencesComprehensiveTestV1, Test_DeleteMultiple_001, TestSize.Level0)
{
    for (int i = 0; i < 10; i++) {
        pref->PutInt(KEY_TEST_INT + "_" + std::to_string(i), i);
    }
    pref->FlushSync();
    for (int i = 0; i < 10; i++) {
        pref->Delete(KEY_TEST_INT + "_" + std::to_string(i));
    }
    pref->FlushSync();
    for (int i = 0; i < 10; i++) {
        int ret = pref->GetInt(KEY_TEST_INT + "_" + std::to_string(i), -1);
        EXPECT_EQ(ret, -1);
    }
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_DeleteMultiple_002, TestSize.Level0)
{
    for (int i = 0; i < 5; i++) {
        pref->PutString(KEY_TEST_STRING + "_" + std::to_string(i), "test_" + std::to_string(i));
    }
    pref->FlushSync();
    pref->Delete(KEY_TEST_STRING + "_0");
    pref->Delete(KEY_TEST_STRING + "_2");
    pref->Delete(KEY_TEST_STRING + "_4");
    pref->FlushSync();
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING + "_0"), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING + "_1"), true);
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING + "_2"), false);
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING + "_3"), true);
    EXPECT_EQ(pref->HasKey(KEY_TEST_STRING + "_4"), false);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_DeleteMultiple_003, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutString(KEY_TEST_STRING, "test");
    pref->PutBool(KEY_TEST_BOOL, true);
    pref->FlushSync();
    EXPECT_EQ(pref->GetAll().size(), 3);
    pref->Clear();
    pref->FlushSync();
    EXPECT_EQ(pref->GetAll().size(), 0);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_ObserverChanges_001, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV1>();
    pref->RegisterObserver(observer);
    for (int i = 0; i < 10; i++) {
        pref->PutInt(KEY_TEST_INT, i);
        pref->FlushSync();
    }
    EXPECT_EQ(static_cast<PreferencesObserverV1 *>(observer.get())->notifyTimes, 10);
    pref->UnRegisterObserver(observer);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_ObserverChanges_002, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV1>();
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutString(KEY_TEST_STRING, "test");
    pref->PutBool(KEY_TEST_BOOL, true);
    pref->PutLong(KEY_TEST_LONG, 1000L);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV1 *>(observer.get())->notifyTimes, 4);
    pref->UnRegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 200);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV1 *>(observer.get())->notifyTimes, 4);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_ObserverChanges_003, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV1>();
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV1 *>(observer.get())->notifyTimes, 1);
    pref->UnRegisterObserver(observer);
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 200);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV1 *>(observer.get())->notifyTimes, 2);
    pref->UnRegisterObserver(observer);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_ObserverChanges_004, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer1 = std::make_shared<PreferencesObserverV1>();
    std::shared_ptr<PreferencesObserver> observer2 = std::make_shared<PreferencesObserverV1>();
    pref->RegisterObserver(observer1);
    pref->RegisterObserver(observer2);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV1 *>(observer1.get())->notifyTimes, 1);
    EXPECT_EQ(static_cast<PreferencesObserverV1 *>(observer2.get())->notifyTimes, 1);
    pref->UnRegisterObserver(observer1);
    pref->UnRegisterObserver(observer2);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_ObserverChanges_005, TestSize.Level0)
{
    std::shared_ptr<PreferencesObserver> observer = std::make_shared<PreferencesObserverV1>();
    pref->RegisterObserver(observer);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    pref->Delete(KEY_TEST_INT);
    pref->FlushSync();
    EXPECT_EQ(static_cast<PreferencesObserverV1 *>(observer.get())->notifyTimes, 2);
    pref->UnRegisterObserver(observer);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_ArrayOperations_001, TestSize.Level0)
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

HWTEST_F(PreferencesComprehensiveTestV1, Test_ArrayOperations_002, TestSize.Level0)
{
    std::vector<bool> array = { true, false, true, false, true };
    pref->Put(KEY_TEST_BOOL_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_BOOL_ARRAY, defValue);
    EXPECT_EQ(static_cast<std::vector<bool>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_ArrayOperations_003, TestSize.Level0)
{
    std::vector<double> array = { 1.1, 2.2, 3.3, 4.4, 5.5 };
    pref->Put(KEY_TEST_DOUBLE_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_DOUBLE_ARRAY, defValue);
    EXPECT_EQ(static_cast<std::vector<double>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_ArrayOperations_004, TestSize.Level0)
{
    std::vector<uint8_t> array = { 1, 2, 3, 4, 5, 6, 7, 8 };
    pref->Put(KEY_TEST_UINT8_ARRAY, array);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret = pref->Get(KEY_TEST_UINT8_ARRAY, defValue);
    EXPECT_EQ(static_cast<std::vector<uint8_t>>(ret), array);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_ArrayOperations_005, TestSize.Level0)
{
    std::vector<std::string> array1 = { "a", "b", "c" };
    std::vector<std::string> array2 = { "x", "y", "z" };
    pref->Put(KEY_TEST_STRING_ARRAY, array1);
    pref->Put(KEY_TEST_STRING_ARRAY + "_2", array2);
    pref->FlushSync();
    PreferencesValue defValue(0);
    PreferencesValue ret1 = pref->Get(KEY_TEST_STRING_ARRAY, defValue);
    PreferencesValue ret2 = pref->Get(KEY_TEST_STRING_ARRAY + "_2", defValue);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret1), array1);
    EXPECT_EQ(static_cast<std::vector<std::string>>(ret2), array2);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_GetAllData_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutString(KEY_TEST_STRING, "test");
    pref->FlushSync();
    auto ret = pref->GetAllData();
    EXPECT_EQ(ret.second.size(), 2);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_GetAllData_002, TestSize.Level0)
{
    auto ret = pref->GetAllData();
    EXPECT_EQ(ret.second.size(), 0);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_GetAllData_003, TestSize.Level0)
{
    for (int i = 0; i < 5; i++) {
        pref->PutInt(KEY_TEST_INT + "_" + std::to_string(i), i);
    }
    pref->FlushSync();
    auto ret = pref->GetAllData();
    EXPECT_EQ(ret.second.size(), 5);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_GetAllData_004, TestSize.Level0)
{
    std::vector<std::string> array = { "a", "b", "c" };
    pref->Put(KEY_TEST_STRING_ARRAY, array);
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutString(KEY_TEST_STRING, "test");
    pref->FlushSync();
    auto ret = pref->GetAllData();
    EXPECT_EQ(ret.second.size(), 3);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_GetAllData_005, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutString(KEY_TEST_STRING, "test");
    pref->FlushSync();
    pref->Clear();
    pref->FlushSync();
    auto ret = pref->GetAllData();
    EXPECT_EQ(ret.second.size(), 0);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_Concurrent_001, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->PutInt(KEY_TEST_INT + "_2", 200);
    pref->PutInt(KEY_TEST_INT + "_3", 300);
    pref->FlushSync();
    EXPECT_EQ(pref->GetInt(KEY_TEST_INT, 0), 100);
    EXPECT_EQ(pref->GetInt(KEY_TEST_INT + "_2", 0), 200);
    EXPECT_EQ(pref->GetInt(KEY_TEST_INT + "_3", 0), 300);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_Concurrent_002, TestSize.Level0)
{
    for (int i = 0; i < 50; i++) {
        pref->PutInt(KEY_TEST_INT + "_" + std::to_string(i), i);
    }
    pref->FlushSync();
    for (int i = 0; i < 50; i++) {
        int ret = pref->GetInt(KEY_TEST_INT + "_" + std::to_string(i), -1);
        EXPECT_EQ(ret, i);
    }
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_Concurrent_003, TestSize.Level0)
{
    std::vector<std::string> array = { "a", "b", "c" };
    for (int i = 0; i < 10; i++) {
        pref->Put(KEY_TEST_STRING_ARRAY + "_" + std::to_string(i), array);
    }
    pref->FlushSync();
    PreferencesValue defValue(0);
    for (int i = 0; i < 10; i++) {
        PreferencesValue ret = pref->Get(KEY_TEST_STRING_ARRAY + "_" + std::to_string(i), defValue);
        EXPECT_EQ(ret.IsStringArray(), true);
    }
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_Concurrent_004, TestSize.Level0)
{
    pref->PutInt(KEY_TEST_INT, 100);
    pref->FlushSync();
    pref->Delete(KEY_TEST_INT);
    pref->PutInt(KEY_TEST_INT, 200);
    pref->FlushSync();
    EXPECT_EQ(pref->GetInt(KEY_TEST_INT, 0), 200);
}

HWTEST_F(PreferencesComprehensiveTestV1, Test_Concurrent_005, TestSize.Level0)
{
    for (int i = 0; i < 20; i++) {
        pref->PutString(KEY_TEST_STRING + "_" + std::to_string(i), "string_" + std::to_string(i));
        pref->PutInt(KEY_TEST_INT + "_" + std::to_string(i), i);
    }
    pref->FlushSync();
    for (int i = 0; i < 20; i++) {
        EXPECT_EQ(pref->GetString(KEY_TEST_STRING + "_" + std::to_string(i), ""), "string_" + std::to_string(i));
        EXPECT_EQ(pref->GetInt(KEY_TEST_INT + "_" + std::to_string(i), -1), i);
    }
}

} // namespace
