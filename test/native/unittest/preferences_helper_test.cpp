/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "preferences_helper.h"

#include <gtest/gtest.h>

#include <cctype>
#include <iostream>
#include <string>

#include "log_print.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_observer.h"

using namespace testing::ext;
using namespace OHOS::NativePreferences;

namespace {
class PreferencesHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PreferencesHelperTest::SetUpTestCase(void)
{
}

void PreferencesHelperTest::TearDownTestCase(void)
{
}

void PreferencesHelperTest::SetUp(void)
{
}

void PreferencesHelperTest::TearDown(void)
{
}

/**
 * @tc.name: NativePreferencesHelperTest_001
 * @tc.desc: normal testcase of DeletePreferences
 * @tc.type: FUNC
 * @tc.author: xiuhongju
 */
HWTEST_F(PreferencesHelperTest, NativePreferencesHelperTest_001, TestSize.Level0)
{
    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences("/data/test/test_helper", errCode);
    EXPECT_EQ(errCode, E_OK);

    pref->PutInt("key1", 2);
    pref->PutString("key2", "test");
    int ret = pref->FlushSync();
    EXPECT_EQ(ret, E_OK);

    pref = nullptr;

    ret = PreferencesHelper::RemovePreferencesFromCache("/data/test/test_helper");
    EXPECT_EQ(ret, E_OK);

    ret = PreferencesHelper::DeletePreferences("/data/test/test_helper");
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: NativePreferencesHelperTest_002
 * @tc.desc: error testcase of Preferences
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesHelperTest, NativePreferencesHelperTest_002, TestSize.Level0)
{
    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences("", errCode);
    EXPECT_EQ(errCode, E_EMPTY_FILE_PATH);

    pref = PreferencesHelper::GetPreferences("data/test/test_helper", errCode);
    EXPECT_EQ(errCode, E_RELATIVE_PATH);

    pref = PreferencesHelper::GetPreferences(":data/test/test_helper", errCode);
    EXPECT_EQ(errCode, E_RELATIVE_PATH);

    std::string path = "/data/test/test_helper" + std::string(4096, 't');
    pref = PreferencesHelper::GetPreferences(path, errCode);
    EXPECT_EQ(errCode, E_PATH_EXCEED_MAX_LENGTH);

    pref = PreferencesHelper::GetPreferences(":data/test/test_helper/", errCode);
    EXPECT_EQ(errCode, E_RELATIVE_PATH);
}

/**
 * @tc.name: NativePreferencesHelperTest_003
 * @tc.desc: error testcase of Preferences
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesHelperTest, NativePreferencesHelperTest_003, TestSize.Level0)
{
    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences("", errCode);
    EXPECT_EQ(errCode, E_EMPTY_FILE_PATH);

    pref = PreferencesHelper::GetPreferences("data/test/test_helper", errCode);
    EXPECT_EQ(errCode, E_RELATIVE_PATH);
}

/**
 * @tc.name: NativePreferencesHelperTest_004
 * @tc.desc: error testcase of DeletePreferences
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesHelperTest, NativePreferencesHelperTest_004, TestSize.Level0)
{
    int pref = PreferencesHelper::DeletePreferences("");
    EXPECT_EQ(pref, E_EMPTY_FILE_PATH);

    pref = PreferencesHelper::RemovePreferencesFromCache("");
    EXPECT_EQ(pref, E_EMPTY_FILE_PATH);
}

/**
 * @tc.name: NativePreferencesHelperTest_005
 * @tc.desc: error testcase of GetRealPath
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesHelperTest, NativePreferencesHelperTest_005, TestSize.Level0)
{
    Options option = Options("test300", "com.hmos.uttest", "");
    int errCode = E_OK;
    std::shared_ptr<Preferences> preferences = PreferencesHelper::GetPreferences(option, errCode);
    EXPECT_EQ(preferences, nullptr);
    preferences = nullptr;
}

/**
 * @tc.name: NativePreferencesHelperTest_006
 * @tc.desc: error testcase of GetRealPath
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesHelperTest, NativePreferencesHelperTest_006, TestSize.Level0)
{
    Options option = Options("/data/test/preferences/test01", "", "");
    int errCode = E_OK;
    std::shared_ptr<Preferences> preferences = PreferencesHelper::GetPreferences(option, errCode);
    EXPECT_EQ(errCode, E_OK);
    preferences = nullptr;
}

/**
 * @tc.name: NativePreferencesHelperTestNormal
 * @tc.desc: normal testcase of DeletePreferences
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesHelperTest, NativePreferencesHelperTestNormal, TestSize.Level0)
{
    int errCode = E_OK;
    std::string path = "/data/test/test_helper_normal";
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(path, errCode);
    EXPECT_EQ(errCode, E_OK);

    pref->PutInt("normal_key1", 200);
    pref->PutString("normal_key2", "test_normal");
    int ret = pref->FlushSync();
    EXPECT_EQ(ret, E_OK);
    auto resStr = pref->GetString("normal_key2", "string_default");
    EXPECT_EQ(resStr, "test_normal");
    auto resInt = pref->GetInt("normal_key1", 0);
    EXPECT_EQ(resInt, 200);

    ret = PreferencesHelper::DeletePreferences(path);
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: NativeCreateMultipleHelper
 * @tc.desc: normal testcase of create multiple helper
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesHelperTest, NativeCreateMultipleHelper, TestSize.Level0)
{
    int errCode = E_OK;
    std::string path = "/data/test/test_helper_normal";
    for (int i = 0; i < 50; i++) {
        std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(path + std::to_string(i), errCode);
        EXPECT_EQ(errCode, E_OK);
        pref->PutInt("normal_key1_test" + std::to_string(i), i);
        pref->PutString("normal_key2_test" + std::to_string(i), "test_normal_" + std::to_string(i));
        int ret = pref->FlushSync();
        EXPECT_EQ(ret, E_OK);
    }
    for (int i = 0; i < 50; i++) {
        std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(path + std::to_string(i), errCode);
        EXPECT_EQ(errCode, E_OK);
        auto resStr = pref->GetString("normal_key2_test" + std::to_string(i), "string_default");
        EXPECT_EQ(resStr, "test_normal_" + std::to_string(i));
        auto resInt = pref->GetInt("normal_key1_test" + std::to_string(i), 0);
        EXPECT_EQ(resInt, i);
        int ret = PreferencesHelper::DeletePreferences(path + std::to_string(i));
        EXPECT_EQ(ret, E_OK);
    }
}

/**
 * @tc.name: NativePreferencesHelperAndRemoveCache
 * @tc.desc: normal testcase of RemoveCache and DeletePreferences
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesHelperTest, NativePreferencesHelperAndRemoveCache, TestSize.Level0)
{
    int errCode = E_OK;
    std::string path = "/data/test/helper_normal";
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(path, errCode);
    EXPECT_EQ(errCode, E_OK);

    pref->PutInt("normal_key1", 200);
    pref->PutString("normal_key2", "test_normal");
    int ret = pref->FlushSync();
    EXPECT_EQ(ret, E_OK);
    auto resStr = pref->GetString("normal_key2", "string_default");
    EXPECT_EQ(resStr, "test_normal");
    auto resInt = pref->GetInt("normal_key1", 0);
    EXPECT_EQ(resInt, 200);

    ret = PreferencesHelper::RemovePreferencesFromCache();
    EXPECT_EQ(ret, E_OK);

    pref = PreferencesHelper::GetPreferences(path, errCode);
    EXPECT_EQ(errCode, E_OK);
    resStr = pref->GetString("normal_key2", "string_default");
    EXPECT_EQ(resStr, "test_normal");
    resInt = pref->GetInt("normal_key1", 0);
    EXPECT_EQ(resInt, 200);

    ret = PreferencesHelper::DeletePreferences(path);
    EXPECT_EQ(ret, E_OK);
}
}
