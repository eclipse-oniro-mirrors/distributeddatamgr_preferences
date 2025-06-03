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

#include <gtest/gtest.h>

#include <string>
#include <thread>

#include "log_print.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_file_operation.h"
#include "preferences_helper.h"
#include "preferences_xml_utils.h"

using namespace testing::ext;
using namespace OHOS::NativePreferences;

namespace {
class PreferencesFileTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PreferencesFileTest::SetUpTestCase(void)
{
}

void PreferencesFileTest::TearDownTestCase(void)
{
}

void PreferencesFileTest::SetUp(void)
{
}

void PreferencesFileTest::TearDown(void)
{
}

int PreferencesPutValue(std::shared_ptr<Preferences> pref, const std::string &intKey, int intValue,
    const std::string &strKey, const std::string &strValue)
{
    pref->PutInt(intKey, intValue);
    pref->PutString(strKey, strValue);
    int ret = pref->FlushSync();
    return ret;
}

/**
 * @tc.name: NativePreferencesFileTest_001
 * @tc.desc: normal testcase of backup file
 * @tc.type: FUNC
 * @tc.author: liulinna
 */
HWTEST_F(PreferencesFileTest, NativePreferencesFileTest_001, TestSize.Level0)
{
    std::string file = "/data/test/test";
    std::string backupFile = "/data/test/test.bak";

    std::remove(file.c_str());
    std::remove(backupFile.c_str());

    std::unordered_map<std::string, PreferencesValue> values;
    values.insert({"intKey", 10});
    PreferencesXmlUtils::WriteSettingXml(backupFile, "", values);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);
    int ret = pref->GetInt("intKey", 0);
    EXPECT_EQ(ret, 10);

    struct stat st = { 0 };
    ret = stat(file.c_str(), &st);
    EXPECT_EQ(ret, 0);
    ret = (st.st_mode & (S_IXUSR | S_IXGRP | S_IRWXO));
    EXPECT_EQ(ret, 0);

    pref = nullptr;
    ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: NativePreferencesFileTest_002
 * @tc.desc: normal testcase of file permission
 * @tc.type: FUNC
 * @tc.author: liulinna
 */
HWTEST_F(PreferencesFileTest, NativePreferencesFileTest_002, TestSize.Level0)
{
    std::string file = "/data/test/test";
    std::remove(file.c_str());

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);

    int ret = PreferencesPutValue(pref, "key1", 2, "key2", "test");
    EXPECT_EQ(ret, E_OK);

    struct stat st = { 0 };
    int result = stat(file.c_str(), &st);
    EXPECT_EQ(result, 0);
    result = st.st_mode & (S_IXUSR | S_IXGRP | S_IRWXO);
    EXPECT_EQ(result, 0);

    pref = nullptr;
    result = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(result, E_OK);
}

/**
 * @tc.name: NativePreferencesFileTest_003
 * @tc.desc: test FlushSync one times and five times
 * @tc.type: FUNC
 * @tc.author: liulinna
 */
HWTEST_F(PreferencesFileTest, NativePreferencesFileTest_003, TestSize.Level0)
{
    std::string file = "/data/test/test";
    int ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);

    ret = PreferencesPutValue(pref, "intKey", 1, "stringKey", "string1");
    EXPECT_EQ(ret, E_OK);

    EXPECT_EQ(1, pref->GetInt("intKey", 0));
    EXPECT_EQ("string1", pref->GetString("stringKey", ""));

    pref = nullptr;
    ret = PreferencesHelper::RemovePreferencesFromCache("/data/test/test_helper");
    EXPECT_EQ(ret, E_OK);

    errCode = E_OK;
    pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);

    EXPECT_EQ(1, pref->GetInt("intKey", 0));
    EXPECT_EQ("string1", pref->GetString("stringKey", ""));

    for (int i = 2; i <= 5; i++) {
        ret = PreferencesPutValue(pref, "intKey", i, "stringKey", "string" + std::to_string(i));
        EXPECT_EQ(ret, E_OK);
    }

    EXPECT_EQ(5, pref->GetInt("intKey", 0));
    EXPECT_EQ("string5", pref->GetString("stringKey", ""));

    pref = nullptr;
    ret = PreferencesHelper::RemovePreferencesFromCache("/data/test/test_helper");
    EXPECT_EQ(ret, E_OK);

    errCode = E_OK;
    pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);

    EXPECT_EQ(5, pref->GetInt("intKey", 0));
    EXPECT_EQ("string5", pref->GetString("stringKey", ""));

    pref = nullptr;
    ret = PreferencesHelper::DeletePreferences("/data/test/test_helper");
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: NativePreferencesFileTest_004
 * @tc.desc: test Flush one times and five times
 * @tc.type: FUNC
 * @tc.author: liulinna
 */
HWTEST_F(PreferencesFileTest, NativePreferencesFileTest_004, TestSize.Level3)
{
    std::string file = "/data/test/test";
    int ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);

    ret = PreferencesPutValue(pref, "intKey", 1, "stringKey", "string1");
    EXPECT_EQ(ret, E_OK);

    EXPECT_EQ(1, pref->GetInt("intKey", 0));
    EXPECT_EQ("string1", pref->GetString("stringKey", ""));

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    pref = nullptr;
    ret = PreferencesHelper::RemovePreferencesFromCache("/data/test/test_helper");
    EXPECT_EQ(ret, E_OK);

    errCode = E_OK;
    pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);

    EXPECT_EQ(1, pref->GetInt("intKey", 0));
    EXPECT_EQ("string1", pref->GetString("stringKey", ""));

    for (int i = 2; i <= 5; i++) {
        ret = PreferencesPutValue(pref, "intKey", i, "stringKey", "string" + std::to_string(i));
        EXPECT_EQ(ret, E_OK);
    }

    EXPECT_EQ(5, pref->GetInt("intKey", 0));
    EXPECT_EQ("string5", pref->GetString("stringKey", ""));

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    pref = nullptr;
    ret = PreferencesHelper::RemovePreferencesFromCache("/data/test/test_helper");
    EXPECT_EQ(ret, E_OK);

    errCode = E_OK;
    pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);

    EXPECT_EQ(5, pref->GetInt("intKey", 0));
    EXPECT_EQ("string5", pref->GetString("stringKey", ""));

    pref = nullptr;
    ret = PreferencesHelper::DeletePreferences("/data/test/test_helper");
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: NativePreferencesFileTest_005
 * @tc.desc: normal testcase of fallback logic
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesFileTest, NativePreferencesFileTest_005, TestSize.Level0)
{
    std::string path = "/data/test/file_test005";
    std::string file = path + "/test";
    int ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);
    ret = pref->GetInt("intKey", 0);
    EXPECT_EQ(ret, 0);
    ret = pref->GetInt("intKey1", 0);
    EXPECT_EQ(ret, 0);
    pref->PutInt("intKey", 2);

    OHOS::NativePreferences::Mkdir(path);
    std::unordered_map<std::string, PreferencesValue> values;
    values.insert({"intKey", 10});
    values.insert({"intKey1", 10});
    PreferencesXmlUtils::WriteSettingXml(file, "", values);
    ret = pref->GetInt("intKey", 0);
    EXPECT_EQ(ret, 2);
    ret = pref->GetInt("intKey1", 0);
    EXPECT_EQ(ret, 10);

    pref = nullptr;
    ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);
    rmdir(path.c_str());
}

/**
 * @tc.name: NativePreferencesFileTest_006
 * @tc.desc: normal testcase of fallback logic
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesFileTest, NativePreferencesFileTest_006, TestSize.Level0)
{
    std::string path = "/data/test/file_test006";
    std::string file = path + "/test";
    int ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(false, pref->HasKey("intKey"));
    EXPECT_EQ(false, pref->HasKey("intKey1"));
    pref->PutInt("intKey", 2);

    OHOS::NativePreferences::Mkdir(path);
    std::unordered_map<std::string, PreferencesValue> values;
    int value = 20;
    values.insert({"intKey", value});
    values.insert({"intKey1", value});
    PreferencesXmlUtils::WriteSettingXml(file, "", values);

    pref->FlushSync();

    std::unordered_map<std::string, PreferencesValue> allDatas;
    bool res = PreferencesXmlUtils::ReadSettingXml(file, "", allDatas);
    EXPECT_EQ(res, true);
    EXPECT_EQ(allDatas.empty(), false);
    auto it = allDatas.find("intKey");
    EXPECT_EQ(it != allDatas.end(), true);
    EXPECT_EQ(2, int(it->second));

    it = allDatas.find("intKey1");
    EXPECT_EQ(it != allDatas.end(), true);
    EXPECT_EQ(PreferencesValue(value) == it->second, true);

    pref = nullptr;
    ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);
    rmdir(path.c_str());
}

/**
 * @tc.name: NativePreferencesFileTest_007
 * @tc.desc: normal testcase of fallback logic
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesFileTest, NativePreferencesFileTest_007, TestSize.Level0)
{
    std::string file = "/data/test/test";
    int ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);
    pref->PutInt("intKey", 7);

    std::unordered_map<std::string, PreferencesValue> values;
    values.insert({"intKey", 70});
    values.insert({"intKey1", 70});
    PreferencesXmlUtils::WriteSettingXml(file, "", values);

    ret = pref->GetInt("intKey", 0);
    EXPECT_EQ(ret, 7);
    ret = pref->GetInt("intKey1", 0);
    EXPECT_EQ(ret, 70);

    pref = nullptr;
    ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: NativePreferencesFileTest_008
 * @tc.desc: normal testcase of fallback logic
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesFileTest, NativePreferencesFileTest_008, TestSize.Level0)
{
    std::string file = "/data/test/test";
    int ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(false, pref->HasKey("intKey"));
    EXPECT_EQ(false, pref->HasKey("intKey1"));
    pref->PutInt("intKey", 8);

    std::unordered_map<std::string, PreferencesValue> values;
    int value = 80;
    values.insert({"intKey", value});
    values.insert({"intKey1", value});
    PreferencesXmlUtils::WriteSettingXml(file, "", values);

    pref->FlushSync();

    std::unordered_map<std::string, PreferencesValue> allDatas;
    bool res = PreferencesXmlUtils::ReadSettingXml(file, "", allDatas);
    EXPECT_EQ(res, true);
    EXPECT_EQ(allDatas.empty(), false);
    auto it = allDatas.find("intKey");
    EXPECT_EQ(it != allDatas.end(), true);
    EXPECT_EQ(8, int(it->second));

    it = allDatas.find("intKey1");
    EXPECT_EQ(it != allDatas.end(), true);
    EXPECT_EQ(PreferencesValue(value) == it->second, true);

    pref = nullptr;
    ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: NativePreferencesFileTest_009
 * @tc.desc: normal testcase of fallback logic
 * @tc.type: FUNC
 */
HWTEST_F(PreferencesFileTest, NativePreferencesFileTest_009, TestSize.Level0)
{
    std::string file = "/data/test/test";
    int ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);
    pref->PutInt("intKey", 9);

    pref->FlushSync();

    std::unordered_map<std::string, PreferencesValue> allDatas;
    bool res = PreferencesXmlUtils::ReadSettingXml(file, "", allDatas);
    EXPECT_EQ(res, true);
    EXPECT_EQ(allDatas.empty(), false);
    auto it = allDatas.find("intKey");
    EXPECT_EQ(it != allDatas.end(), true);
    EXPECT_EQ(9, int(it->second));

    pref = nullptr;
    ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);
}
}