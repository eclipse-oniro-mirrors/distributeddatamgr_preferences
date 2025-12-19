/*
* Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "preferences_xml_utils.h"

#include <gtest/gtest.h>

#include <fstream>
#include <string>

#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_helper.h"
#include "preferences_utils.h"

using namespace testing::ext;
using namespace OHOS::NativePreferences;

namespace {
class PreferencesXmlUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PreferencesXmlUtilsTest::SetUpTestCase(void)
{
}

void PreferencesXmlUtilsTest::TearDownTestCase(void)
{
}

void PreferencesXmlUtilsTest::SetUp(void)
{
}

void PreferencesXmlUtilsTest::TearDown(void)
{
}

/**
* @tc.name: ReadSettingXmlTest_001
* @tc.desc: normal testcase of ReadSettingXml
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, ReadSettingXmlTest_001, TestSize.Level0)
{
    std::unordered_map<std::string, PreferencesValue> allDatas;
    bool ret = PreferencesXmlUtils::ReadSettingXml("", "", allDatas);
    EXPECT_EQ(ret, false);

    std::string path = "/data/test/test_helper" + std::string(4096, 't');
    ret = PreferencesXmlUtils::ReadSettingXml(path, "", allDatas);
    EXPECT_EQ(ret, false);

    ret = PreferencesXmlUtils::ReadSettingXml("data/test/test_helper", "", allDatas);
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: ReadSettingXmlTest_002
* @tc.desc: ReadSettingXml testcase of PreferencesXmlUtils, reading a corrupt file
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, ReadSettingXmlTest_002, TestSize.Level0)
{
    std::string fileName = "/data/test/test01";

    std::ofstream oss(fileName);
    oss << "corrupted";

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(fileName, errCode);
    EXPECT_EQ(errCode, E_OK);

    int ret = PreferencesHelper::DeletePreferences(fileName);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: ReadSettingXmlTest_003
* @tc.desc: ReadSettingXml testcase of PreferencesXmlUtils, no empty dataGroupId
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, ReadSettingXmlTest_003, TestSize.Level0)
{
    std::string file = "/data/test/test01";

    std::unordered_map<std::string, PreferencesValue> values;
    values.insert({"testKey", 999});
    PreferencesXmlUtils::WriteSettingXml(file, "", values);

    std::unordered_map<std::string, PreferencesValue> allDatas;
    bool ret = PreferencesXmlUtils::ReadSettingXml(file, "", allDatas);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(allDatas.empty(), false);
    auto it = allDatas.find("testKey");
    EXPECT_EQ(it != allDatas.end(), true);
    EXPECT_EQ(999, int(it->second));

    std::remove(file.c_str());
}

/**
* @tc.name: UnnormalReadSettingXml_001
* @tc.desc: unnormal testcase of ReadSettingXml
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, UnnormalReadSettingXml_001, TestSize.Level0)
{
    std::unordered_map<std::string, PreferencesValue> values;
    PreferencesXmlUtils::WriteSettingXml("", "", values);
    bool ret = PreferencesXmlUtils::ReadSettingXml("", "", values);
    EXPECT_EQ(ret, false);

    std::string path = "/data/test/test_helper" + std::string(4096, 't');
    ret = PreferencesXmlUtils::ReadSettingXml(path, "", values);
    EXPECT_EQ(ret, false);

    ret = PreferencesXmlUtils::ReadSettingXml("data/test/test_helper", "", values);
    EXPECT_EQ(ret, false);

    values.insert({});
    path = "data/test/test_helper";
    PreferencesXmlUtils::WriteSettingXml(path, "", values);
    ret = PreferencesXmlUtils::ReadSettingXml(path, "", values);
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: StringNodeElementTest_001
* @tc.desc: StringNodeElement testcase of PreferencesXmlUtils
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, StringNodeElementTest_001, TestSize.Level0)
{
    std::string file = "/data/test/test01";
    std::remove(file.c_str());

    std::unordered_map<std::string, PreferencesValue> values;
    values.insert({"stringKey", "test"});
    PreferencesXmlUtils::WriteSettingXml(file, "", values);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);
    std::string retString = pref->GetString("stringKey", "");
    EXPECT_EQ(retString, "test");

    int ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: ArrayNodeElementTest_001
* @tc.desc: ArrayNodeElement testcase of PreferencesXmlUtils
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, ArrayNodeElementTest_001, TestSize.Level0)
{
    std::string file = "/data/test/test02";
    std::remove(file.c_str());
    std::unordered_map<std::string, PreferencesValue> values;
    std::vector<std::string> inputStringArray = { "test_child1", "test_child2" };
    values.insert({"stringArrayKey", inputStringArray});
    PreferencesXmlUtils::WriteSettingXml(file, "", values);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);

    auto retStringArray = pref->Get("stringArrayKey", "");
    EXPECT_EQ(retStringArray.operator std::vector<std::string>(), inputStringArray);

    int ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: ArrayNodeElementTest_001
* @tc.desc: ArrayNodeElement testcase of PreferencesXmlUtils
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, ArrayNodeElementTest_002, TestSize.Level0)
{
    std::string file = "/data/test/test03";
    std::remove(file.c_str());
    std::unordered_map<std::string, PreferencesValue> values;
    std::vector<double> inputDoubleArray = { 1.0, 2.0 };
    values.insert({"doubleArrayKey", inputDoubleArray});
    PreferencesXmlUtils::WriteSettingXml(file, "", values);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);

    auto retDoubleArray = pref->Get("doubleArrayKey", 10.0);
    EXPECT_EQ(retDoubleArray.operator std::vector<double>(), inputDoubleArray);

    int ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: ArrayNodeElementTest_003
* @tc.desc: ArrayNodeElement testcase of PreferencesXmlUtils
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, ArrayNodeElementTest_003, TestSize.Level0)
{
    std::string file = "/data/test/test04";
    std::remove(file.c_str());
    std::unordered_map<std::string, PreferencesValue> values;
    std::vector<bool> inputBoolArray = { false, true };
    values.insert({"boolArrayKey", inputBoolArray});
    PreferencesXmlUtils::WriteSettingXml(file, "", values);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);

    auto retBoolArray = pref->Get("boolArrayKey", false);
    EXPECT_EQ(retBoolArray.operator std::vector<bool>(), inputBoolArray);

    int ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: ArrayNodeElementTest_004
* @tc.desc: ArrayNodeElement testcase of PreferencesXmlUtils
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, ArrayNodeElementTest_004, TestSize.Level0)
{
    std::string file = "/data/test/testttt05";
    std::remove(file.c_str());
    std::unordered_map<std::string, PreferencesValue> values;
    std::vector<bool> value = {};
    values.insert({"boolArrayKey", value});
    PreferencesXmlUtils::WriteSettingXml(file, "", values);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);

    auto retBoolArray = pref->Get("boolArrayKey", false);
    EXPECT_EQ(retBoolArray.IsBoolArray(), true);
    auto array = static_cast<std::vector<bool>>(retBoolArray);
    EXPECT_EQ(array.empty(), true);

    int ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: ArrayNodeElementTest_005
* @tc.desc: ArrayNodeElement testcase of PreferencesXmlUtils
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, ArrayNodeElementTest_005, TestSize.Level0)
{
    std::string file = "/data/test/testttt06";
    std::remove(file.c_str());
    std::unordered_map<std::string, PreferencesValue> values;
    std::vector<std::string> value = {};
    values.insert({"stringArrayKey", value});
    PreferencesXmlUtils::WriteSettingXml(file, "", values);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);

    auto retStringArray = pref->Get("stringArrayKey", false);
    EXPECT_EQ(retStringArray.IsStringArray(), true);
    auto array = static_cast<std::vector<std::string>>(retStringArray);
    EXPECT_EQ(array.empty(), true);

    int ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: ArrayNodeElementTest_006
* @tc.desc: ArrayNodeElement testcase of PreferencesXmlUtils
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, ArrayNodeElementTest_006, TestSize.Level0)
{
    std::string file = "/data/test/test07";
    std::remove(file.c_str());
    std::unordered_map<std::string, PreferencesValue> values;
    std::vector<double> value = {};
    values.insert({"doubleArrayKey", value});
    PreferencesXmlUtils::WriteSettingXml(file, "", values);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(file, errCode);
    EXPECT_EQ(errCode, E_OK);

    auto retDoubleArray = pref->Get("doubleArrayKey", 0);
    EXPECT_EQ(retDoubleArray.IsDoubleArray(), true);
    auto array = static_cast<std::vector<double>>(retDoubleArray);
    EXPECT_EQ(array.empty(), true);

    int ret = PreferencesHelper::DeletePreferences(file);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: RenameToBrokenFileTest_001
* @tc.desc: RenameToBrokenFile testcase of PreferencesXmlUtils
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, RenameToBrokenFileTest_001, TestSize.Level0)
{
    std::string fileName = "/data/test/test01";
    // construct an unreadable file
    std::ofstream oss(fileName);
    oss << "corrupted";

    std::unordered_map<std::string, PreferencesValue> values;
    values.insert({"intKey", 2});
    PreferencesXmlUtils::WriteSettingXml(PreferencesUtils::MakeFilePath(fileName, PreferencesUtils::STR_BACKUP), "",
        values);

    int errCode = E_OK;
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(fileName, errCode);
    EXPECT_EQ(errCode, E_OK);

    int value = pref->Get("intKey", 0);
    EXPECT_EQ(value, 2);

    int ret = PreferencesHelper::DeletePreferences(fileName);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: ReadSettingXmlTest_004
* @tc.desc: RenameToBrokenFile testcase of PreferencesXmlUtils
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, ReadSettingXmlTest_004, TestSize.Level0)
{
    std::string fileName = "/data/test/test01";
    // construct an unreadable file
    std::ofstream oss(fileName);
    oss << "corrupted";

    std::ofstream ossBak(PreferencesUtils::MakeFilePath(fileName, PreferencesUtils::STR_BACKUP));
    ossBak << "corruptedBak";

    std::unordered_map<std::string, PreferencesValue> values;
    bool res = PreferencesXmlUtils::ReadSettingXml(fileName, "", values);
    EXPECT_EQ(res, false);

    int ret = PreferencesHelper::DeletePreferences(fileName);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: WriteSettingXmlWhenFileIsNotExistTest_001
* @tc.desc: RenameToBrokenFile testcase of PreferencesXmlUtils
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, WriteSettingXmlWhenFileIsNotExistTest_001, TestSize.Level0)
{
    std::string fileName = "/data/test/test01";
    std::unordered_map<std::string, PreferencesValue> values;
    values.insert({"stringKey", ""});
    bool result = PreferencesXmlUtils::WriteSettingXml("/data/test/preferences/testttt01", "", values);
    EXPECT_EQ(result, false);

    result = PreferencesXmlUtils::WriteSettingXml(fileName, "", values);
    EXPECT_EQ(result, true);
}

/**
* @tc.name: ReadSettingXmlTest_005
* @tc.desc: Restore testcase of PreferencesXmlUtils
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, ReadSettingXmlTest_005, TestSize.Level0)
{
    std::string fileName = "/data/test/test01";
    std::string bakFileName = "/data/test/test01.bak";
    // construct an unreadable file
    std::ofstream oss(fileName);
    oss << "corrupted";

    std::unordered_map<std::string, PreferencesValue> values;
    values.insert({"stringKey", ""});
    bool result = PreferencesXmlUtils::WriteSettingXml(
        PreferencesUtils::MakeFilePath(fileName, PreferencesUtils::STR_BACKUP), "", values);
    EXPECT_EQ(result, true);

    std::unordered_map<std::string, PreferencesValue> allDatas;
    bool res = PreferencesXmlUtils::ReadSettingXml(fileName, "", values);
    EXPECT_EQ(res, true);

    int ret = PreferencesHelper::DeletePreferences(fileName);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: ReadSettingXmlTest_006
* @tc.desc: Test for unsupported data type in the element
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, ReadSettingXmlTest_006, TestSize.Level1)
{
    std::string fileName = "/data/test/test01";
    // construct an abnormal file
    std::string abnormalContent = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<preferences version=\"1.0\"><text key=\"test_abnormal_key\" value=\"1\"/></preferences>";
    std::ofstream file(fileName);
    file << abnormalContent;
    file.close();

    std::unordered_map<std::string, PreferencesValue> values;
    bool res = PreferencesXmlUtils::ReadSettingXml(fileName, "", values);
    EXPECT_EQ(res, false);

    int ret = PreferencesHelper::DeletePreferences(fileName);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: ReadSettingXmlTest_007
* @tc.desc: Test for unsupported data types and no key in the element
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, ReadSettingXmlTest_007, TestSize.Level1)
{
    std::string fileName = "/data/test/test01";
    // construct an abnormal file
    std::string abnormalContent = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<preferences version=\"1.0\"><text value=\"1\"/></preferences>";
    std::ofstream file(fileName);
    file << abnormalContent;
    file.close();

    std::unordered_map<std::string, PreferencesValue> values;
    bool res = PreferencesXmlUtils::ReadSettingXml(fileName, "", values);
    EXPECT_EQ(res, false);

    int ret = PreferencesHelper::DeletePreferences(fileName);
    EXPECT_EQ(ret, E_OK);
}

/**
* @tc.name: WriteSettingXmlTestIntVector
* @tc.desc: Test for writing and reading std::vector<int> to/from XML.
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, WriteSettingXmlTestIntVector, TestSize.Level0)
{
    std::string file = "/data/test/testIntVector";
    std::unordered_map<std::string, PreferencesValue> values;
    std::vector<int> intVec = {1, 2, 3, 42};
    values.insert({"testKey", intVec});
    PreferencesXmlUtils::WriteSettingXml(file, "", values);

    std::unordered_map<std::string, PreferencesValue> allDatas;
    bool ret = PreferencesXmlUtils::ReadSettingXml(file, "", allDatas);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(allDatas.empty(), false);
    auto it = allDatas.find("testKey");
    EXPECT_EQ(it != allDatas.end(), true);
    auto& readValue = it->second.value_;
    // Verify the read value matches the original vector<int>
    bool isEqual = std::visit([&intVec](const auto& val) {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, std::vector<int>>) {
            return val == intVec;
        } else {
            return false;
        }
    }, readValue);

    EXPECT_EQ(isEqual, true);
    std::remove(file.c_str());
}

/**
* @tc.name: WriteSettingXmlTestInt64Vector
* @tc.desc: Test for writing and reading std::vector<int64_t> to/from XML.
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, WriteSettingXmlTestInt64Vector, TestSize.Level0)
{
    std::string file = "/data/test/testInt64Vector";
    std::unordered_map<std::string, PreferencesValue> values;
    std::vector<int64_t> int64Vec = {1LL, 2LL, 3LL, 42LL};
    values.insert({"testKey", int64Vec});
    PreferencesXmlUtils::WriteSettingXml(file, "", values);

    std::unordered_map<std::string, PreferencesValue> allDatas;
    bool ret = PreferencesXmlUtils::ReadSettingXml(file, "", allDatas);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(allDatas.empty(), false);
    auto it = allDatas.find("testKey");
    EXPECT_EQ(it != allDatas.end(), true);
    auto& readValue = it->second.value_;
    // Verify the read value matches the original vector<int64_t>
    bool isEqual = std::visit([&int64Vec](const auto& val) {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, std::vector<int64_t>>) {
            return val == int64Vec;
        } else {
            return false;
        }
    }, readValue);
    EXPECT_EQ(isEqual, true);
    std::remove(file.c_str());
}
}
