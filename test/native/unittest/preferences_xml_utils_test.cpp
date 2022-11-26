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

#include <string>

using namespace testing::ext;
using namespace OHOS::NativePreferences;

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
* @tc.name: NativePreferencesImplTest_001
* @tc.desc: normal testcase of DeletePreferences
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, NativePreferencesHelperTest_001, TestSize.Level1)
{
    std::vector<Element> settings = {};
    bool ret = PreferencesXmlUtils::ReadSettingXml("", settings);
    EXPECT_EQ(ret, false);

    std::string path = "/data/test/test_helper" + std::string(4096, 't');
    ret = PreferencesXmlUtils::ReadSettingXml(path, settings);
    EXPECT_EQ(ret, false);

    ret = PreferencesXmlUtils::ReadSettingXml("data/test/test_helper", settings);
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: NativePreferencesImplTest_002
* @tc.desc: normal testcase of DeletePreferences
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, NativePreferencesHelperTest_002, TestSize.Level1)
{
    std::vector<Element> settings = {};
    bool ret = PreferencesXmlUtils::ReadSettingXml("", settings);
    EXPECT_EQ(ret, false);

    std::string path = "/data/test/test_helper" + std::string(4096, 't');
    ret = PreferencesXmlUtils::ReadSettingXml(path, settings);
    EXPECT_EQ(ret, false);

    ret = PreferencesXmlUtils::ReadSettingXml("data/test/test_helper", settings);
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: StringNodeElementTest_001
* @tc.desc: StringNodeElement testcase of PreferencesXmlUtils
* @tc.type: FUNC
*/
HWTEST_F(PreferencesXmlUtilsTest, StringNodeElementTest_001, TestSize.Level1)
{
    std::string file = "/data/test/test";
    std::remove(file.c_str());

    std::vector<Element> settings;
    Element elem;
    elem.key_ = "stringKey";
    elem.tag_ = std::string("string");
    elem.value_ = "test";
    settings.push_back(elem);
    PreferencesXmlUtils::WriteSettingXml(file, settings);

    bool ret = PreferencesXmlUtils::ReadSettingXml(file, settings);
    EXPECT_EQ(ret, false);
}
