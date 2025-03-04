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
#include <cctype>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>

#include <gtest/gtest.h>
#include "log_print.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_file_operation.h"
#include "preferences_helper.h"
#include "preferences_observer.h"
#include "preferences_value.h"

using namespace testing::ext;
using namespace OHOS::NativePreferences;

namespace {

static void CreateDirectoryRecursively(const std::string &path)
{
    std::string::size_type pos = path.find_last_of('/');
    if (pos == std::string::npos || path.front() != '/') {
        printf("path can not be relative path.\n");
    }
    std::string dir = path.substr(0, pos);

    std::string tempDirectory = dir;
    std::vector<std::string> directories;

    pos = tempDirectory.find('/');
    while (pos != std::string::npos) {
        std::string directory = tempDirectory.substr(0, pos);
        if (!directory.empty()) {
            directories.push_back(directory);
        }
        tempDirectory = tempDirectory.substr(pos + 1);
        pos = tempDirectory.find('/');
    }
    directories.push_back(tempDirectory);

    std::string databaseDirectory;
    for (const std::string& directory : directories) {
        databaseDirectory = databaseDirectory + "/" + directory;
        if (OHOS::NativePreferences::Access(databaseDirectory.c_str()) != F_OK) {
            if (OHOS::NativePreferences::Mkdir(databaseDirectory)) {
                printf("failed to mkdir, errno %d, %s \n", errno, databaseDirectory.c_str());
                return;
            }
        }
    }
}

static bool IsFileExist(const std::string &path)
{
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

class PreferencesStorageTypeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PreferencesStorageTypeTest::SetUpTestCase(void)
{
    CreateDirectoryRecursively("/data/test/");
}

void PreferencesStorageTypeTest::TearDownTestCase(void)
{
}

void PreferencesStorageTypeTest::SetUp(void)
{
    CreateDirectoryRecursively("/data/test/");
}

void PreferencesStorageTypeTest::TearDown(void)
{
}

/**
 * @tc.name: StorageTypeBaseTest000
 * @tc.desc: test IsStorageTypeSupported api
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeBaseTest000, TestSize.Level0)
{
    ASSERT_EQ(PreferencesHelper::IsStorageTypeSupported(StorageType::XML), true);
    ASSERT_EQ(PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV), false);
}

/**
 * @tc.name: StorageTypeBaseTest002
 * @tc.desc: base test, use different storage type to get preferences and check file type
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeBaseTest002, TestSize.Level0)
{
    printf("test with xml\n");
    // default option constructor
    int errCode = E_OK;
    std::string filePath = "/data/test/XML002_1";
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(filePath, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    ASSERT_EQ(IsFileExist(filePath + ".db"), false);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);

    filePath = "/data/test/XML002_2";
    Options option = Options(filePath, "", "", false);
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    ASSERT_EQ(IsFileExist(filePath + ".db"), false);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);

    filePath = "/data/test/GSKV002";
    Options option2 = Options(filePath, "", "", true);
    pref = PreferencesHelper::GetPreferences(option2, errCode);
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        printf("test with GSKV\n");
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(IsFileExist(filePath), false);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
    } else {
        ASSERT_EQ(errCode, E_NOT_SUPPORTED);
    }
}

/**
 * @tc.name: StorageTypeBaseTest004
 * @tc.desc: base test, test get again with different mode
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeBaseTest004, TestSize.Level0)
{
    printf("test with xml\n");
    // xml exist and open with GSKV mode
    int errCode = E_OK;
    std::string filePath = "/data/test/XML004";
    Options option = Options(filePath, "", "", false);
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    option.isEnhance = true;
    // in cache, not check type, just return
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    // not in cahce, invalid storage type
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_NOT_SUPPORTED);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);

    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        printf("test with GSKV\n");
        // GSKV exist and open with xml mode
        filePath = "/data/test/GSKV004";
        option.filePath = filePath;
        option.isEnhance = true;
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(IsFileExist(filePath), false);
        option.isEnhance = false;
        // in cache, not check type, just return
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        // not in cahce, invalid storage type
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_NOT_SUPPORTED);
        ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
    }
}

/**
 * @tc.name: StorageTypeCombineTest005
 * @tc.desc: combine test, test xml mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest005, TestSize.Level0)
{
    // new with xml mode in white list
    printf("test with xml\n");
    int errCode = E_OK;
    std::string filePath = "/data/test/White005";
    Options option = Options(filePath, "abcuttestabc", ""); // XML type
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(errCode, E_OK);
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        printf("test with GSKV\n");
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(IsFileExist(filePath), false);
    } else {
        ASSERT_EQ(IsFileExist(filePath), true);
        ASSERT_EQ(IsFileExist(filePath + ".db"), false);
    }
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);

    // not white
    filePath = "/data/test/Normal005";
    option.filePath = filePath;
    option.bundleName = "abcabc";
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    ASSERT_EQ(IsFileExist(filePath + ".db"), false);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: StorageTypeCombineTest006
 * @tc.desc: combine test, test xml mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest006, TestSize.Level0)
{
    // new with xml exists in xml mode
    // create xml firstly
    int errCode = E_OK;
    std::string filePath = "/data/test/XML006";
    Options option = Options(filePath, "", "");
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);

    // in white list, when xml exist, open with xml mode, it should be xml even in enhance
    option.isEnhance = false;
    option.bundleName = "abcuttestabc";
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        printf("test with GSKV\n");
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(IsFileExist(filePath), true);
    }

    // not in white list, open with xml mode when xml exists
    Options option2 = Options(filePath, "abc", "", false);
    pref = PreferencesHelper::GetPreferences(option2, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    ASSERT_EQ(IsFileExist(filePath + ".db"), false);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: StorageTypeCombineTest007
 * @tc.desc: combine test, test xml mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest007, TestSize.Level0)
{
    // create fake GSKV firstly
    int errCode = E_OK;
    std::string filePath = "/data/test/XML007";
    Options option = Options(filePath + ".db", "", "");
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(IsFileExist(filePath + ".db"), true);
    ASSERT_EQ(IsFileExist(filePath), false);
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (!isEnhance) {
        // open with white list in xml mode
        // it should be xml
        Options option1 = Options(filePath, "abcuttestabc", "", false);
        pref = PreferencesHelper::GetPreferences(option1, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(pref->PutString("key", "value"), E_OK);
        ASSERT_EQ(pref->FlushSync(), E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(IsFileExist(filePath), true);
    }

    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath + ".db"), E_OK);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);

    if (isEnhance) {
        // create GSKV firstly
        printf("test with GSKV\n");
        filePath = "/data/test/GSKV007";
        option.filePath = filePath;
        option.isEnhance = true;
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);

        // open in xml mode with white list, it should be GSKV
        option.bundleName = "abcuttestabc";
        option.isEnhance = false;
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(IsFileExist(filePath), false);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
    }
}

/**
 * @tc.name: StorageTypeCombineTest008
 * @tc.desc: combine test, test xml mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest008, TestSize.Level0)
{
    // create fake GSKV firstly
    int errCode = E_OK;
    printf("test with xml\n");
    std::string filePath = "/data/test/XML008";
    Options option1 = Options(filePath + ".db", "", "");
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option1, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(IsFileExist(filePath + ".db"), true);
    ASSERT_EQ(IsFileExist(filePath), false);

    // open with xml mode, not in white list
    // GSKV exists, should return E_NOT_SUPPORTED
    Options option = Options(filePath, "abc", "", false);
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_NOT_SUPPORTED);
    ASSERT_EQ(IsFileExist(filePath), false);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath + ".db"), E_OK);

    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        // same case in enhance
        printf("test with GSKV\n");
        filePath = "/data/test/GSKV008";
        option.filePath = filePath;
        option.isEnhance = true;
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);

        option.isEnhance = false;
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_NOT_SUPPORTED);
        ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
    }
}

/**
 * @tc.name: StorageTypeCombineTest009
 * @tc.desc: combine test, test GSKV mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest009, TestSize.Level0)
{
    // new with GSKV mode
    // white list
    int errCode = E_OK;
    std::string filePath = "/data/test/White009";
    Options option = Options(filePath, "abcuttestabc", "", true);
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        printf("test with GSKV\n");
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(IsFileExist(filePath), false);
    } else {
        ASSERT_EQ(IsFileExist(filePath + ".db"), false);
        ASSERT_EQ(IsFileExist(filePath), true);
    }
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);

    // new with GSKV mode and not in white list
    filePath = "/data/test/Normal009";
    option.filePath = filePath;
    option.bundleName = "abc";
    pref = PreferencesHelper::GetPreferences(option, errCode);

    if (isEnhance) {
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
        ASSERT_EQ(IsFileExist(filePath), false);
        ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
    } else {
        ASSERT_EQ(errCode, E_NOT_SUPPORTED);
    }
}

/**
 * @tc.name: StorageTypeCombineTest010
 * @tc.desc: combine test, test GSKV mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest010, TestSize.Level0)
{
    // xml exists when GSKV mode
    // create xml firstly
    int errCode = E_OK;
    std::string filePath = "/data/test/Test010";
    Options option = Options(filePath, "", "");
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    ASSERT_EQ(IsFileExist(filePath + ".db"), false);

    // open with white list, it should be xml even in enhance
    option.bundleName = "abcuttestabc";
    option.isEnhance = true;
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(IsFileExist(filePath), true);
    ASSERT_EQ(IsFileExist(filePath + ".db"), false);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);

    // when not in white list
    option.bundleName = "abc";
    pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_NOT_SUPPORTED);
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
}

/**
 * @tc.name: StorageTypeCombineTest011
 * @tc.desc: combine test, test GSKV mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest011, TestSize.Level0)
{
    // GSKV exists, open with GSKV mode
    // create fake GSKV firstly
    int errCode = E_OK;
    std::string filePath = "/data/test/Test011";
    std::string filePathFakeKV = "/data/test/Test011.db";
    Options option = Options(filePathFakeKV, "", "");
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
    ASSERT_EQ(errCode, E_OK);
    ASSERT_EQ(pref->PutString("key", "value"), E_OK);
    ASSERT_EQ(pref->FlushSync(), E_OK);
    ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePathFakeKV), E_OK);
    ASSERT_EQ(IsFileExist(filePath), false);
    ASSERT_EQ(IsFileExist(filePathFakeKV), true);

    // open in white list when not enhance
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (!isEnhance) {
        option.bundleName = "uttest";
        option.isEnhance = true;
        option.filePath = filePath;
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        // when not white list
        option.bundleName = "abc";
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_NOT_SUPPORTED);
    }
    ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath + ".db"), E_OK);
}

/**
 * @tc.name: StorageTypeCombineTest012
 * @tc.desc: combine test, test GSKV mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeCombineTest012, TestSize.Level0)
{
    // GSKV exists, open with GSKV mode
    // it should be GSKV enven not in white list
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        // create GSKV firstly
        int errCode = E_OK;
        std::string filePath = "/data/test/Test012";
        Options option = Options(filePath, "", "", true);
        std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(IsFileExist(filePath), false);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);

        option.bundleName = "uttest";
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(IsFileExist(filePath), false);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);

        option.bundleName = "abc";
        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(IsFileExist(filePath), false);
        ASSERT_EQ(IsFileExist(filePath + ".db"), true);
    }
}

/**
 * @tc.name: StorageTypeApiTest013
 * @tc.desc: api test, test GSKV mode in different cases
 * @tc.type: FUNC
 * @tc.author: huangboxin
 */
HWTEST_F(PreferencesStorageTypeTest, StorageTypeApiTest013, TestSize.Level0)
{
    bool isEnhance = PreferencesHelper::IsStorageTypeSupported(StorageType::GSKV);
    if (isEnhance) {
        int errCode = E_OK;
        std::string filePath = "/data/test/Test013";
        Options option = Options(filePath, "", "", true);
        std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        for (int i = 0; i < 100; i++) {
            ASSERT_EQ(pref->PutString("test013_key_" + std::to_string(i), "test013_value_" + std::to_string(i)), E_OK);
        }
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);

        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        for (int i = 0; i < 100; i++) {
            std::string expValue = "test013_value_" + std::to_string(i);
            ASSERT_EQ(pref->GetString("test013_key_" + std::to_string(i), "def"), expValue);
        }
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);

        pref = PreferencesHelper::GetPreferences(option, errCode);
        ASSERT_EQ(errCode, E_OK);
        auto set = pref->GetAll();
        ASSERT_EQ(set.size(), 100);
        ASSERT_EQ(pref->Clear(), E_OK);
        auto set2 = pref->GetAll();
        ASSERT_EQ(set2.size(), 0);
        ASSERT_EQ(PreferencesHelper::RemovePreferencesFromCache(filePath), E_OK);
        ASSERT_EQ(PreferencesHelper::DeletePreferences(filePath), E_OK);
    }
}

} // namespace