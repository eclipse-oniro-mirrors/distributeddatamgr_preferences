/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <fcntl.h>
#include <filesystem>
#include <functional>
#include <gtest/gtest.h>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <thread>
#include <vector>

#include "log_print.h"
#include "oh_preferences_impl.h"
#include "oh_preferences.h"
#include "oh_preferences_err_code.h"
#include "oh_preferences_value.h"
#include "oh_preferences_option.h"
#include "preferences_helper.h"
 
using namespace testing::ext;

using namespace OHOS::PreferencesNdk;
using namespace OHOS::NativePreferences;
namespace {
class PreferencesNdkTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PreferencesNdkTest::SetUpTestCase(void) {}
void PreferencesNdkTest::TearDownTestCase(void) {}

void PreferencesNdkTest::SetUp(void) {}

void PreferencesNdkTest::TearDown(void) {}

enum class PrefDataType { UNASSIGNED, INT, STRING, BOOL };
 
static OH_PreferencesOption *GetCommonOption()
{
    OH_PreferencesOption *option = OH_PreferencesOption_Create();
    EXPECT_EQ(OH_PreferencesOption_SetFilePath(option, "/data/test/testdb"), PREFERENCES_OK);
    EXPECT_EQ(OH_PreferencesOption_SetBundleName(option, "com.uttest"), PREFERENCES_OK);
    EXPECT_EQ(OH_PreferencesOption_SetDataGroupId(option, "123"), PREFERENCES_OK);
    return option;
}
 
std::map<std::string, int> g_intDataMap = {
    {"ndktest_int_key_1", -2147483648},
    {"ndktest_int_key_2", -1},
    {"ndktest_int_key_3", 0},
    {"ndktest_int_key_4", 1},
    {"ndktest_int_key_5", 2147483647}
};
 
std::map<std::string, std::string> g_stringDataMap = {
    {"ndktest_string_key_1", "2679b2c70120214984b3aec34fc849dc996f40e3cdb60f3b3eaf8abe2559439a"},
    {"ndktest_string_key_2", "+88780079687688"},
    {"ndktest_string_key_3", "/data/storage/el2/base/files/Thumbnail_1717209543267.jpg"},
    {"ndktest_string_key_4", "A NEW PHONE"},
    {"ndktest_string_key_5", "https://upfile-drcn.platform.hicloud.com/"}
};
 
std::map<std::string, bool> g_boolDataMap = {
    {"ndktest_bool_key_1", true},
    {"ndktest_bool_key_2", false},
    {"ndktest_bool_key_3", false},
    {"ndktest_bool_key_4", true},
    {"ndktest_bool_key_5", true}
};

int g_changeNum = 0;
void DataChangeObserverCallback(void *context, const OH_PreferencesPair *pairs, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        const OH_PreferencesValue *pValue = OH_PreferencesPair_GetPreferencesValue(pairs, i);
        Preference_ValueType type = OH_PreferencesValue_GetValueType(pValue);
        if (type == Preference_ValueType::TYPE_INT) {
            int intV = 0;
            OH_PreferencesValue_GetInt(pValue, &intV);
        } else if (type == Preference_ValueType::TYPE_BOOL) {
            bool boolV = false;
            OH_PreferencesValue_GetBool(pValue, &boolV);
        } else if (type == Preference_ValueType::TYPE_STRING) {
            char *stringV = nullptr;
            uint32_t len = 0;
            OH_PreferencesValue_GetString(pValue, &stringV, &len);
            OH_Preferences_FreeString(stringV);
        }
        g_changeNum++;
    }
}

int PreferencesFlush(OH_Preferences *preference)
{
    OH_PreferencesImpl *pref = static_cast<OH_PreferencesImpl *>(preference);
    std::shared_ptr<OHOS::NativePreferences::Preferences> nativePreferences = pref->GetNativePreferences();
    return nativePreferences->FlushSync();
}

void SetAllValuesWithCheck(OH_Preferences *pref)
{
    for (auto &[key, value] : g_intDataMap) {
        EXPECT_EQ(OH_Preferences_SetInt(pref, key.c_str(), value), PREFERENCES_OK);
        EXPECT_EQ(PreferencesFlush(pref), OHOS::NativePreferences::E_OK);
        int res = 0;
        EXPECT_EQ(OH_Preferences_GetInt(pref, key.c_str(), &res), PREFERENCES_OK);
        EXPECT_EQ(res, value);
    }
    for (auto &[key, value] : g_stringDataMap) {
        EXPECT_EQ(OH_Preferences_SetString(pref, key.c_str(), value.c_str()), PREFERENCES_OK);
        EXPECT_EQ(PreferencesFlush(pref), OHOS::NativePreferences::E_OK);
        char *res = nullptr;
        uint32_t len = 0;
        EXPECT_EQ(OH_Preferences_GetString(pref, key.c_str(), &res, &len), PREFERENCES_OK);
        EXPECT_EQ(strcmp(res, value.c_str()), 0);
        OH_Preferences_FreeString(res);
    }
    for (auto &[key, value] : g_boolDataMap) {
        EXPECT_EQ(OH_Preferences_SetBool(pref, key.c_str(), value), PREFERENCES_OK);
        EXPECT_EQ(PreferencesFlush(pref), OHOS::NativePreferences::E_OK);
        bool res;
        EXPECT_EQ(OH_Preferences_GetBool(pref, key.c_str(), &res), PREFERENCES_OK);
        EXPECT_EQ(res, value);
    }
}
 
void CheckTargetTypeValues(OH_Preferences *pref, bool exist, PrefDataType pdt)
{
    if (pdt == PrefDataType::INT) {
        for (auto &[key, value] : g_intDataMap) {
            int res;
            if (exist) {
                EXPECT_EQ(OH_Preferences_GetInt(pref, key.c_str(), &res), PREFERENCES_OK);
                EXPECT_EQ(res, value);
            } else {
                EXPECT_EQ(OH_Preferences_GetInt(pref, key.c_str(), &res), PREFERENCES_ERROR_KEY_NOT_FOUND);
            }
        }
    } else if (pdt == PrefDataType::STRING) {
        for (auto &[key, value] : g_stringDataMap) {
            char *res = nullptr;
            uint32_t len = 0;
            if (exist) {
                EXPECT_EQ(OH_Preferences_GetString(pref, key.c_str(), &res, &len), PREFERENCES_OK);
                EXPECT_EQ(strcmp(res, value.c_str()), 0);
            } else {
                EXPECT_EQ(OH_Preferences_GetString(pref, key.c_str(), &res, &len), PREFERENCES_ERROR_KEY_NOT_FOUND);
            }
            OH_Preferences_FreeString(res);
        }
    } else if (pdt == PrefDataType::BOOL) {
        for (auto &[key, value] : g_boolDataMap) {
            bool res;
            if (exist) {
                EXPECT_EQ(OH_Preferences_GetBool(pref, key.c_str(), &res), PREFERENCES_OK);
                EXPECT_EQ(res, value);
            } else {
                EXPECT_EQ(OH_Preferences_GetBool(pref, key.c_str(), &res), PREFERENCES_ERROR_KEY_NOT_FOUND);
            }
        }
    }
}
 
/**
 * @tc.name: NDKPreferencesGetTest_001
 * @tc.desc: 测试先put int类型的kv，再get相同的key，值相同
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesGetTest_001, TestSize.Level1)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
 
    SetAllValuesWithCheck(pref);
 
    const char *key = "test_key_int";
    EXPECT_EQ(OH_Preferences_SetInt(pref, key, 12), PREFERENCES_OK);
    int ret;
    EXPECT_EQ(OH_Preferences_GetInt(pref, key, &ret), PREFERENCES_OK);
    EXPECT_EQ(ret, 12);
 
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}
 
/**
 * @tc.name: NDKPreferencesGetTest_002
 * @tc.desc: 测试先put string类型的kv，再get相同的key，值相同
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesGetTest_002, TestSize.Level1)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
 
    SetAllValuesWithCheck(pref);
 
    const char *key = "test_key_string";
    const char *value = "test_value";
    EXPECT_EQ(OH_Preferences_SetString(pref, key, value), PREFERENCES_OK);
    char *ret = nullptr;
    uint32_t len = 0;
    EXPECT_EQ(OH_Preferences_GetString(pref, key, &ret, &len), PREFERENCES_OK);
    EXPECT_EQ(strcmp(ret, value), 0);
    OH_Preferences_FreeString(ret);
 
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}
 
/**
 * @tc.name: NDKPreferencesGetTest_003
 * @tc.desc: 测试先put bool类型的kv，再get相同的key，值相同
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesGetTest_003, TestSize.Level1)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
 
    SetAllValuesWithCheck(pref);
 
    const char *key = "test_key_bool";
    bool value = true;
    EXPECT_EQ(OH_Preferences_SetBool(pref, key, value), PREFERENCES_OK);
    bool ret;
    EXPECT_EQ(OH_Preferences_GetBool(pref, key, &ret), PREFERENCES_OK);
    EXPECT_EQ(ret, value);
 
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}
 
/**
 * @tc.name: NDKPreferencesGetTest_004
 * @tc.desc: 测试get不存在的kv
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesGetTest_004, TestSize.Level1)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
 
    CheckTargetTypeValues(pref, false, PrefDataType::INT);
    CheckTargetTypeValues(pref, false, PrefDataType::STRING);
    CheckTargetTypeValues(pref, false, PrefDataType::BOOL);
 
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}
 
/**
 * @tc.name: NDKPreferencesPutTest_001
 * @tc.desc: 测试先get不存在的kv，再put进kv，然后get
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesPutTest_001, TestSize.Level1)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
 
    CheckTargetTypeValues(pref, false, PrefDataType::INT);
    CheckTargetTypeValues(pref, false, PrefDataType::STRING);
    CheckTargetTypeValues(pref, false, PrefDataType::BOOL);
 
    SetAllValuesWithCheck(pref);
 
    CheckTargetTypeValues(pref, true, PrefDataType::INT);
    CheckTargetTypeValues(pref, true, PrefDataType::STRING);
    CheckTargetTypeValues(pref, true, PrefDataType::BOOL);
 
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}
 
/**
 * @tc.name: NDKPreferencesUpdateTest_001
 * @tc.desc: 测试先put int类型的kv，然后get，然后再put新的值进行更新，再get
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesUpdateTest_001, TestSize.Level1)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
 
    SetAllValuesWithCheck(pref);
 
    const char *key = "ndktest_int_key_1";
    int newValue = 10;
    EXPECT_EQ(OH_Preferences_SetInt(pref, key, newValue), PREFERENCES_OK);
    int ret;
    EXPECT_EQ(OH_Preferences_GetInt(pref, key, &ret), PREFERENCES_OK);
    EXPECT_EQ(ret, newValue);
 
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}
 
/**
 * @tc.name: NDKPreferencesUpdateTest_002
 * @tc.desc: 测试先put string类型的kv，然后get，然后再put新的值进行更新，再get
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesUpdateTest_002, TestSize.Level1)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
 
    SetAllValuesWithCheck(pref);
 
    const char *key = "ndktest_string_key_1";
    const char *newValue = "adlkj1#$&sdioj9i0i841a61aa4gh44o98()!@@.,.{:/',}";
    EXPECT_EQ(OH_Preferences_SetString(pref, key, newValue), PREFERENCES_OK);
    char *ret = nullptr;
    uint32_t len = 0;
    EXPECT_EQ(OH_Preferences_GetString(pref, key, &ret, &len), PREFERENCES_OK);
    EXPECT_EQ(strcmp(ret, newValue), 0);
    OH_Preferences_FreeString(ret);
 
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}
 
/**
 * @tc.name: NDKPreferencesUpdateTest_003
 * @tc.desc: 测试先put bool类型的kv，然后get，然后再put新的值进行更新，再get
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Song Yixiu
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesUpdateTest_003, TestSize.Level1)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
 
    SetAllValuesWithCheck(pref);
 
    const char *key = "ndktest_bool_key_1";
    bool newValue = false;
    EXPECT_EQ(OH_Preferences_SetBool(pref, key, newValue), PREFERENCES_OK);
    bool ret;
    EXPECT_EQ(OH_Preferences_GetBool(pref, key, &ret), PREFERENCES_OK);
    EXPECT_EQ(ret, newValue);
 
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}
 
/**
 * @tc.name: NDKPreferencesDeleteTest_001
 * @tc.desc: test Delete exist key
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Liu Xiaolong
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesDeleteTest_001, TestSize.Level1)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
 
    SetAllValuesWithCheck(pref);
 
    for (auto &[key, value] : g_stringDataMap) {
        EXPECT_EQ(OH_Preferences_Delete(pref, key.c_str()), PREFERENCES_OK);
    }
 
    CheckTargetTypeValues(pref, true, PrefDataType::INT);
    CheckTargetTypeValues(pref, false, PrefDataType::STRING);
    CheckTargetTypeValues(pref, true, PrefDataType::BOOL);
 
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}
 
/**
 * @tc.name: NDKPreferencesDeleteTest_002
 * @tc.desc: test Delete non-exist key
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Liu Xiaolong
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesDeleteTest_002, TestSize.Level1)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);
 
    CheckTargetTypeValues(pref, false, PrefDataType::INT);
 
    for (auto &[key, value] : g_intDataMap) {
        EXPECT_EQ(OH_Preferences_Delete(pref, key.c_str()), PREFERENCES_OK);
    }
 
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}
 
/**
 * @tc.name: NDKPreferencesObserverTest_001
 * @tc.desc: test Observer
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: Liu Xiaolong
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesObserverTest_001, TestSize.Level1)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    const char *keys[] = {"ndktest_int_key_1", "ndktest_string_key_1", "ndktest_bool_key_1"};

    OH_PreferencesDataObserver observer = &DataChangeObserverCallback;
    int ret = OH_Preferences_RegisterDataObserver(pref, nullptr, &observer, keys, 3);
    ASSERT_EQ(ret, PREFERENCES_OK);

    SetAllValuesWithCheck(pref);

    for (auto &[key, value] : g_intDataMap) {
        EXPECT_EQ(OH_Preferences_Delete(pref, key.c_str()), PREFERENCES_OK);
        EXPECT_EQ(PreferencesFlush(pref), OHOS::NativePreferences::E_OK);
    }
 
    for (auto &[key, value] : g_stringDataMap) {
        const char *newValue = "update_string_value_109uokadnf894u5";
        EXPECT_EQ(OH_Preferences_SetString(pref, key.c_str(), newValue), PREFERENCES_OK);
        EXPECT_EQ(PreferencesFlush(pref), OHOS::NativePreferences::E_OK);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    EXPECT_EQ(g_changeNum, 5);

    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, &observer, keys, 3), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesObserverTest_002
 * @tc.desc: test Observer
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: bluhuang
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesObserverTest_002, TestSize.Level1)
{
    // cannot get callback when unregister
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    const char *keys[] = {"ndktest_int_key_1", "ndktest_string_key_1", "ndktest_bool_key_1"};
    g_changeNum = 0;
    OH_PreferencesDataObserver observer = &DataChangeObserverCallback;
    int ret = OH_Preferences_RegisterDataObserver(pref, nullptr, &observer, keys, 3);
    ASSERT_EQ(ret, PREFERENCES_OK);
    const char *empty[] = {};
    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, &observer, empty, 0), PREFERENCES_OK);

    SetAllValuesWithCheck(pref);
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    EXPECT_EQ(g_changeNum, 0);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesObserverTest_003
 * @tc.desc: test Observer
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: bluhuang
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesObserverTest_003, TestSize.Level1)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    const char *keys[] = {"ndktest_int_key_1", "ndktest_string_key_1", "ndktest_bool_key_1"};
    g_changeNum = 0;
    OH_PreferencesDataObserver observer = &DataChangeObserverCallback;
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(nullptr, nullptr, &observer, keys, 3),
        PREFERENCES_ERROR_INVALID_PARAM);
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(pref, nullptr, nullptr, keys, 3), PREFERENCES_ERROR_INVALID_PARAM);
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(pref, nullptr, &observer, nullptr, 3),
        PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(nullptr, nullptr, &observer, keys, 0),
        PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, nullptr, keys, 0),
        PREFERENCES_ERROR_INVALID_PARAM);
    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, &observer, nullptr, 0),
        PREFERENCES_ERROR_INVALID_PARAM);
}

/**
 * @tc.name: NDKPreferencesObserverTest_004
 * @tc.desc: test Observer
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: bluhuang
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesObserverTest_004, TestSize.Level1)
{
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    const char *keys1[] = {"ndktest_int_key_1", "ndktest_string_key_1", "ndktest_bool_key_1"};
    g_changeNum = 0;
    OH_PreferencesDataObserver observer = &DataChangeObserverCallback;
    double obj = 1.1;
    void *context1 = &obj;
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(pref, (void*) context1, &observer, keys1, 3), PREFERENCES_OK);

    const char *keys2[] = {"ndktest_int_key_5"};
    double obj2 = 2.2;
    void *context2 = &obj2;
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(pref, (void*) context2, &observer, keys2, 1), PREFERENCES_OK);
    SetAllValuesWithCheck(pref);

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    EXPECT_EQ(g_changeNum, 4);

    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, &observer, keys1, 3), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, &observer, keys2, 1), PREFERENCES_OK);
    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}

/**
 * @tc.name: NDKPreferencesObserverTest_005
 * @tc.desc: test Observer
 * @tc.type: FUNC
 * @tc.require: NA
 * @tc.author: bluhuang
 */
HWTEST_F(PreferencesNdkTest, NDKPreferencesObserverTest_005, TestSize.Level1)
{
    // cancel part of all registerd key
    int errCode = PREFERENCES_OK;
    OH_PreferencesOption *option = GetCommonOption();
    OH_Preferences *pref = OH_Preferences_Open(option, &errCode);
    (void)OH_PreferencesOption_Destroy(option);
    ASSERT_EQ(errCode, PREFERENCES_OK);

    const char *keys[] = {"ndktest_int_key_1", "ndktest_string_key_1", "ndktest_bool_key_1"};
    g_changeNum = 0;
    OH_PreferencesDataObserver observer = &DataChangeObserverCallback;
    ASSERT_EQ(OH_Preferences_RegisterDataObserver(pref, nullptr, &observer, keys, 3), PREFERENCES_OK);
    const char *cancel[] = {"ndktest_bool_key_1"};
    EXPECT_EQ(OH_Preferences_UnregisterDataObserver(pref, nullptr, &observer, cancel, 1), PREFERENCES_OK);

    SetAllValuesWithCheck(pref);

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    EXPECT_EQ(g_changeNum, 2);

    EXPECT_EQ(OH_Preferences_Close(pref), PREFERENCES_OK);
    EXPECT_EQ(OHOS::NativePreferences::PreferencesHelper::DeletePreferences("/data/test/testdb"),
        OHOS::NativePreferences::E_OK);
}
}
