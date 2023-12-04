/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium';
import data_preferences from '@ohos.data.preferences';


const NAME = 'test_preferences_store';
const TAG = "[stagePreferencesSyncJsTest]"
const KEY_TEST_STRING_ELEMENT = 'key_test_string';
let mPreferences;

export default function stagePreferencesSyncJsTest() {
  describe('stagePreferencesSyncJsTest', function () {
    beforeAll(async function () {
      console.info('beforeAll');
    })
    afterAll(async function () {
      console.info('afterAll');
    })

    /**
     * @tc.number SUB_DDM_Preferences_GetPreferencesSync_0100
     * @tc.name getPreferencesSync interface test
     * @tc.desc getPreferencesSync interface test
     */
    it('SUB_DDM_Preferences_GetPreferencesSync_0100', 0, async function () {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: '',
      };
      try {
        mPreferences = data_preferences.getPreferencesSync(globalThis.abilityContext, Options)
        console.info(TAG, `getPreferences successfully.`);
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect().assertFail();
      }
    })

    /**
     * @tc.number SUB_DDM_Preferences_GetPreferencesSync_0200
     * @tc.name getPreferencesSync interface test
     * @tc.desc getPreferencesSync interface test
     */
    it('SUB_DDM_Preferences_GetPreferencesSync_0200', 0, async function () {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: '123123',
      };
      try {
        mPreferences = data_preferences.getPreferencesSync(globalThis.abilityContext, Options)
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect(errInfo.code).assertEqual('15501002');
      }
    })

    /**
     * @tc.number SUB_DDM_Preferences_GetPreferencesSync_0300
     * @tc.name getPreferencesSync interface test
     * @tc.desc getPreferencesSync interface test
     */
    it('SUB_DDM_Preferences_GetPreferencesSync_0300', 0, async function () {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: '123456',
      };
      try {
        mPreferences = data_preferences.getPreferencesSync(globalThis.abilityContext, Options)
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect(errInfo.code).assertEqual('15501002');
      }
    })

    /**
     * @tc.number SUB_DDM_Preferences_removePreferencesFromCacheSync_0100
     * @tc.name removePreferencesFromCacheSync interface test
     * @tc.desc removePreferencesFromCacheSync interface test
     */
    it('SUB_DDM_Preferences_removePreferencesFromCacheSync_0100', 0, async function () {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: '',
      };
      try {
        data_preferences.removePreferencesFromCacheSync(globalThis.abilityContext, Options)
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect().assertFail();
      }
    })

    /**
     * @tc.number SUB_DDM_Preferences_removePreferencesFromCacheSync_0200
     * @tc.name removePreferencesFromCacheSync interface test
     * @tc.desc removePreferencesFromCacheSync interface test
     */
    it('SUB_DDM_Preferences_removePreferencesFromCacheSync_0200', 0, async function () {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: '123123',
      };
      try {
        data_preferences.removePreferencesFromCacheSync(globalThis.abilityContext, Options)
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect(errInfo.code).assertEqual('15501002');
      }
    })

    /**
     * @tc.number SUB_DDM_Preferences_removePreferencesFromCacheSync_0300
     * @tc.name removePreferencesFromCacheSync interface test
     * @tc.desc removePreferencesFromCacheSync interface test
     */
    it('SUB_DDM_Preferences_removePreferencesFromCacheSync_0300', 0, async function () {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: '123456',
      };
      try {
        data_preferences.removePreferencesFromCacheSync(globalThis.abilityContext, Options)
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect(errInfo.code).assertEqual('15501002');
      }
    })
  })
}
