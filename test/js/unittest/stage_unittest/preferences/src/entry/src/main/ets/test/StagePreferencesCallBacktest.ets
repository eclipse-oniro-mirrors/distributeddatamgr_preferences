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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium'
import dataPreferences from '@ohos.data.preferences';

const TAG = "[ttt]"

export default function stagePreferencesCallbackJsTest() {
  describe('stagePreferencesCallbackJsTest', function () {
    console.log(TAG + "*************Unit Test Begin*************");
    beforeAll(function() {
      console.info('beforeAll')
    })
    afterAll(function() {
      console.info('afterAll')
    })
    /**
     * @tc.number SUB_DDM_Preferences_DataGroupId_Callback_0100
     * @tc.name preferences dataGroupId null callback test
     * @tc.desc preferences getPreferences dataGroupId null callback test
     */
    it('SUB_DDM_Preferences_DataGroupId_Callback_0100', 0, async function (done) {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: null,
      };
      try {
        dataPreferences.getPreferences(globalThis.abilityContext, Options, async function (err) {
          console.info(TAG, `getPreferences successfully.`);
          done();
        })
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect().assertFail();
        done();
      }
    })

    /**
     * @tc.number SUB_DDM_Preferences_DataGroupId_Callback_0200
     * @tc.name preferences dataGroupId undefined callback test
     * @tc.desc preferences getPreferences dataGroupId undefined callback test
     */
    it('SUB_DDM_Preferences_DataGroupId_Callback_0200', 0, async function (done) {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: undefined,
      };
      try {
        dataPreferences.getPreferences(globalThis.abilityContext, Options, async function (err) {
          console.info(TAG, `getPreferences successfully.`);
          done();
        })
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect().assertFail();
        done();
        }
    })

    /**
     * @tc.number SUB_DDM_Preferences_DataGroupId_Callback_0300
     * @tc.name preferences dataGroupId callback test
     * @tc.desc preferences getPreferences dataGroupId callback test
     */
    it('SUB_DDM_Preferences_DataGroupId_Callback_0300', 0, async function (done) {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: '112233',
      };
      try {
        dataPreferences.getPreferences(globalThis.abilityContext, Options, async function (err) {
          console.info(TAG, `getPreferences successfully.`);
          done();
        })
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect(errInfo.code).assertEqual('15501002');
        done();
      } 
    })

    /**
     * @tc.number SUB_DDM_Preferences_DataGroupId_Callback_0400
     * @tc.name preferences dataGroupId null callback test
     * @tc.desc preferences removePreferencesFromCache dataGroupId null callback test
     */
    it('SUB_DDM_Preferences_DataGroupId_Callback_0400', 0, async function (done) {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: null,
      };
      try {
        dataPreferences.removePreferencesFromCache(globalThis.abilityContext, Options, function (error) {
            console.info(TAG, `removePreferencesFromCache successfully.`);
            done();
          })
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect().assertFail();
        done();
      }
    })

    /**
     * @tc.number SUB_DDM_Preferences_DataGroupId_Callback_0500
     * @tc.name preferences dataGroupId undefined callback test
     * @tc.desc preferences removePreferencesFromCache dataGroupId undefined callback test
     */
    it('SUB_DDM_Preferences_DataGroupId_Callback_0500', 0, async function (done) {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: undefined,
      };
      try {
        dataPreferences.removePreferencesFromCache(globalThis.abilityContext, Options, function (error) {
          console.info(TAG, `removePreferencesFromCache successfully.`);
          done();
        })
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect().assertFail();
        done();
      }
    })

    /**
     * @tc.number SUB_DDM_Preferences_DataGroupId_Callback_0600
     * @tc.name preferences dataGroupId callback test
     * @tc.desc preferences removePreferencesFromCache dataGroupId callback test
     */
    it('SUB_DDM_Preferences_DataGroupId_Callback_0600', 0, async function (done) {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: '112233',
      };
      try {
        dataPreferences.removePreferencesFromCache(globalThis.abilityContext, Options, function (error) {
          console.info(TAG, `removePreferencesFromCache successfully.`);
          expect().assertFail();
        })
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect(errInfo.code).assertEqual('15501002');
        done();
      }
    })

    /**
     * @tc.number SUB_DDM_Preferences_DataGroupId_Callback_0700
     * @tc.name preferences dataGroupId null callback test
     * @tc.desc preferences deletePreferences dataGroupId null callback test
     */
    it('SUB_DDM_Preferences_DataGroupId_Callback_0700', 0, async function (done) {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: null,
      };
      try {
        dataPreferences.deletePreferences(globalThis.abilityContext, Options, async function (err) {
          console.info(TAG, `deletePreferences successfully.`);
          done();
        })
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect().assertFail();
        done();
      }
    })

    /**
     * @tc.number SUB_DDM_Preferences_DataGroupId_Callback_0800
     * @tc.name preferences dataGroupId undefined callback test
     * @tc.desc preferences deletePreferences dataGroupId undefined callback test
     */
    it('SUB_DDM_Preferences_DataGroupId_Callback_0800', 0, async function (done) {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: undefined,
      };
      try {
        dataPreferences.deletePreferences(globalThis.abilityContext, Options, async function (err) {
          console.info(TAG, `deletePreferences successfully.`);
          done();
        })
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect().assertFail();
        done();
        }
    })

    /**
     * @tc.number SUB_DDM_Preferences_DataGroupId_Callback_0900
     * @tc.name preferences dataGroupId callback test
     * @tc.desc preferences deletePreferences dataGroupId callback test
     */
    it('SUB_DDM_Preferences_DataGroupId_Callback_0900', 0, async function (done) {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: '112233',
      };
      try {
        dataPreferences.deletePreferences(globalThis.abilityContext, Options, async function (err) {
          console.info(TAG, `deletePreferences successfully.`);
          done();
          expect().assertFail();
        })
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect(errInfo.code).assertEqual('15501002');
        done();
      } 
    })

    /**
     * @tc.number SUB_DDM_Preferences_DataGroupId_Callback_1000
     * @tc.name preferences dataGroupId callback test
     * @tc.desc preferences getPreferences dataGroupId callback test
     */
    it('SUB_DDM_Preferences_DataGroupId_Callback_1000', 0, async function (done) {
      const Options = {
        name: "test_preferences_callback",
        dataGroupId: '123456',
      };
      try {
        dataPreferences.getPreferences(globalThis.abilityContext, Options, async function (err) {
          console.info(TAG, `getPreferences successfully.`);
          done();
        })
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code}, message is ${errInfo.message}`);
        expect(errInfo.code).assertEqual('15501002');
        done();
      } 
    })

    console.log(TAG + "*************Unit Test End*************");
  })
}