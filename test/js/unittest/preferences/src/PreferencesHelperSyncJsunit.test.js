/*
* Copyright (c) 2023 Huawei Device Co., Ltd.
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
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'
import data_preferences from '@ohos.data.preferences'
import featureAbility from '@ohos.ability.featureAbility';

const NAME = 'test_preferences';
const KEY_TEST_STRING_ELEMENT = 'key_test_string';
var context;

describe('preferencesSyncTest', function () {
    beforeAll(async function () {
        console.info('beforeAll');
        context = featureAbility.getContext();
    })

    afterAll(async function () {
        console.info('afterAll')
    })

    /**
     * @tc.name GetPreferencesSync
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_GetPreferencesSync_001
     * @tc.desc test GetPreferencesSync if success
     */
    it('testPreferencesGetPreferencesSync001', 0, function () {
        let preferences = data_preferences.getPreferencesSync(context, { name: NAME });
        preferences.putSync(KEY_TEST_STRING_ELEMENT, "132");
        expect(preferences.hasSync(KEY_TEST_STRING_ELEMENT)).assertTrue();
        let val = preferences.getSync(KEY_TEST_STRING_ELEMENT, "defaultvalue");
        expect("132").assertEqual(val);
        data_preferences.deletePreferencesSync(context, { name: NAME });
    })

    /**
     * @tc.name RemovePreferencesFromCacheSync
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_RemovePreferencesFromCacheSync_001
     * @tc.desc test RemovePreferencesFromCacheSync if success
     */
    it('testPreferencesRemovePreferencesFromCacheSync001', 0, function () {
        let preferences = data_preferences.getPreferencesSync(context, NAME);
        preferences.putSync(KEY_TEST_STRING_ELEMENT, "132");
        expect(preferences.hasSync(KEY_TEST_STRING_ELEMENT)).assertTrue();
        let val = preferences.getSync(KEY_TEST_STRING_ELEMENT, "defaultvalue");
        expect("132").assertEqual(val);
        preferences = null;
        data_preferences.removePreferencesFromCacheSync(context, NAME);
        let preferences1 = data_preferences.getPreferencesSync(context, NAME);
        expect(preferences1.hasSync(KEY_TEST_STRING_ELEMENT)).assertFalse();
        data_preferences.deletePreferencesSync(context, NAME);
    })

    /**
     * @tc.name RemovePreferencesFromCacheSync
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_RemovePreferencesFromCacheSync_002
     * @tc.desc test RemovePreferencesFromCacheSync if success
     */
    it('testPreferencesRemovePreferencesFromCacheSync002', 0, function () {
        let preferences = data_preferences.getPreferencesSync(context, { name: NAME });
        preferences.putSync(KEY_TEST_STRING_ELEMENT, "132");
        expect(preferences.hasSync(KEY_TEST_STRING_ELEMENT)).assertTrue();
        let val = preferences.getSync(KEY_TEST_STRING_ELEMENT, "defaultvalue");
        expect("132").assertEqual(val);
        preferences = null;
        data_preferences.removePreferencesFromCacheSync(context, { name: NAME });
        let preferences1 = data_preferences.getPreferencesSync(context, { name: NAME });
        expect(preferences1.hasSync(KEY_TEST_STRING_ELEMENT)).assertFalse();
        data_preferences.deletePreferencesSync(context, { name: NAME });
    })
})