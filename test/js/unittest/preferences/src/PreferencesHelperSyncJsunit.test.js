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
        console.info('beforeAll')
        context = featureAbility.getContext()
    })

    afterAll(async function () {
        console.info('afterAll')
    })

    /**
     * @tc.name RemovePreferencesFromCacheSync
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Preferences_RemovePreferencesFromCacheSync_001
     * @tc.desc test RemovePreferencesFromCacheSync if success
     */
    it('testPreferencesRemovePreferencesFromCacheSync0001', 0, async function (done) {
        let preferences = await data_preferences.getPreferences(context, NAME);
        preferences.putSync(KEY_TEST_STRING_ELEMENT, "132");
        expect(preferences.hasSync(KEY_TEST_STRING_ELEMENT)).assertTrue();
        let val = preferences.getSync(KEY_TEST_STRING_ELEMENT, "defaultvalue");
        expect("132").assertEqual(val);
        preferences = null;

        data_preferences.removePreferencesFromCacheSync(context, NAME);

        let preferences1 = await data_preferences.getPreferences(context, NAME);
        expect(preferences1.hasSync(KEY_TEST_STRING_ELEMENT)).assertFalse();
        done();
    })
})