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
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'
import data_preferences from '@ohos.data.preferences';
import featureAbility from '@ohos.ability.featureAbility';
import taskpool from '@ohos.taskpool'

const NAME = 'test_preferences';
const KEY_TEST_STRING_ELEMENT = 'key_test_string';
var context;

const TAG = '[PREFERENCES_CALLBACK_JSUNIT_TEST]'

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

describe('PreferencesTaskpoolJsunit', function () {
    beforeAll(function () {
        console.info('beforeAll')
        context = featureAbility.getContext()
    })

    beforeEach(async function () {
        console.info('beforeEach');
    })

    afterEach(async function () {
        console.info('afterEach');
        await data_preferences.deletePreferences(context, NAME);
    })

    afterAll(function () {
        console.info('afterAll')
    })

    /**
     * @tc.name clear taskpool interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Taskpool_0001
     * @tc.desc clear taskpool interface test
     */
    it('testPreferencesTaskpoolClear0001', 0, async function (done) {
        async function PreferencesPut() {
            for (let index = 0; index < 100; index++) {
                let mPreferences = await data_preferences.getPreferences(context, NAME);
                await mPreferences.put(KEY_TEST_STRING_ELEMENT + index.toString(), "test" + index.toString());
                await mPreferences.flush()
            }
        }
        async function PreferencesClear() {
            for (let index = 0; index < 100; index++) {
                let mPreferences = await data_preferences.getPreferences(context, NAME);
                await mPreferences.clear();
                await mPreferences.flush()
            }
        }
        taskpool.execute(PreferencesPut);
        taskpool.execute(PreferencesClear);
        await sleep(3000);
        done();
    })

    /**
     * @tc.name clear taskpool interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Taskpool_0002
     * @tc.desc clear taskpool interface test
     */
    it('testPreferencesTaskpoolClear0001', 0, async function (done) {
        async function PreferencesPut() {
            for (let index = 0; index < 100; index++) {
                let mPreferences = await data_preferences.getPreferences(context, NAME);
                mPreferences.putSync(KEY_TEST_STRING_ELEMENT + index.toString(), "test" + index.toString());
                await mPreferences.flush()
            }
        }
        async function PreferencesClear() {
            for (let index = 0; index < 100; index++) {
                let mPreferences = await data_preferences.getPreferences(context, NAME);
                mPreferences.clearSync();
                await mPreferences.flush()
            }
        }
        taskpool.execute(PreferencesPut);
        taskpool.execute(PreferencesClear);
        await sleep(3000);
        done();
    })

    /**
     * @tc.name preferences taskpool interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Taskpool_0003
     * @tc.desc preferences taskpool interface test
     */
    it('testPreferencesTaskpool0001', 0, async function (done) {
        console.info('testPreferencesTaskpool0001 start');
        async function PreferencesPut() {
            for (let index = 0; index < 100; index++) {
                let mPreferences = await data_preferences.getPreferences(context, NAME);
                await mPreferences.put(KEY_TEST_STRING_ELEMENT + index.toString(), "test" + index.toString());
                await mPreferences.get(KEY_TEST_STRING_ELEMENT + index.toString(), "defaultvalue");
                await mPreferences.flush()
            }
        }
        async function PreferencesUpdate() {
            for (let index = 0; index < 100; index++) {
                let pref = await data_preferences.getPreferences(context, NAME);
                pref.has(KEY_TEST_STRING_ELEMENT + index.toString(), async function (err, ret) {
                    let val = "test" + index.toString();
                    await pref.delete(KEY_TEST_STRING_ELEMENT + index.toString());
                    await pref.flush();
                    await pref.put(KEY_TEST_STRING_ELEMENT + index.toString(), "test");
                    await pref.flush();
                });
            }
        }
        taskpool.execute(PreferencesPut);
        taskpool.execute(PreferencesUpdate);
        await sleep(3000);
        await data_preferences.removePreferencesFromCache(context, NAME);
        let preference = await data_preferences.getPreferences(context, NAME);
        preference.getAll().then((ret) => {
            done();
            console.log("testPreferencesTaskpool0002 end.");
        }).catch((err) => {
            console.log("getAll err =" + err + ", code =" + err.code + ", message =" + err.message);
            expect(false).assertTrue();
        })
    })

    /**
     * @tc.name preferences sync taskpool interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_Taskpool_0004
     * @tc.desc preferences sync taskpool interface test
     */
    it('testPreferencesTaskpool0002', 0, async function (done) {
        async function PreferencesPutSync() {
            for (let index = 0; index < 100; index++) {
                let mPreferences = await data_preferences.getPreferences(context, NAME);
                mPreferences.putSync(KEY_TEST_STRING_ELEMENT + index.toString(), "test" + index.toString());
                mPreferences.getSync(KEY_TEST_STRING_ELEMENT + index.toString(), "defaultvalue");
                await mPreferences.flush()
            }
        }
        async function PreferencesUpdateSync() {
            for (let index = 0; index < 100; index++) {
                let pref = await data_preferences.getPreferences(context, NAME);
                pref.has(KEY_TEST_STRING_ELEMENT + index.toString(), async function (err, ret) {
                    let val = "test" + index.toString();
                    pref.deleteSync(KEY_TEST_STRING_ELEMENT + index.toString());
                    await pref.flush();
                    pref.putSync(KEY_TEST_STRING_ELEMENT + index.toString(), "test");
                    await pref.flush();
                    pref.getSync(KEY_TEST_STRING_ELEMENT + index.toString(), "defaultvalue");
                });
            }
        }
        taskpool.execute(PreferencesPutSync);
        taskpool.execute(PreferencesUpdateSync);
        await sleep(3000);
        await data_preferences.removePreferencesFromCache(context, NAME);
        let preference = await data_preferences.getPreferences(context, NAME);
        preference.getAll().then((ret) => {
            done();
            console.log("testPreferencesTaskpool0002 end.");
        }).catch((err) => {
            console.log("getAll err =" + err + ", code =" + err.code + ", message =" + err.message);
            expect(false).assertTrue();
        })
    })
})