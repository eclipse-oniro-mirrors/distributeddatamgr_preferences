// @ts-nocheck
/*
* Copyright (c) 2022 Huawei Device Co., Ltd.
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
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import data_preferences from '@ohos.data.preferences'
import featureAbility from '@ohos.ability.featureAbility';

const NAME = 'test_preferences';
const KEY_TEST_STRING_ELEMENT = 'key_test_string';
var mPreferences;
var context;
describe('PreferencesHelperJsunit', function () {
    beforeAll(function () {
        console.info('beforeAll');
        context = featureAbility.getContext();
    })

    beforeEach(async function () {
        console.info('beforeEach');
        mPreferences = await data_preferences.getPreferences(context, NAME);
    })

    afterEach(async function () {
        console.info('afterEach');
        await data_preferences.deletePreferences(context, NAME);
    })

    afterAll(function () {
        console.info('afterAll')
    })

    /**
     * @tc.name getPreferences interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_getPreferences_001
     * @tc.desc getPreferences interface test
     */
    it('testGetPreferencesHelper001', 0, async function () {
        await mPreferences.put('test', 2);
        var value = await mPreferences.get('test', 0);
        expect(value).assertEqual(2);
    })

    /**
     * @tc.name getPreferences interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_getPreferences_002
     * @tc.desc getPreferences interface test
     */
    it('testGetPreferencesHelper002', 0, async function (done) {
        const promise = data_preferences.getPreferences(context, NAME);
        await promise.then(async (pref) => {
            await pref.put('test', 2);
            var value = await mPreferences.get('test', 0);
            done();
            expect(value).assertEqual(2);
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name getPreferences interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_getPreferences_003
     * @tc.desc getPreferences interface test
     */
    it('testGetPreferencesHelper003', 0, async function (done) {
        try {
            mPreferences = await data_preferences.getPreferences(context, { name: NAME });
            done();
            expect(mPreferences != null).assertTrue();
        } catch(err) {
            expect(err).assertFail();
        }
    })

    /**
     * @tc.name getPreferencesSync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_getPreferences_004
     * @tc.desc getPreferencesSync interface test
     */
    it('testGetPreferencesHelper004', 0, async function (done) {
        try {
            await data_preferences.getPreferences(context, { name: NAME, dataGroupId: "123456" });
        } catch(err) {
            done();
            expect('15501001').assertEqual(err.code);
        }
    })

    /**
     * @tc.name getPreferencesSync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_getPreferences_005
     * @tc.desc getPreferencesSync interface test
     */
    it('testGetPreferencesHelper005', 0, async function (done) {
        try {
            await data_preferences.getPreferences(undefined, { name: NAME });
            done();
            expect(mPreferences != null).assertTrue();
        } catch(err) {
            expect(err).assertFail();
        }
    })

    /**
     * @tc.name getPreferencesSync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_getPreferences_006
     * @tc.desc getPreferencesSync interface test
     */
    it('testGetPreferencesHelper006', 0, async function (done) {
        try {
            await data_preferences.getPreferences(null, { name: NAME });
            done();
            expect(mPreferences != null).assertTrue();
        } catch(err) {
            expect(err).assertFail();
        }
    })

    /**
     * @tc.name getPreferencesSync interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_getPreferences_007
     * @tc.desc getPreferencesSync interface test
     */
    it('testGetPreferencesHelper007', 0, async function (done) {
        try {
            await data_preferences.getPreferences({}, { name: NAME });
            done();
            expect(mPreferences != null).assertTrue();
        } catch(err) {
            expect(err).assertFail();
        }
    })

    /**
     * @tc.name removePreferencesFromCache interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_removePreferencesFromCache_001
     * @tc.desc removePreferencesFromCache interface test
     */
    it('testRemovePreferencesFromCache001', 0, async function () {
        let perf = await data_preferences.getPreferences(context, NAME);
        perf = null;
        const promise = data_preferences.removePreferencesFromCache(context, NAME);
        await promise.then((pref) => {
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name removePreferencesFromCache interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_removePreferencesFromCache_002
     * @tc.desc removePreferencesFromCache interface test
     */
    it('testRemovePreferencesFromCache002', 0, async function (done) {
        let perf = await data_preferences.getPreferences(context, { name: NAME });
        perf = null;
        try {
            await data_preferences.removePreferencesFromCache(context, { name: NAME });
            done();
        } catch(err) {
            expect(err).assertFail();
        }
    })

    /**
     * @tc.name removePreferencesFromCache interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_removePreferencesFromCache_003
     * @tc.desc removePreferencesFromCache interface test
     */
    it('testRemovePreferencesFromCache003', 0, async function (done) {
        try {
            await data_preferences.removePreferencesFromCache(context, { name: NAME, dataGroupId: "123456" });
        } catch(err) {
            done();
            expect('15501001').assertEqual(err.code);
        }
    })

    /**
     * @tc.name deletePreferences interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_deletePreferences_001
     * @tc.desc deletePreferences interface test
     */
    it('testDeletePreferencesHelper001', 0, async function () {
        let perf = await data_preferences.getPreferences(context, NAME);
        perf = null;
        const promise = data_preferences.deletePreferences(context, NAME);
        await promise.then((pref) => {   
        }).catch((err) => {
            expect(null).assertFail();
        });
    })

    /**
     * @tc.name deletePreferences interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_deletePreferences_002
     * @tc.desc deletePreferences interface test
     */
    it('testDeletePreferencesHelper002', 0, async function (done) {
        let perf = await data_preferences.getPreferences(context, { name: NAME });
        try {
            await data_preferences.deletePreferences(context, { name: NAME });
            done();
        } catch(err) {
            expect(err).assertFail();
        }
    })

    /**
     * @tc.name deletePreferences interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_deletePreferences_003
     * @tc.desc removePreferencesFromCache interface test
     */
    it('testDeletePreferencesHelper003', 0, async function (done) {
        try {
            await data_preferences.deletePreferences(context, { name: NAME, dataGroupId: "123456" });
        } catch(err) {
            done();
            expect('15501001').assertEqual(err.code);
        }
    })

    /**
     * @tc.name repeat on interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_on_001
     * @tc.desc repeat on interface test
     */
    it('testPreferencesOn001', 0, async function () {
        await mPreferences.clear();
        var observer = function (key) {
            console.info('testPreferencesRegisterObserver002 key' + key);
            expect('abc').assertEqual(key);
        };
        await mPreferences.on('change', observer);
        await mPreferences.on('change', observer);
        await mPreferences.put(KEY_TEST_STRING_ELEMENT, "abc");
    })

    /**
     * @tc.name off interface test
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_off_001
     * @tc.desc off interface test
     */
    it('testPreferencesOff001', 0, async function () {
        var observer = function (key) {
            console.info('testPreferencesUnRegisterObserver001 key' + key);
            expect('').assertEqual(key);
        };
        await mPreferences.on('change', observer);
        await mPreferences.off('change', observer);
        await mPreferences.put(KEY_TEST_STRING_ELEMENT, "abc");
    })
})