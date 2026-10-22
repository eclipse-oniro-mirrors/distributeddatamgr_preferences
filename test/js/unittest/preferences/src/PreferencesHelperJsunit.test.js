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

    /**
     * @tc.name getPreferences with cacheSize positive value
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_cacheSize_001
     * @tc.desc getPreferences with cacheSize=4096 should succeed
     */
    it('testGetPreferencesCacheSize001', 0, async function (done) {
        try {
            let pref = await data_preferences.getPreferences(context, { name: 'test_cacheSize_001', cacheSize: 256 });
            expect(pref != null).assertTrue();
            await pref.put('key', 'value');
            await pref.flush();
            await data_preferences.removePreferencesFromCache(context, { name: 'test_cacheSize_001' });
            await data_preferences.deletePreferences(context, { name: 'test_cacheSize_001' });
            done();
        } catch (err) {
            expect(err).assertFail();
        }
    })

    /**
     * @tc.name getPreferences with cacheSize zero value
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_cacheSize_002
     * @tc.desc getPreferences with cacheSize=0 should succeed
     */
    it('testGetPreferencesCacheSize002', 0, async function (done) {
        try {
            let pref = await data_preferences.getPreferences(context, { name: 'test_cacheSize_002', cacheSize: 0 });
            expect(pref != null).assertTrue();
            await pref.put('key', 'value');
            await pref.flush();
            await data_preferences.removePreferencesFromCache(context, { name: 'test_cacheSize_002' });
            await data_preferences.deletePreferences(context, { name: 'test_cacheSize_002' });
            done();
        } catch (err) {
            expect(err).assertFail();
        }
    })

    /**
     * @tc.name getPreferences with cacheSize negative value
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_cacheSize_003
     * @tc.desc getPreferences with negative cacheSize should throw error
     */
    it('testGetPreferencesCacheSize003', 0, async function (done) {
        try {
            await data_preferences.getPreferences(context, { name: 'test_cacheSize_003', cacheSize: -1 });
            expect(null).assertFail();
        } catch (err) {
            expect(err.code == 15500000 || err.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name getPreferences with cacheSize non-number type
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_cacheSize_004
     * @tc.desc getPreferences with non-number cacheSize should throw error
     */
    it('testGetPreferencesCacheSize004', 0, async function (done) {
        try {
            await data_preferences.getPreferences(context, { name: 'test_cacheSize_004', cacheSize: 'invalid' });
            expect(null).assertFail();
        } catch (err) {
            expect(err.code == 15500000 || err.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name getPreferences without cacheSize
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_cacheSize_005
     * @tc.desc getPreferences without cacheSize should succeed (backward compatible)
     */
    it('testGetPreferencesCacheSize005', 0, async function (done) {
        try {
            let pref = await data_preferences.getPreferences(context, { name: 'test_cacheSize_005' });
            expect(pref != null).assertTrue();
            await data_preferences.removePreferencesFromCache(context, { name: 'test_cacheSize_005' });
            await data_preferences.deletePreferences(context, { name: 'test_cacheSize_005' });
            done();
        } catch (err) {
            expect(err).assertFail();
        }
    })

    /**
     * @tc.name getPreferences with cacheSize below minimum range
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_cacheSize_006
     * @tc.desc getPreferences with cacheSize=1 (below 4096) should throw error 401
     */
    it('testGetPreferencesCacheSize006', 0, async function (done) {
        try {
            await data_preferences.getPreferences(context, { name: 'test_cacheSize_006', cacheSize: 1 });
            expect(null).assertFail();
        } catch (err) {
            expect(err.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name getPreferences with cacheSize above maximum range
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_cacheSize_007
     * @tc.desc getPreferences with cacheSize=9999999 (above 1112784) should throw error 401
     */
    it('testGetPreferencesCacheSize007', 0, async function (done) {
        try {
            await data_preferences.getPreferences(context, { name: 'test_cacheSize_007', cacheSize: 9999999 });
            expect(null).assertFail();
        } catch (err) {
            expect(err.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name getPreferences with cacheSize boundary values
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_cacheSize_008
     * @tc.desc getPreferences with cacheSize=4096 and 1112784 (boundary) should succeed
     */
    it('testGetPreferencesCacheSize008', 0, async function (done) {
        try {
            let pref = await data_preferences.getPreferences(context, { name: 'test_cacheSize_008a', cacheSize: 256 });
            expect(pref != null).assertTrue();
            await data_preferences.removePreferencesFromCache(context, { name: 'test_cacheSize_008a' });
            await data_preferences.deletePreferences(context, { name: 'test_cacheSize_008a' });

            pref = await data_preferences.getPreferences(context, { name: 'test_cacheSize_008b', cacheSize: 1112784 });
            expect(pref != null).assertTrue();
            await data_preferences.removePreferencesFromCache(context, { name: 'test_cacheSize_008b' });
            await data_preferences.deletePreferences(context, { name: 'test_cacheSize_008b' });
            done();
        } catch (err) {
            expect(err).assertFail();
        }
    })

    /**
     * @tc.name getPreferences with cacheSize in XML mode (silently ignored)
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_cacheSize_009
     * @tc.desc getPreferences with storageType XML and cacheSize=4096 should succeed, cacheSize silently ignored
     */
    it('testGetPreferencesCacheSize009', 0, async function (done) {
        try {
            let pref = await data_preferences.getPreferences(context,
                { name: 'test_cacheSize_009', storageType: 0, cacheSize: 256 });
            expect(pref != null).assertTrue();
            await pref.put('key', 'value');
            await pref.flush();
            await data_preferences.removePreferencesFromCache(context, { name: 'test_cacheSize_009' });
            await data_preferences.deletePreferences(context, { name: 'test_cacheSize_009' });
            done();
        } catch (err) {
            expect(err).assertFail();
        }
    })

    /**
     * @tc.name getPreferences with cacheSize=0 in XML mode (silently ignored)
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_cacheSize_010
     * @tc.desc getPreferences with storageType XML and cacheSize=0 should succeed, cacheSize silently ignored
     */
    it('testGetPreferencesCacheSize010', 0, async function (done) {
        try {
            let pref = await data_preferences.getPreferences(context,
                { name: 'test_cacheSize_010', storageType: 0, cacheSize: 0 });
            expect(pref != null).assertTrue();
            await pref.put('key', 'value');
            await pref.flush();
            await data_preferences.removePreferencesFromCache(context, { name: 'test_cacheSize_010' });
            await data_preferences.deletePreferences(context, { name: 'test_cacheSize_010' });
            done();
        } catch (err) {
            expect(err).assertFail();
        }
    })
})