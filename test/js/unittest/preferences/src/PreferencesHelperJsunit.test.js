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
     * @tc.name getPreferences with sharedMapSize positive value
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_sharedMapSize_001
     * @tc.desc getPreferences with sharedMapSize=256 should succeed
     */
    it('testGetPreferencesCacheSize001', 0, async function (done) {
        try {
            let pref = await data_preferences.getPreferences(context, { name: 'test_sharedMapSize_001', sharedMapSize: 256 });
            expect(pref != null).assertTrue();
            await pref.put('key', 'value');
            await pref.flush();
        } catch (err) {
            expect(err).assertFail();
        } finally {
            await data_preferences.removePreferencesFromCache(context, { name: 'test_sharedMapSize_001' });
            await data_preferences.deletePreferences(context, { name: 'test_sharedMapSize_001' });
            done();
        }
    })

    /**
     * @tc.name getPreferences with sharedMapSize zero value
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_sharedMapSize_002
     * @tc.desc getPreferences with sharedMapSize=0 should succeed
     */
    it('testGetPreferencesCacheSize002', 0, async function (done) {
        try {
            let pref = await data_preferences.getPreferences(context, { name: 'test_sharedMapSize_002', sharedMapSize: 0 });
            expect(pref != null).assertTrue();
            await pref.put('key', 'value');
            await pref.flush();
        } catch (err) {
            expect(err).assertFail();
        } finally {
            await data_preferences.removePreferencesFromCache(context, { name: 'test_sharedMapSize_002' });
            await data_preferences.deletePreferences(context, { name: 'test_sharedMapSize_002' });
            done();
        }
    })

    /**
     * @tc.name getPreferences with sharedMapSize negative value
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_sharedMapSize_003
     * @tc.desc getPreferences with negative sharedMapSize should throw error
     */
    it('testGetPreferencesCacheSize003', 0, async function (done) {
        try {
            await data_preferences.getPreferences(context, { name: 'test_sharedMapSize_003', sharedMapSize: -1 });
            expect(null).assertFail();
            done();
        } catch (err) {
            expect(err.code == 15500000 || err.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name getPreferences with sharedMapSize non-number type
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_sharedMapSize_004
     * @tc.desc getPreferences with non-number sharedMapSize should throw error
     */
    it('testGetPreferencesCacheSize004', 0, async function (done) {
        try {
            await data_preferences.getPreferences(context, { name: 'test_sharedMapSize_004', sharedMapSize: 'invalid' });
            expect(null).assertFail();
            done();
        } catch (err) {
            expect(err.code == 15500000 || err.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name getPreferences without sharedMapSize
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_sharedMapSize_005
     * @tc.desc getPreferences without sharedMapSize should succeed (backward compatible)
     */
    it('testGetPreferencesCacheSize005', 0, async function (done) {
        try {
            let pref = await data_preferences.getPreferences(context, { name: 'test_sharedMapSize_005' });
            expect(pref != null).assertTrue();
        } catch (err) {
            expect(err).assertFail();
        } finally {
            await data_preferences.removePreferencesFromCache(context, { name: 'test_sharedMapSize_005' });
            await data_preferences.deletePreferences(context, { name: 'test_sharedMapSize_005' });
            done();
        }
    })

    /**
     * @tc.name getPreferences with sharedMapSize below minimum range
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_sharedMapSize_006
     * @tc.desc getPreferences with sharedMapSize=1 (below 256) should throw error 401
     */
    it('testGetPreferencesCacheSize006', 0, async function (done) {
        try {
            await data_preferences.getPreferences(context, { name: 'test_sharedMapSize_006', sharedMapSize: 1 });
            expect(null).assertFail();
            done();
        } catch (err) {
            expect(err.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name getPreferences with sharedMapSize above maximum range
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_sharedMapSize_007
     * @tc.desc getPreferences with sharedMapSize=9999999 (above 1112784) should throw error 401
     */
    it('testGetPreferencesCacheSize007', 0, async function (done) {
        try {
            await data_preferences.getPreferences(context, { name: 'test_sharedMapSize_007', sharedMapSize: 9999999 });
            expect(null).assertFail();
            done();
        } catch (err) {
            expect(err.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name getPreferences with sharedMapSize boundary values
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_sharedMapSize_008
     * @tc.desc getPreferences with sharedMapSize=256 and 1112784 (boundary) should succeed
     */
    it('testGetPreferencesCacheSize008', 0, async function (done) {
        try {
            let pref = await data_preferences.getPreferences(context, { name: 'test_sharedMapSize_008a', sharedMapSize: 256 });
            expect(pref != null).assertTrue();
            await data_preferences.removePreferencesFromCache(context, { name: 'test_sharedMapSize_008a' });
            await data_preferences.deletePreferences(context, { name: 'test_sharedMapSize_008a' });

            pref = await data_preferences.getPreferences(context, { name: 'test_sharedMapSize_008b', sharedMapSize: 1112784 });
            expect(pref != null).assertTrue();
        } catch (err) {
            expect(err).assertFail();
        } finally {
            await data_preferences.removePreferencesFromCache(context, { name: 'test_sharedMapSize_008b' });
            await data_preferences.deletePreferences(context, { name: 'test_sharedMapSize_008b' });
            done();
        }
    })

    /**
     * @tc.name getPreferences with sharedMapSize in XML mode (silently ignored)
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_sharedMapSize_009
     * @tc.desc getPreferences with storageType XML and sharedMapSize=256 should succeed, sharedMapSize silently ignored
     */
    it('testGetPreferencesCacheSize009', 0, async function (done) {
        try {
            let pref = await data_preferences.getPreferences(context,
                { name: 'test_sharedMapSize_009', storageType: 0, sharedMapSize: 256 });
            expect(pref != null).assertTrue();
            await pref.put('key', 'value');
            await pref.flush();
        } catch (err) {
            expect(err).assertFail();
        } finally {
            await data_preferences.removePreferencesFromCache(context, { name: 'test_sharedMapSize_009' });
            await data_preferences.deletePreferences(context, { name: 'test_sharedMapSize_009' });
            done();
        }
    })

    /**
     * @tc.name getPreferences with sharedMapSize=0 in XML mode (silently ignored)
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_sharedMapSize_010
     * @tc.desc getPreferences with storageType XML and sharedMapSize=0 should succeed, sharedMapSize silently ignored
     */
    it('testGetPreferencesCacheSize010', 0, async function (done) {
        try {
            let pref = await data_preferences.getPreferences(context,
                { name: 'test_sharedMapSize_010', storageType: 0, sharedMapSize: 0 });
            expect(pref != null).assertTrue();
            await pref.put('key', 'value');
            await pref.flush();
        } catch (err) {
            expect(err).assertFail();
        } finally {
            await data_preferences.removePreferencesFromCache(context, { name: 'test_sharedMapSize_010' });
            await data_preferences.deletePreferences(context, { name: 'test_sharedMapSize_010' });
            done();
        }
    })

    /**
     * @tc.name getPreferences with GSKV mode and sharedMapSize=256
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_sharedMapSize_011
     * @tc.desc getPreferences with storageType GSKV and sharedMapSize=256 should succeed
     */
    it('testGetPreferencesCacheSize011', 0, async function (done) {
        let isGskvSupported = data_preferences.isStorageTypeSupported(data_preferences.StorageType.GSKV);
        if (!isGskvSupported) {
            console.info('GSKV not supported, skip this test');
            done();
            return;
        }
        try {
            let pref = await data_preferences.getPreferences(context,
                { name: 'test_sharedMapSize_011', storageType: 1, sharedMapSize: 256 });
            expect(pref != null).assertTrue();
            await pref.put('key', 'value');
            await pref.flush();
        } catch (err) {
            expect(err).assertFail();
        } finally {
            await data_preferences.removePreferencesFromCache(context, { name: 'test_sharedMapSize_011' });
            await data_preferences.deletePreferences(context, { name: 'test_sharedMapSize_011' });
            done();
        }
    })

    /**
     * @tc.name getPreferences with GSKV mode and sharedMapSize=0
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_sharedMapSize_012
     * @tc.desc getPreferences with storageType GSKV and sharedMapSize=0 should succeed
     */
    it('testGetPreferencesCacheSize012', 0, async function (done) {
        let isGskvSupported = data_preferences.isStorageTypeSupported(data_preferences.StorageType.GSKV);
        if (!isGskvSupported) {
            console.info('GSKV not supported, skip this test');
            done();
            return;
        }
        try {
            let pref = await data_preferences.getPreferences(context,
                { name: 'test_sharedMapSize_012', storageType: 1, sharedMapSize: 0 });
            expect(pref != null).assertTrue();
            await pref.put('key', 'value');
            await pref.flush();
        } catch (err) {
            expect(err).assertFail();
        } finally {
            await data_preferences.removePreferencesFromCache(context, { name: 'test_sharedMapSize_012' });
            await data_preferences.deletePreferences(context, { name: 'test_sharedMapSize_012' });
            done();
        }
    })

    /**
     * @tc.name getPreferences with GSKV mode and sharedMapSize=1112784 (max boundary)
     * @tc.number SUB_DDM_AppDataFWK_JSPreferences_sharedMapSize_013
     * @tc.desc getPreferences with storageType GSKV and sharedMapSize=1112784 should succeed
     */
    it('testGetPreferencesCacheSize013', 0, async function (done) {
        let isGskvSupported = data_preferences.isStorageTypeSupported(data_preferences.StorageType.GSKV);
        if (!isGskvSupported) {
            console.info('GSKV not supported, skip this test');
            done();
            return;
        }
        try {
            let pref = await data_preferences.getPreferences(context,
                { name: 'test_sharedMapSize_013', storageType: 1, sharedMapSize: 1112784 });
            expect(pref != null).assertTrue();
            await pref.put('key', 'value');
            await pref.flush();
        } catch (err) {
            expect(err).assertFail();
        } finally {
            await data_preferences.removePreferencesFromCache(context, { name: 'test_sharedMapSize_013' });
            await data_preferences.deletePreferences(context, { name: 'test_sharedMapSize_013' });
            done();
        }
    })
})