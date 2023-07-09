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

import {beforeAll, beforeEach, describe, afterEach, afterAll, expect, it} from 'deccjsunit/index';
import dataPreferences from '@ohos.data.preferences'
import featureAbility from '@ohos.ability.featureAbility';

const NAME = 'test_preferences';
const BASE_COUNT = 2000;
const DELETE_BASE_COUNT = 1500;
const BASELINE = 25000;
const KEY_TEST_FLOAT_ELEMENT = 'key_test_float';
const KEY_TEST_BOOLEAN_ELEMENT = 'key_test_boolean';
const KEY_TEST_STRING_ELEMENT = 'key_test_string';

var context;

const TAG = '[SUB_DDM_PERF_PreferencesInstancePromiseJsPref]'

describe("PreferencesInstancePromiseJsPref", async function () {
    beforeAll(async function () {
        console.info(`${TAG}beforeAll`)
        context = featureAbility.getContext()
        await presetFiles();
    })

    beforeEach(async function () {
        console.info(`${TAG}beforeEach`);
    })

    afterEach(async function () {
        console.info(`${TAG}afterEach`);
    })

    afterAll(async function () {
        console.info(`${TAG}afterAll`)
        for (let index = 0; index < BASE_COUNT; index++) {
            dataPreferences.removePreferencesFromCacheSync(context, `${NAME}${index}`);
            await dataPreferences.deletePreferences(context, `${NAME}${index}`);
        }
    })

    async function presetFiles() { // preset 100 files for get or delete
        for (let index = 0; index < BASE_COUNT; index++) {
            const pref = await dataPreferences.getPreferences(context, `${NAME}${index}`);
            pref.putSync(KEY_TEST_FLOAT_ELEMENT, 123456789.00001);
            pref.putSync(KEY_TEST_BOOLEAN_ELEMENT, true);
            pref.putSync(KEY_TEST_STRING_ELEMENT + '1', "01234567890123456789012345678901234567890123456789");
            pref.putSync(KEY_TEST_STRING_ELEMENT + '2', "01234567890123456789012345678901234567890123456789");
            pref.putSync(KEY_TEST_STRING_ELEMENT + '3', "01234567890123456789012345678901234567890123456789");
            pref.putSync(KEY_TEST_STRING_ELEMENT + '4', "01234567890123456789012345678901234567890123456789");
            pref.putSync(KEY_TEST_STRING_ELEMENT + '5', "01234567890123456789012345678901234567890123456789");
            await pref.flush();
            dataPreferences.removePreferencesFromCacheSync(context, `${NAME}${index}`);
        }
    }

    /**
     * @tc.desc PreferencesInstancePromiseJsPref_GetPreferences without open exist file and repeat one pref
     */
    it("GetPreferences_0001", 0, async function () {
        let startTime = new Date().getTime(); // time unit is mm
        for (let index = 0; index < BASE_COUNT; index++) {
            await dataPreferences.getPreferences(context, NAME);
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(`${TAG}GetPreferences_0001 averageTime: ${averageTime} us`);
        expect(averageTime < BASELINE).assertTrue();
    })

    /**
     * @tc.desc PreferencesInstancePromiseJsPref_GetPreferences with open exist diff file
     */
    it("GetPreferences_0002", 0, async function () {
        let startTime = new Date().getTime(); // time unit is mm
        for (let index = 0; index < BASE_COUNT; index++) {
            await dataPreferences.getPreferences(context, `${NAME}${index}`);
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(`${TAG}GetPreferences_0002 averageTime: ${averageTime} us`);
        expect(averageTime < BASELINE).assertTrue();
    })

    /**
     * @tc.desc PreferencesInstancePromiseJsPref_Flush without repeat one pref
     */
    it("Flush_0001", 0, async function () {
        let pref = await dataPreferences.getPreferences(context, NAME);
        let startTime = new Date().getTime(); // time unit is mm
        for (let index = 0; index < BASE_COUNT; index++) {
            await pref.flush();
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(`${TAG}Flush_0001 averageTime: ${averageTime} us`);
        expect(averageTime < BASELINE).assertTrue();
    })

    /**
     * @tc.desc PreferencesInstancePromiseJsPref_removePreferencesFromCache with repeating one pref
     */
    it("removePreferencesFromCache_0001", 0, async function () {
        let startTime = new Date().getTime(); // time unit is mm
        for (let index = 0; index < BASE_COUNT; index++) {
            await dataPreferences.removePreferencesFromCache(context, NAME);
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(`${TAG}removePreferencesFromCache_0001 averageTime: ${averageTime} us`);
        expect(averageTime < BASELINE).assertTrue();
    })

    /**
     * @tc.desc PreferencesInstancePromiseJsPref_removePreferencesFromCache with diff pref
     */
    it("removePreferencesFromCache_0002", 0, async function () {
        for (let index = 0; index < BASE_COUNT; index++) {
            await dataPreferences.getPreferences(context, `${NAME}${index}`); // put prefs into cache
        }

        let startTime = new Date().getTime(); // time unit is mm
        for (let index = 0; index < BASE_COUNT; index++) {
            await dataPreferences.removePreferencesFromCache(context, `${NAME}${index}`);
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(`${TAG}removePreferencesFromCache_0002 averageTime: ${averageTime} us`);
        expect(averageTime < BASELINE).assertTrue();
    })

    /**
     * @tc.desc PreferencesInstancePromiseJsPref_DeletePreferences without exist file and repeat one pref
     */
    it("DeletePreferences_0001", 0, async function () {
        let startTime = new Date().getTime(); // time unit is mm
        for (let index = 0; index < BASE_COUNT; index++) {
            await dataPreferences.deletePreferences(context, NAME);
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
        console.info(`${TAG}DeletePreferences_0001 averageTime: ${averageTime} us`);
        expect(averageTime < BASELINE).assertTrue();
    })

    /**
     * @tc.desc PreferencesInstancePromiseJsPref_DeletePreferences with open exist diff file.
     * Warn: this depends on testcase execute order, otherwise testcase will execute very slow.
     */
    it("DeletePreferences_0002", 0, async function () {
        let startTime = new Date().getTime(); // time unit is mm
        for (let index = 0; index < DELETE_BASE_COUNT; index++) {
            await dataPreferences.deletePreferences(context, `${NAME}${index}`);
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / DELETE_BASE_COUNT;
        console.info(`${TAG}DeletePreferences_0002 averageTime: ${averageTime} us`);
        expect(averageTime < BASELINE).assertTrue();
    })
})