/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

/**
 * @file
 * @kit ArkData
 */

import BaseContext from 'BaseContext'

type AsyncCallback<T> = (data: T) => T;
type Callback<T> = (data: T) => void;

/**
 * Provides interfaces to obtain and modify preferences data.
 *
 * @namespace preferences
 * @syscap SystemCapability.DistributedDataManager.Preferences.Core
 * @since 9
 * @name preferences
 */
/**
 * Provides interfaces to obtain and modify preferences data.
 *
 * @namespace preferences
 * @syscap SystemCapability.DistributedDataManager.Preferences.Core
 * @crossplatform
 * @since 10
 * @name preferences
 */
/**
 * Provides interfaces to obtain and modify preferences data.
 *
 * @namespace preferences
 * @syscap SystemCapability.DistributedDataManager.Preferences.Core
 * @crossplatform
 * @atomicservice
 * @since 11
 * @name preferences
 */
export namespace preferences {
    loadLibrary("ani_preferences");
    export native function executeGetOpt(context: BaseContext, options: Options) : Preferences;
    export native function executeGetName(context: BaseContext, name: string) : Preferences;
    export native function executeRemoveName(context: BaseContext, name: string) : int;
    export native function executeRemoveOpt(context: BaseContext, options: Options) : int;

    export native function flushSync(obj :Preferences): int;
    export native function getInner(obj :Preferences, key: string, defValue: ValueType): ValueType;
    native function putInner(obj :Preferences, key: string, value: ValueType): void;

    export function putSyncFunc(obj :Preferences, key: string, value: ValueType): int {
      putInner(obj, key, value);
      return 0;
    }

    export native function deleteSyncInner(obj :Preferences, key: string): int;

    export native function hasSyncInner(obj :Preferences, key: string): boolean;

  /**
   * Indicates possible value types
   *
   * @typedef {number | string | boolean | Array<number> | Array<string> | Array<boolean>}
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @since 9
   */
  /**
   * Indicates possible value types
   *
   * @typedef {number | string | boolean | Array<number> | Array<string> | Array<boolean>}
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @since 10
   */
  /**
   * Indicates possible value types
   *
   * @typedef {number | string | boolean | Array<number> | Array<string> | Array<boolean> | Uint8Array}
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @atomicservice
   * @since 11
   */
  /**
   * Indicates possible value types
   *
   * @typedef {number | string | boolean | Array<number> | Array<string> | Array<boolean> |
   * Uint8Array | object | bigint}
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @atomicservice
   * @since 12
   */
  type ValueType = number | string | boolean | Array<number> | Array<string> | Array<boolean> |
    Uint8Array | object | bigint;

  /**
   * Indicates the maximum length of a key (80 characters).
   *
   * @constant
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @since 9
   */
  /**
   * Indicates the maximum length of a key (80 characters).
   *
   * @constant
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @since 10
   */
  /**
   * Indicates the maximum length of a key (80 characters).
   *
   * @constant
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 11
   */
  /**
   * Maximum length of a key.
   *
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 12
   */
  const MAX_KEY_LENGTH: number;

  /**
   * Indicates the maximum length of a string (8192 characters).
   *
   * @constant
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @since 9
   */
  /**
   * Indicates the maximum length of a string (8192 characters).
   *
   * @constant
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @since 10
   */
  /**
   * Indicates the maximum length of a string (8192 characters).
   *
   * @constant
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 11
   */
  /**
   * Maximum length of a value.
   *
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 12
   */
  const MAX_VALUE_LENGTH: number;

  /**
   * Manages preferences file configurations.
   *
   * @interface Options
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @since 10
   */
  /**
   * Manages preferences file configurations.
   *
   * @interface Options
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 11
   */
  export interface Options {
    /**
     * The preferences file name.
     *
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @since 10
     */
    /**
     * The preferences file name.
     *
     * @type { string }
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    name: string;

    /**
     * Application Group Id.
     *
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @StageModelOnly
     * @since 10
     */
    /**
     * Application Group Id.
     *
     * @type { ?(string | null | undefined) }
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @StageModelOnly
     * @atomicservice
     * @since 11
     */
    dataGroupId?: string | null | undefined;
  }

  /**
   * Obtains a {@link Preferences} instance matching a specified preferences file name.
   * <p>The {@link references} instance loads all data of the preferences file and
   * resides in the memory. You can use removePreferencesFromCache to remove the instance from the memory.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { string } name - Indicates the preferences file name.
   * @param { AsyncCallback<Preferences> } callback - The {@link Preferences} instance matching the specified
   *        preferences file name.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @since 9
   */
  /**
   * Obtains a {@link Preferences} instance matching a specified preferences file name.
   * <p>The {@link references} instance loads all data of the preferences file and
   * resides in the memory. You can use removePreferencesFromCache to remove the instance from the memory.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { string } name - Indicates the preferences file name.
   * @param { AsyncCallback<Preferences> } callback - The {@link Preferences} instance matching the specified
   *        preferences file name.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @since 10
   */
  /**
   * Obtains a {@link Preferences} instance matching a specified preferences file name.
   * <p>The {@link references} instance loads all data of the preferences file and
   * resides in the memory. You can use removePreferencesFromCache to remove the instance from the memory.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { string } name - Indicates the preferences file name.
   * @param { AsyncCallback<Preferences> } callback - The {@link Preferences} instance matching the specified
   *        preferences file name.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @throws { BusinessError } 15500000 - Inner error.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 11
   */
  export function getPreferences(context: BaseContext, name: string, callback: AsyncCallback<Preferences>): void {
    console.log("in callback before.....")
    let p1 = taskpool.execute(executeGetName, context, name);
    p1.then((e :NullishType)=>{
        console.log("in callback then.....")
        let r =  e as Preferences;
        callback(r)
    });
  };

  /**
   * Obtains a {@link Preferences} instance matching a specified preferences file name.
   * <p>The {@link references} instance loads all data of the preferences file and
   * resides in the memory. You can use removePreferencesFromCache to remove the instance from the memory.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { Options } options - Indicates the {@link Options} option of preferences file position.
   * @param { AsyncCallback<Preferences> } callback - The {@link Preferences} instance matching the specified
   *        preferences file name.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 15501001 - Only supported in stage mode.
   * @throws { BusinessError } 15501002 - The data group id is not valid.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @since 10
   */
  /**
   * Obtains a {@link Preferences} instance matching a specified preferences file name.
   * <p>The {@link references} instance loads all data of the preferences file and
   * resides in the memory. You can use removePreferencesFromCache to remove the instance from the memory.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { Options } options - Indicates the {@link Options} option of preferences file position.
   * @param { AsyncCallback<Preferences> } callback - The {@link Preferences} instance matching the specified
   *        preferences file name.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 15500000 - Inner error.
   * @throws { BusinessError } 15501001 - Only supported in stage mode.
   * @throws { BusinessError } 15501002 - The data group id is not valid.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 11
   */
    export function getPreferences(context: BaseContext, options: Options,
      callback: AsyncCallback<Preferences>): void {
        console.log("in callback before.....")
        let p1 = taskpool.execute(executeGetOpt, context, options);
        p1.then((e :NullishType)=>{
            console.log("in callback then.....")
            let r =  e as Preferences;
            callback(r)
        });
    }

  /**
   * Obtains a {@link Preferences} instance matching a specified preferences file name.
   * <p>The {@link references} instance loads all data of the preferences file and
   * resides in the memory. You can use removePreferencesFromCache to remove the instance from the memory.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { string } name - Indicates the preferences file name.
   * @returns { Promise<Preferences> } The {@link Preferences} instance matching the specified preferences file name.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @since 9
   */
  /**
   * Obtains a {@link Preferences} instance matching a specified preferences file name.
   * <p>The {@link references} instance loads all data of the preferences file and
   * resides in the memory. You can use removePreferencesFromCache to remove the instance from the memory.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { string } name - Indicates the preferences file name.
   * @returns { Promise<Preferences> } The {@link Preferences} instance matching the specified preferences file name.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @since 10
   */
  /**
   * Obtains a {@link Preferences} instance matching a specified preferences file name.
   * <p>The {@link references} instance loads all data of the preferences file and
   * resides in the memory. You can use removePreferencesFromCache to remove the instance from the memory.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { string } name - Indicates the preferences file name.
   * @returns { Promise<Preferences> } The {@link Preferences} instance matching the specified preferences file name.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @throws { BusinessError } 15500000 - Inner error.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 11
   */
    export function getPreferences(context: BaseContext, name: string): Promise<Preferences> {
      let p = new Promise<Preferences>((resolve: (v: Preferences) => void,
        reject: (error: Object) => void) => {
          let p1 = taskpool.execute(executeGetName, context, name);
          p1.then((e :NullishType)=>{
              console.log("in promise then.....")
              let r =  e as Preferences;
              resolve(r);
          });
      });
      return p;
    }

  /**
   * Obtains a {@link Preferences} instance matching a specified preferences file name.
   * <p>The {@link references} instance loads all data of the preferences file and
   * resides in the memory. You can use removePreferencesFromCache to remove the instance from the memory.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { Options } options - Indicates the {@link Options} option of preferences file position.
   * @returns { Promise<Preferences> } The {@link Preferences} instance matching the specified preferences file name.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 15501001 - Only supported in stage mode.
   * @throws { BusinessError } 15501002 - The data group id is not valid.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @since 10
   */
  /**
   * Obtains a {@link Preferences} instance matching a specified preferences file name.
   * <p>The {@link references} instance loads all data of the preferences file and
   * resides in the memory. You can use removePreferencesFromCache to remove the instance from the memory.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { Options } options - Indicates the {@link Options} option of preferences file position.
   * @returns { Promise<Preferences> } The {@link Preferences} instance matching the specified preferences file name.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 15500000 - Inner error.
   * @throws { BusinessError } 15501001 - Only supported in stage mode.
   * @throws { BusinessError } 15501002 - The data group id is not valid.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 11
   */
    export function getPreferences(context: BaseContext, options: Options): Promise<Preferences> {
      let p = new Promise<Preferences>((resolve: (v: Preferences) => void,
        reject: (error: Object) => void) => {
          console.log("in getPreferences , options is ", options);
          console.log("in getPreferences , context is ", context);
          let p1 = taskpool.execute(executeGetOpt, context, options);
          p1.then((e :NullishType)=>{
              console.log("in promise then.....")
              let r =  e as Preferences;
              resolve(r);
          });
      });
      return p;
    }

  /**
   * Deletes a {@link Preferences} instance matching a specified preferences file name
   * from the cache.
   * <p>When deleting the {@link Preferences} instance, you must release all references
   * of the instance. In addition, do not use the instance to perform data operations. Otherwise, data inconsistency
   * will occur.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { string } name - Indicates the preferences file name.
   * @param { AsyncCallback<void> } callback - Indicates the callback function.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @since 9
   */
  /**
   * Deletes a {@link Preferences} instance matching a specified preferences file name
   * from the cache.
   * <p>When deleting the {@link Preferences} instance, you must release all references
   * of the instance. In addition, do not use the instance to perform data operations. Otherwise, data inconsistency
   * will occur.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { string } name - Indicates the preferences file name.
   * @param { AsyncCallback<void> } callback - Indicates the callback function.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @since 10
   */
  /**
   * Deletes a {@link Preferences} instance matching a specified preferences file name
   * from the cache.
   * <p>When deleting the {@link Preferences} instance, you must release all references
   * of the instance. In addition, do not use the instance to perform data operations. Otherwise, data inconsistency
   * will occur.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { string } name - Indicates the preferences file name.
   * @param { AsyncCallback<void> } callback - Indicates the callback function.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @throws { BusinessError } 15500000 - Inner error.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 11
   */
  export function removePreferencesFromCache(context: BaseContext, name: string, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(executeRemoveName, context, name);
    p1.then((e :NullishType)=>{
        console.log("in callback then. e is ", e)
        let r =  undefined;
        callback(r)
    });
  };

  /**
   * Deletes a {@link Preferences} instance matching a specified preferences file name
   * from the cache.
   * <p>When deleting the {@link Preferences} instance, you must release all references
   * of the instance. In addition, do not use the instance to perform data operations. Otherwise, data inconsistency
   * will occur.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { Options } options - Indicates the {@link Options} option of preferences file position.
   * @param { AsyncCallback<void> } callback - Indicates the callback function.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 15501001 - Only supported in stage mode.
   * @throws { BusinessError } 15501002 - The data group id is not valid.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @since 10
   */
  /**
   * Deletes a {@link Preferences} instance matching a specified preferences file name
   * from the cache.
   * <p>When deleting the {@link Preferences} instance, you must release all references
   * of the instance. In addition, do not use the instance to perform data operations. Otherwise, data inconsistency
   * will occur.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { Options } options - Indicates the {@link Options} option of preferences file position.
   * @param { AsyncCallback<void> } callback - Indicates the callback function.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 15500000 - Inner error.
   * @throws { BusinessError } 15501001 - Only supported in stage mode.
   * @throws { BusinessError } 15501002 - The data group id is not valid.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 11
   */
  export function removePreferencesFromCache(context: BaseContext, options: Options, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(executeRemoveOpt, context, options);
    p1.then((e :NullishType)=>{
        console.log("in callback then. e is ", e)
        let r =  undefined;
        callback(r)
    });
  };

  /**
   * Deletes a {@link Preferences} instance matching a specified preferences file name
   * from the cache.
   * <p>When deleting the {@link Preferences} instance, you must release all references
   * of the instance. In addition, do not use the instance to perform data operations. Otherwise, data inconsistency
   * will occur.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { string } name - Indicates the preferences file name.
   * @returns { Promise<void> } A promise object.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @since 9
   */
  /**
   * Deletes a {@link Preferences} instance matching a specified preferences file name
   * from the cache.
   * <p>When deleting the {@link Preferences} instance, you must release all references
   * of the instance. In addition, do not use the instance to perform data operations. Otherwise, data inconsistency
   * will occur.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { string } name - Indicates the preferences file name.
   * @returns { Promise<void> } A promise object.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @since 10
   */
  /**
   * Deletes a {@link Preferences} instance matching a specified preferences file name
   * from the cache.
   * <p>When deleting the {@link Preferences} instance, you must release all references
   * of the instance. In addition, do not use the instance to perform data operations. Otherwise, data inconsistency
   * will occur.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { string } name - Indicates the preferences file name.
   * @returns { Promise<void> } A promise object.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @throws { BusinessError } 15500000 - Inner error.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 11
   */
  export function removePreferencesFromCache(context: BaseContext, name: string): Promise<int> {
    let p = new Promise<int>((resolve: (v: int) => void,
      reject: (error: Object) => void) => {
        let p1 = taskpool.execute(executeRemoveName, context, name);
        p1.then((e : NullishType)=>{
            console.log("in Promise then. e is ", e)
            let r = e as int;
            resolve(r);
        });
    });
    return p;
  };

  /**
   * Deletes a {@link Preferences} instance matching a specified preferences file name
   * from the cache.
   * <p>When deleting the {@link Preferences} instance, you must release all references
   * of the instance. In addition, do not use the instance to perform data operations. Otherwise, data inconsistency
   * will occur.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { Options } options - Indicates the {@link Options} option of preferences file position.
   * @returns { Promise<void> } A promise object.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 15501001 - Only supported in stage mode.
   * @throws { BusinessError } 15501002 - The data group id is not valid.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @since 10
   */
  /**
   * Deletes a {@link Preferences} instance matching a specified preferences file name
   * from the cache.
   * <p>When deleting the {@link Preferences} instance, you must release all references
   * of the instance. In addition, do not use the instance to perform data operations. Otherwise, data inconsistency
   * will occur.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { Options } options - Indicates the {@link Options} option of preferences file position.
   * @returns { Promise<void> } A promise object.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 15500000 - Inner error.
   * @throws { BusinessError } 15501001 - Only supported in stage mode.
   * @throws { BusinessError } 15501002 - The data group id is not valid.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 11
   */
  export function removePreferencesFromCache(context: BaseContext, options: Options): Promise<int> {
    let p = new Promise<int>((resolve: (v: int) => void,
      reject: (error: Object) => void) => {
        let p1 = taskpool.execute(executeRemoveOpt, context, options);
        p1.then((e : NullishType)=>{
            console.log("in Promise then. e is ", e)
            let r = e as int;
            resolve(r);
        });
    });
    return p;
  };

  /**
   * Deletes a {@link Preferences} instance matching a specified preferences file name
   * from the cache. This interface is executed synchronously.
   * <p>When deleting the {@link Preferences} instance, you must release all references
   * of the instance. In addition, do not use the instance to perform data operations. Otherwise, data inconsistency
   * will occur.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { string } name - Indicates the preferences file name.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @since 10
   */
  /**
   * Deletes a {@link Preferences} instance matching a specified preferences file name
   * from the cache. This interface is executed synchronously.
   * <p>When deleting the {@link Preferences} instance, you must release all references
   * of the instance. In addition, do not use the instance to perform data operations. Otherwise, data inconsistency
   * will occur.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { string } name - Indicates the preferences file name.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @throws { BusinessError } 15500000 - Inner error.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 11
   */
  function removePreferencesFromCacheSync(context: BaseContext, name: string): void {};

  /**
   * Deletes a {@link Preferences} instance matching a specified preferences file name
   * from the cache. This interface is executed synchronously.
   * <p>When deleting the {@link Preferences} instance, you must release all references
   * of the instance. In addition, do not use the instance to perform data operations. Otherwise, data inconsistency
   * will occur.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { Options } options - Indicates the {@link Options} option of preferences file position.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 15501001 - Only supported in stage mode.
   * @throws { BusinessError } 15501002 - The data group id is not valid.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @since 10
   */
  /**
   * Deletes a {@link Preferences} instance matching a specified preferences file name
   * from the cache. This interface is executed synchronously.
   * <p>When deleting the {@link Preferences} instance, you must release all references
   * of the instance. In addition, do not use the instance to perform data operations. Otherwise, data inconsistency
   * will occur.
   *
   * @param { Context } context - Indicates the context of application or capability.
   * @param { Options } options - Indicates the {@link Options} option of preferences file position.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   *                                                                   2. Incorrect parameter types;
   *                                                                   3. Parameter verification failed.
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 15500000 - Inner error.
   * @throws { BusinessError } 15501001 - Only supported in stage mode.
   * @throws { BusinessError } 15501002 - The data group id is not valid.
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 11
   */
  function removePreferencesFromCacheSync(context: BaseContext, options: Options): void {};

  /**
   * Provides interfaces to obtain and modify preferences data.
   * <p>The preferences data is stored in a file, which matches only one {@link Preferences} instance in the memory.
   * You can use getPreferences to obtain the {@link Preferences} instance matching
   * the file that stores preferences data, and use movePreferencesFromCache
   * to remove the {@link Preferences} instance from the memory.
   *
   * @interface Preferences
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @since 9
   */
  /**
   * Provides interfaces to obtain and modify preferences data.
   * <p>The preferences data is stored in a file, which matches only one {@link Preferences} instance in the memory.
   * You can use getPreferences to obtain the {@link Preferences} instance matching
   * the file that stores preferences data, and use movePreferencesFromCache
   * to remove the {@link Preferences} instance from the memory.
   *
   * @interface Preferences
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @since 10
   */
  /**
   * Provides interfaces to obtain and modify preferences data.
   * <p>The preferences data is stored in a file, which matches only one {@link Preferences} instance in the memory.
   * You can use getPreferences to obtain the {@link Preferences} instance matching
   * the file that stores preferences data, and use movePreferencesFromCache
   * to remove the {@link Preferences} instance from the memory.
   *
   * @interface Preferences
   * @syscap SystemCapability.DistributedDataManager.Preferences.Core
   * @crossplatform
   * @atomicservice
   * @since 11
   */
  export interface Preferences {
    /**
     * Obtains the value of a preferences in the ValueType format.
     * <p>If the value is {@code null} or not in the ValueType format, the default value is returned.
     *
     * @param { string } key - Indicates the key of the preferences. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } defValue - Indicates the default value to return.
     * @param { AsyncCallback<ValueType> } callback - The value matching the specified key if it is found;
     *        returns the default value otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @since 9
     */
    /**
     * Obtains the value of a preferences in the ValueType format.
     * <p>If the value is {@code null} or not in the ValueType format, the default value is returned.
     *
     * @param { string } key - Indicates the key of the preferences. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } defValue - Indicates the default value to return.
     * @param { AsyncCallback<ValueType> } callback - The value matching the specified key if it is found;
     *        returns the default value otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @since 10
     */
    /**
     * Obtains the value of a preferences in the ValueType format.
     * <p>If the value is {@code null} or not in the ValueType format, the default value is returned.
     *
     * @param { string } key - Indicates the key of the preferences. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } defValue - Indicates the default value to return.
     * @param { AsyncCallback<ValueType> } callback - The value matching the specified key if it is found;
     *        returns the default value otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @throws { BusinessError } 15500000 - Inner error.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    get(key: string, defValue: ValueType, callback: AsyncCallback<ValueType>): void;

    /**
     * Obtains the value of a preferences in the ValueType format.
     * <p>If the value is {@code null} or not in the ValueType format, the default value is returned.
     *
     * @param { string } key - Indicates the key of the preferences. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } defValue - Indicates the default value to return.
     * @returns { Promise<ValueType> } The value matching the specified key if it is found;
     *          returns the default value otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @since 9
     */
    /**
     * Obtains the value of a preferences in the ValueType format.
     * <p>If the value is {@code null} or not in the ValueType format, the default value is returned.
     *
     * @param { string } key - Indicates the key of the preferences. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } defValue - Indicates the default value to return.
     * @returns { Promise<ValueType> } The value matching the specified key if it is found;
     *          returns the default value otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @since 10
     */
    /**
     * Obtains the value of a preferences in the ValueType format.
     * <p>If the value is {@code null} or not in the ValueType format, the default value is returned.
     *
     * @param { string } key - Indicates the key of the preferences. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } defValue - Indicates the default value to return.
     * @returns { Promise<ValueType> } The value matching the specified key if it is found;
     *          returns the default value otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @throws { BusinessError } 15500000 - Inner error.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    get(key: string, defValue: ValueType): Promise<ValueType>;

    /**
     * Obtains the value of a preferences in the ValueType format. This interface is executed synchronously.
     * <p>If the value is {@code null} or not in the ValueType format, the default value is returned.
     *
     * @param { string } key - Indicates the key of the preferences. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } defValue - Indicates the default value to return.
     * @returns { ValueType } The value matching the specified key if it is found;
     *          returns the default value otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @since 10
     */
    /**
     * Obtains the value of a preferences in the ValueType format. This interface is executed synchronously.
     * <p>If the value is {@code null} or not in the ValueType format, the default value is returned.
     *
     * @param { string } key - Indicates the key of the preferences. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } defValue - Indicates the default value to return.
     * @returns { ValueType } The value matching the specified key if it is found;
     *          returns the default value otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @throws { BusinessError } 15500000 - Inner error.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    getSync(key: string, defValue: ValueType): ValueType;

    /**
     * Checks whether the {@link Preferences} object contains a preferences matching a specified key.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @param { AsyncCallback<boolean> } callback - {@code true} if the {@link Preferences} object contains
     *         a preferences with the specified key;returns {@code false} otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @since 9
     */
    /**
     * Checks whether the {@link Preferences} object contains a preferences matching a specified key.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @param { AsyncCallback<boolean> } callback - {@code true} if the {@link Preferences} object contains
     *         a preferences with the specified key;returns {@code false} otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @since 10
     */
    /**
     * Checks whether the {@link Preferences} object contains a preferences matching a specified key.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @param { AsyncCallback<boolean> } callback - {@code true} if the {@link Preferences} object contains
     *         a preferences with the specified key;returns {@code false} otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @throws { BusinessError } 15500000 - Inner error.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    has(key: string, callback: AsyncCallback<boolean>): void;

    /**
     * Checks whether the {@link Preferences} object contains a preferences matching a specified key.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @returns { Promise<boolean> } {@code true} if the {@link Preferences} object contains
     *         a preferences with the specified key; returns {@code false} otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @since 9
     */
    /**
     * Checks whether the {@link Preferences} object contains a preferences matching a specified key.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @returns { Promise<boolean> } {@code true} if the {@link Preferences} object contains
     *         a preferences with the specified key; returns {@code false} otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @since 10
     */
    /**
     * Checks whether the {@link Preferences} object contains a preferences matching a specified key.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @returns { Promise<boolean> } {@code true} if the {@link Preferences} object contains
     *         a preferences with the specified key; returns {@code false} otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @throws { BusinessError } 15500000 - Inner error.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    has(key: string): Promise<boolean>;

    /**
     * Checks whether the {@link Preferences} object contains a preferences matching a specified key. This interface
     * is executed synchronously.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @returns { boolean } {@code true} if the {@link Preferences} object contains
     *         a preferences with the specified key; returns {@code false} otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @since 10
     */
    /**
     * Checks whether the {@link Preferences} object contains a preferences matching a specified key. This interface
     * is executed synchronously.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *         <tt>MAX_KEY_LENGTH</tt>.
     * @returns { boolean } {@code true} if the {@link Preferences} object contains
     *         a preferences with the specified key; returns {@code false} otherwise.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @throws { BusinessError } 15500000 - Inner error.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    hasSync(key: string): boolean;

    /**
     * Sets an int value for the key in the {@link Preferences} object.
     * <p>You can call the {@link #flush} method to save the {@link Preferences} object to the
     * file.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } value - Indicates the value of the preferences.
     *        <tt>MAX_VALUE_LENGTH</tt>.
     * @param { AsyncCallback<void> } callback - Indicates the callback function.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @since 9
     */
    /**
     * Sets an int value for the key in the {@link Preferences} object.
     * <p>You can call the {@link #flush} method to save the {@link Preferences} object to the
     * file.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } value - Indicates the value of the preferences.
     *        <tt>MAX_VALUE_LENGTH</tt>.
     * @param { AsyncCallback<void> } callback - Indicates the callback function.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @since 10
     */
    /**
     * Sets an int value for the key in the {@link Preferences} object.
     * <p>You can call the {@link #flush} method to save the {@link Preferences} object to the
     * file.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } value - Indicates the value of the preferences.
     *        <tt>MAX_VALUE_LENGTH</tt>.
     * @param { AsyncCallback<void> } callback - Indicates the callback function.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @throws { BusinessError } 15500000 - Inner error.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    put(key: string, value: ValueType, callback: AsyncCallback<void>): void;

    /**
     * Sets an int value for the key in the {@link Preferences} object.
     * <p>You can call the {@link #flush} method to save the {@link Preferences} object to the
     * file.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } value - Indicates the value of the preferences.
     *        <tt>MAX_VALUE_LENGTH</tt>.
     * @returns { Promise<void> } A promise object.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @since 9
     */
    /**
     * Sets an int value for the key in the {@link Preferences} object.
     * <p>You can call the {@link #flush} method to save the {@link Preferences} object to the
     * file.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } value - Indicates the value of the preferences.
     *        <tt>MAX_VALUE_LENGTH</tt>.
     * @returns { Promise<void> } A promise object.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @since 10
     */
    /**
     * Sets an int value for the key in the {@link Preferences} object.
     * <p>You can call the {@link #flush} method to save the {@link Preferences} object to the
     * file.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } value - Indicates the value of the preferences.
     *        <tt>MAX_VALUE_LENGTH</tt>.
     * @returns { Promise<int> } A promise object.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @throws { BusinessError } 15500000 - Inner error.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    put(key: string, value: ValueType): Promise<int>;

    /**
     * Sets an int value for the key in the {@link Preferences} object. This interface is executed synchronously.
     * <p>You can call the {@link #flush} method to save the {@link Preferences} object to the
     * file.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } value - Indicates the value of the preferences.
     *        <tt>MAX_VALUE_LENGTH</tt>.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @since 10
     */
    /**
     * Sets an int value for the key in the {@link Preferences} object. This interface is executed synchronously.
     * <p>You can call the {@link #flush} method to save the {@link Preferences} object to the
     * file.
     *
     * @param { string } key - Indicates the key of the preferences to modify. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @param { ValueType } value - Indicates the value of the preferences.
     *        <tt>MAX_VALUE_LENGTH</tt>.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @throws { BusinessError } 15500000 - Inner error.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    putSync(key: string, value: ValueType): void;

    /**
     * Deletes the preferences with a specified key from the {@link Preferences} object.
     * <p>You can call the {@link #flush} method to save the {@link Preferences} object to the
     * file.
     *
     * @param { string } key - Indicates the key of the preferences to delete. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @param { AsyncCallback<void> } callback - Indicates the callback function.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @since 9
     */
    /**
     * Deletes the preferences with a specified key from the {@link Preferences} object.
     * <p>You can call the {@link #flush} method to save the {@link Preferences} object to the
     * file.
     *
     * @param { string } key - Indicates the key of the preferences to delete. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @param { AsyncCallback<void> } callback - Indicates the callback function.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @since 10
     */
    /**
     * Deletes the preferences with a specified key from the {@link Preferences} object.
     * <p>You can call the {@link #flush} method to save the {@link Preferences} object to the
     * file.
     *
     * @param { string } key - Indicates the key of the preferences to delete. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @param { AsyncCallback<void> } callback - Indicates the callback function.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @throws { BusinessError } 15500000 - Inner error.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    delete(key: string, callback: AsyncCallback<void>): void;

    /**
     * Deletes the preferences with a specified key from the {@link Preferences} object.
     * <p>You can call the {@link #flush} method to save the {@link Preferences} object to the
     * file.
     *
     * @param { string } key - Indicates the key of the preferences to delete. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @returns { Promise<void> } A promise object.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @since 9
     */
    /**
     * Deletes the preferences with a specified key from the {@link Preferences} object.
     * <p>You can call the {@link #flush} method to save the {@link Preferences} object to the
     * file.
     *
     * @param { string } key - Indicates the key of the preferences to delete. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @returns { Promise<void> } A promise object.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @since 10
     */
    /**
     * Deletes the preferences with a specified key from the {@link Preferences} object.
     * <p>You can call the {@link #flush} method to save the {@link Preferences} object to the
     * file.
     *
     * @param { string } key - Indicates the key of the preferences to delete. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @returns { Promise<void> } A promise object.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @throws { BusinessError } 15500000 - Inner error.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    delete(key: string): Promise<int>;

    /**
     * Deletes the preferences with a specified key from the {@link Preferences} object. This interface is
     * executed synchronously. <p>You can call the {@link #flush} method to save the {@link Preferences}
     * object to the file.
     *
     * @param { string } key - Indicates the key of the preferences to delete. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @since 10
     */
    /**
     * Deletes the preferences with a specified key from the {@link Preferences} object. This interface is
     * executed synchronously. <p>You can call the {@link #flush} method to save the {@link Preferences}
     * object to the file.
     *
     * @param { string } key - Indicates the key of the preferences to delete. It cannot be {@code null} or empty.
     *        <tt>MAX_KEY_LENGTH</tt>.
     * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
     *                                                                   2. Incorrect parameter types;
     *                                                                   3. Parameter verification failed.
     * @throws { BusinessError } 15500000 - Inner error.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    deleteSync(key: string): void;

    /**
     * Asynchronously saves the {@link Preferences} object to the file.
     *
     * @param { AsyncCallback<void> } callback - Indicates the callback function.
     * @throws { BusinessError } 401 - Parameter error. Mandatory parameters are left unspecified;
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @since 9
     */
    /**
     * Asynchronously saves the {@link Preferences} object to the file.
     *
     * @param { AsyncCallback<void> } callback - Indicates the callback function.
     * @throws { BusinessError } 401 - Parameter error. Mandatory parameters are left unspecified;
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @since 10
     */
    /**
     * Asynchronously saves the {@link Preferences} object to the file.
     *
     * @param { AsyncCallback<void> } callback - Indicates the callback function.
     * @throws { BusinessError } 401 - Parameter error. Mandatory parameters are left unspecified.
     * @throws { BusinessError } 15500000 - Inner error.
     * @syscap SystemCapability.DistributedDataManager.Preferences.Core
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    flush(callback: AsyncCallback<void>): void;
  }

  class PreferencesImpl implements Preferences {
    private nativePtr:long = 0;
    constructor(context:long) {
      console.log("in constructor, context is ", context)
      this.nativePtr = context;
    }

    getNativePtr(): long {
      return this.nativePtr;
    }

    get(key: string, defValue: ValueType, callback: AsyncCallback<ValueType>): void {
      console.log("Start get in asyncCallback thread.")
      let p1 = taskpool.execute(getInner, this, key, defValue);
      p1.then((e :NullishType)=>{
          let r =  e as ValueType;
          console.log("in callback then. r is ", r)
          callback(r)
      });
    }

    get(key: string, defValue: ValueType): Promise<ValueType> {
      console.log("Start get in promise thread.")
      let p = new Promise<ValueType>((resolve: (v: ValueType) => void,
        reject: (error: Object) => void) => {
          let p1 = taskpool.execute(getInner, this, key, defValue);
          p1.then((e :NullishType)=>{
              let r =  e as ValueType;
              console.log("in promise then.....")
              resolve(r);
          });
      });
      return p;
    }

    getSync(key: string, defValue: ValueType): ValueType {
      return getInner(this, key, defValue);
    }

    has(key: string, callback: AsyncCallback<boolean>): void {
      console.log("Start get in asyncCallback thread.")
      let p1 = taskpool.execute(hasSyncInner, this, key);
      p1.then((e :NullishType)=>{
          let r =  e as boolean;
          console.log("in callback then. r is ", r)
          callback(r)
      });
    }

    has(key: string): Promise<boolean> {
      console.log("Start get in promise thread.")
      let p = new Promise<boolean>((resolve: (v: boolean) => void,
        reject: (error: Object) => void) => {
          let p1 = taskpool.execute(hasSyncInner, this, key);
          p1.then((e :NullishType)=>{
              let r =  e as boolean;
              console.log("in promise then, r is: ", r)
              resolve(r);
          });
      });
      return p;
    }

    hasSync(key: string): boolean {
        return hasSyncInner(this, key);
    }

    put(key: string, value: ValueType, callback: AsyncCallback<void>): void {
      console.log("Start put in asyncCallback thread.")
      let p1 = taskpool.execute(putSyncFunc, this, key, value);
      p1.then((e :NullishType)=>{
          let r = undefined;
          callback(r)
      });
    }

    put(key: string, value: ValueType): Promise<int> {
      console.log("Start put in promise thread.")
      let p = new Promise<int>((resolve: (v: int) => void, reject: (error: Object) => void) => {
          let p1 = taskpool.execute(putSyncFunc, this, key, value);
          p1.then((e :NullishType)=>{
              let r = e as int;
              resolve(r);
          })
      });
      return p;
    }

    putSync(key: string, value: ValueType): void {
      putSyncFunc(this, key, value);
    }

    delete(key: string, callback: AsyncCallback<void>): void {
      console.log("Start put in asyncCallback thread.")
      let p1 = taskpool.execute(deleteSyncInner, this, key);
      p1.then((e :NullishType)=>{
          let r = e as int;
          console.log("In delete callback, ret is: ", r);
          callback(undefined);
      });
    }

    delete(key: string): Promise<int> {
      console.log("Start put in asyncCallback thread.")
      let p = new Promise<int>((resolve: (v: int) => void, reject: (error: Object) => void) => {
          let p1 = taskpool.execute(deleteSyncInner, this, key);
            p1.then((e :NullishType)=>{
              let r = e as int;
              console.log("In delete Promise, ret is: ", r);
              resolve(r);
          })
      });
      return p;
    }

    deleteSync(key: string): void {
      deleteSyncInner(this, key);
    };

    flush(callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute(flushSync, this);
      p1.then((e :NullishType)=>{
        console.log("in callback then. r is ", e)
        let r =  undefined;
        callback(r)
      });
    }
  }

}
