/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { AsyncCallback } from "@ohos.base"
import { BusinessError } from "@ohos.base"
import BaseContext from 'application.BaseContext'

// type AsyncCallback<T> = (data: T) => T;
// type Callback<T> = (data: T) => void;

export namespace preferences {
  loadLibrary("ani_preferences");
  export native function executeGetByOpt(context: BaseContext, options: Options) : Preferences;
  export native function executeGetByName(context: BaseContext, name: string) : Preferences;
  export native function executeRemoveByName(context: BaseContext, name: string) : int;
  export native function executeRemoveByOpt(context: BaseContext, options: Options) : int;

  export native function flushSync(obj :Preferences): int;
  export native function getInner(obj :Preferences, key: string, defValue: ValueType): ValueType;
  native function putInner(obj :Preferences, key: string, value: ValueType): void;

  export function putSyncFunc(obj :Preferences, key: string, value: ValueType): int {
    putInner(obj, key, value);
    return 0;
  }

  export native function deleteSyncInner(obj :Preferences, key: string): int;

  export native function hasSyncInner(obj :Preferences, key: string): boolean;

  type ValueType = number | string | boolean | Array<number> | Array<string> | Array<boolean> |
    Uint8Array | object | bigint;

  export interface Options {
    name: string;
    dataGroupId?: string | null | undefined;
  }

  export function getPreferences(context: BaseContext, name: string, callback: AsyncCallback<Preferences>): void {
    console.log("in callback before.....")
    let p1 = taskpool.execute(executeGetByName, context, name);
    p1.then((data: NullishType) => {
      let r =  data as Preferences;
      let err : BusinessError<void>
      callback(err, r);
    }).catch((error: NullishType) => {
      let err =  error as BusinessError<void>;
      let data = new PreferencesImpl(0);
      callback(err, data);
    });
  };

    export function getPreferences(context: BaseContext, options: Options,
      callback: AsyncCallback<Preferences>): void {
        console.log("in callback before.....")
        let p1 = taskpool.execute(executeGetByOpt, context, options);
        p1.then((data: NullishType) => {
          let r =  data as Preferences;
          let err : BusinessError<void>
          callback(err, r);
        }).catch((error: NullishType) => {
          let err =  error as BusinessError<void>;
          let data = new PreferencesImpl(0);
          callback(err, data);
        });
    }

    export function getPreferences(context: BaseContext, name: string): Promise<Preferences> {
      let p = new Promise<Preferences>((resolve: (v: Preferences) => void,
        reject: (error: Object) => void) => {
          let p1 = taskpool.execute(executeGetByName, context, name);
          p1.then((e :NullishType)=>{
              console.log("in promise then.....")
              let r =  e as Preferences;
              resolve(r);
          }).catch((err: Error) : Preferences => {
            reject(err);
          });
      });
      return p;
    }

    export function getPreferences(context: BaseContext, options: Options): Promise<Preferences> {
      let p = new Promise<Preferences>((resolve: (v: Preferences) => void,
        reject: (error: Object) => void) => {
          console.log("in getPreferences , options is ", options);
          console.log("in getPreferences , context is ", context);
          let p1 = taskpool.execute(executeGetByOpt, context, options);
          p1.then((e :NullishType)=>{
              console.log("in promise then.....")
              let r =  e as Preferences;
              resolve(r);
          }).catch((err: Error) : Preferences => {
            reject(err);
          });
      });
      return p;
    }

  export function removePreferencesFromCache(context: BaseContext, name: string, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(executeRemoveByName, context, name);
    p1.then((data: NullishType) => {
      let ret =  data as int;
      console.log("in removePreferencesFromCache callback then. ret is ", ret)
      let err : BusinessError<void>
      callback(err, undefined);
    }).catch((error: NullishType) => {
      let err =  error as BusinessError<void>;
      callback(err, undefined);
    });
  };

  export function removePreferencesFromCache(context: BaseContext, options: Options,
    callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute(executeRemoveByOpt, context, options);
    p1.then((data: NullishType) => {
      let ret =  data as int;
      console.log("in removePreferencesFromCache callback then. ret is ", ret)
      let err : BusinessError<void>
      callback(err, undefined);
    }).catch((error: NullishType) => {
      let err =  error as BusinessError<void>;
      callback(err, undefined);
    });
  };

  export function removePreferencesFromCache(context: BaseContext, name: string): Promise<void> {
    let p = new Promise<void>((resolve: (v: undefined) => void,
      reject: (error: Object) => void) : void => {
        let p1 = taskpool.execute(executeRemoveByName, context, name);
        p1.then((e : NullishType) : void =>{
          console.log("in Promise then. e is ", e)
          resolve(undefined);
        }).catch((err: Error) : void => {
          reject(err);
        });
    });
    return p;
  };

  export function removePreferencesFromCache(context: BaseContext, options: Options): Promise<void> {
    let p = new Promise<void>((resolve: (v: undefined) => void,
      reject: (error: Object) => void) : void => {
        let p1 = taskpool.execute(executeRemoveByOpt, context, options);
        p1.then((e : NullishType) : void=>{
          console.log("in Promise then. e is ", e)
          resolve(undefined);
        }).catch((err: Error) : void => {
          reject(err);
        });
    });
    return p;
  };

  export interface Preferences {

    get(key: string, defValue: ValueType, callback: AsyncCallback<ValueType>): void;

    get(key: string, defValue: ValueType): Promise<ValueType>;
    getSync(key: string, defValue: ValueType): ValueType;

    has(key: string, callback: AsyncCallback<boolean>): void;
    has(key: string): Promise<boolean>;
    hasSync(key: string): boolean;
    put(key: string, value: ValueType, callback: AsyncCallback<void>): void;
    put(key: string, value: ValueType): Promise<void>;
    putSync(key: string, value: ValueType): void;
    delete(key: string, callback: AsyncCallback<void>): void;
    delete(key: string): Promise<void>;
    deleteSync(key: string): void;
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
      p1.then((data: NullishType) => {
        let ret =  data as ValueType;
        console.log("in get callback then. ret is ", ret)
        let err : BusinessError<void>
        callback(err, ret);
      }).catch((error: NullishType) => {
        let err =  error as BusinessError<void>;
        let data : ValueType;
        callback(err, data);
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
          }).catch((err: Error) : ValueType => {
            reject(err);
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
      p1.then((data: NullishType) => {
        let ret =  data as boolean;
        console.log("in get callback then. ret is ", ret)
        let err : BusinessError<void>
        callback(err, ret);
      }).catch((error: NullishType) => {
        let err =  error as BusinessError<void>;
        let data : boolean;
        callback(err, data);
      });
    }

    has(key: string): Promise<boolean> {
      console.log("Start get in promise thread.")
      let p = new Promise<boolean>((resolve: (v: boolean) => void,
        reject: (error: Object) => void) => {
          let p1 = taskpool.execute(hasSyncInner, this, key);
          p1.then((e :NullishType) : boolean =>{
              let r =  e as boolean;
              console.log("in promise then, r is: ", r)
              resolve(r);
          }).catch((err: Error) : boolean => {
            reject(err);
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
      p1.then((data: NullishType) => {
        let ret =  data as int;
        console.log("in get callback then. ret is ", ret)
        let err : BusinessError<void>
        callback(err, undefined);
      }).catch((error: NullishType) => {
        let err =  error as BusinessError<void>;
        callback(err, undefined);
      });
    }

    put(key: string, value: ValueType): Promise<void> {
      console.log("Start put in promise thread.")
      let p = new Promise<void>((resolve: (v: undefined) => void,
        reject: (error: Object) => void) : void => {
          let p1 = taskpool.execute(putSyncFunc, this, key, value);
          p1.then((e :NullishType) : void =>{
            console.log("end put in promise thread.")
            resolve(undefined);
          }).catch((err: Error) : void => {
            reject(err);
          });
      });
      return p;
    }

    putSync(key: string, value: ValueType): void {
      putSyncFunc(this, key, value);
    }

    delete(key: string, callback: AsyncCallback<void>): void {
      console.log("Start put in asyncCallback thread.")
      let p1 = taskpool.execute(deleteSyncInner, this, key);
      p1.then((data: NullishType) => {
        let ret =  data as int;
        console.log("in get callback then. ret is ", ret)
        let err : BusinessError<void>
        callback(err, undefined);
      }).catch((error: NullishType) => {
        let err =  error as BusinessError<void>;
        callback(err, undefined);
      });
    }

    delete(key: string): Promise<void> {
      console.log("Start put in asyncCallback thread.")
      let p = new Promise<void>((resolve: (v: undefined) => void,
        reject: (error: Object) => void) : void => {
        let p1 = taskpool.execute(deleteSyncInner, this, key);
          p1.then((e :NullishType) : void=>{
            let r = e as int;
            console.log("In delete Promise, ret is: ", r);
            resolve(undefined);
        }).catch((err: Error) : void => {
          reject(err);
        });
      });
      return p;
    }

    deleteSync(key: string): void {
      deleteSyncInner(this, key);
    };

    flush(callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute(flushSync, this);
      p1.then((data: NullishType) => {
        let ret =  data as int;
        console.log("in get callback then. ret is ", ret)
        let err : BusinessError<void>
        callback(err, undefined);
      }).catch((error: NullishType) => {
        let err =  error as BusinessError<void>;
        callback(err, undefined);
      });
    }
  }
}
