/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import BaseContext  from 'BaseContext'

type ValueType = number | string | boolean | Array<number> | Array<string> | Array<boolean> | Uint8Array | object | bigint;

export class BusinessError<T = void> {
   code: number;
   data: T;
}

type AsyncCallback<T> = (data: T) => T;

class Result<T, E>{
    result:T;
    error:E;
    constructor(result: T , error: E) {
        this.result = result;
        this.error = error;
    }
}

export interface Options {
  name: string;
  dataGroupId ?: string | null | undefined;
}

export namespace preferences {
    loadLibrary("ani_preferences");
    export native function executeGetOpt(context: BaseContext, options: Options) : Preferences;
    export native function executeGetName(context: BaseContext, name: string) : Preferences;
    export native function executeRemoveName(context: BaseContext, name: string) : int;
    export native function executeRemoveOpt(context: BaseContext, options: Options) : int;

    export native function flushSync(obj: Object): int;
    export native function getInner(obj :Preferences, key: string, defValue: ValueType): ValueType;
    native function putInner(obj :Preferences, key: string, value: ValueType): void;
    export function putSyncFunc(obj :Preferences, key: string, value: ValueType): int {
      putInner(obj, key, value);
      return 0;
    }

    // native execute(context: BaseContext, options: Options):int;

    export function getPreferences(context: BaseContext, name: string, callback: AsyncCallback<Preferences>): void {
      console.log("in callback before.....")
      let p1 = taskpool.execute(executeGetName, context, name);
      p1.then((e :NullishType)=>{
          console.log("in callback then.....")
          let r =  e as Preferences;
          callback(r)
      });
    }

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

    export function removePreferencesFromCache(context: BaseContext, name: string, callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute(executeRemoveName, context, name);
      p1.then((e :NullishType)=>{
          console.log("in callback then. e is ", e)
          let r =  undefined;
          callback(r)
      });
    }

    export function removePreferencesFromCache(context: BaseContext, options: Options, callback: AsyncCallback<void>): void {
      let p1 = taskpool.execute(executeRemoveOpt, context, options);
      p1.then((e :NullishType)=>{
          console.log("in callback then. e is ", e)
          let r =  undefined;
          callback(r)
      });
    }

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
    }

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
    }

    export interface Preferences {
        get(key: string, defValue: ValueType, callback: AsyncCallback<ValueType>): void;
        get(key: string, defValue: ValueType): Promise<ValueType>;
        getSync(key: string, defValue: ValueType): ValueType;
        // has(key: string, callback: AsyncCallback<boolean>): void;
        // has(key: string): Promise<boolean>;
        put(key: string, value: ValueType, callback: AsyncCallback<void>): void;
        put(key: string, value: ValueType): Promise<int>;
        putSync(key: string, value: ValueType): void;
        // delete(key: string, callback: AsyncCallback<int>): void;
        // delete(key: string): Promise<void>;
        deleteSync(key: string): int;
        flush(callback: AsyncCallback<void>): void;
        // flush(): Promise<void>;
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

        // native has(key: string, callback: AsyncCallback<boolean>): void;
        // native has(key: string): Promise<boolean>;
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

        // native delete(key: string): Promise<void>;
        native deleteSync(key: string): int;

        flush(callback: AsyncCallback<void>): void {
          let p1 = taskpool.execute(flushSync, this);
          p1.then((e :NullishType)=>{
            console.log("in callback then. r is ", e)
              let r =  undefined;
              callback(r)
          });
        }
        // native flush(): Promise<void>;
    }
}
