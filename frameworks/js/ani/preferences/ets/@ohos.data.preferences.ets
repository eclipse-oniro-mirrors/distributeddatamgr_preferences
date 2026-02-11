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
 import hilog from '@ohos.hilog'
 import { AsyncCallback, BusinessError } from '@ohos.base';
 import Context from 'application.BaseContext'
 
 export namespace preferences {
   loadLibrary("ani_preferences");
   export native function executeGetByOpt(context: Context, options: Options) : Preferences;
   export native function executeGetByName(context: Context, name: string) : Preferences;
   export native function executeRemoveByName(context: Context, name: string) : int;
   export native function executeRemoveByOpt(context: Context, options: Options) : int;
   export native function delPreByOpt(context: Context, options: Options) : int;
   export native function delPreByName(context: Context, name: string) : int;
 
   export native function getAllSyncInner(obj :Preferences): Object;
   export native function flushSync(obj :Preferences): int;
   export native function getInner(obj :Preferences, key: string, defValue: ValueType): ValueType;
   native function putInner(obj :Preferences, key: string, value: ValueType): void;
 
   export function putSyncFunc(obj :Preferences, key: string, value: ValueType): int {
     putInner(obj, key, value);
     return 0;
   }
 
   export native function deleteSyncInner(obj :Preferences, key: string): int;
   export native function hasSyncInner(obj :Preferences, key: string): boolean;
   export native function clearSyncInner(obj :Preferences): int;
 
   type ValueType = number | string | boolean | Array<number> | Array<string> | Array<boolean> |
     Uint8Array | object | bigint;
 
   export interface Options {
     name: string;
     dataGroupId?: string | null | undefined;
   }
 
   export function getPreferencesSync(context: Context, options: Options): Preferences {
     return executeGetByOpt(context, options);
   }
 
   export function getPreferences(context: Context, name: string, callback: AsyncCallback<Preferences>): void {
     let p1 = taskpool.execute(executeGetByName, context, name);
     p1.then((data: Any) => {
       let r =  data as Preferences;
       let err : BusinessError<void>
       callback(err, r);
     }).catch((error: Any) => {
       let err =  error as BusinessError<void>;
       let data = new PreferencesImpl(0);
       callback(err, data);
     });
   };
 
   export function getPreferences(context: Context, options: Options,
     callback: AsyncCallback<Preferences>): void {
       let p1 = taskpool.execute(executeGetByOpt, context, options);
       p1.then((data: Any) => {
         let r =  data as Preferences;
         let err : BusinessError<void>
         callback(err, r);
       }).catch((error: Any) => {
         let err =  error as BusinessError<void>;
         let data = new PreferencesImpl(0);
         callback(err, data);
       });
   }
 
   export function getPreferences(context: Context, name: string): Promise<Preferences> {
     let p = new Promise<Preferences>((resolve: (v: Preferences) => void,
       reject: (error: Error) => void) => {
         let p1 = taskpool.execute(executeGetByName, context, name);
         p1.then((e :Any)=>{
           let r =  e as Preferences;
           resolve(r);
         }).catch((error: Error) : Preferences => {
           reject(error);
         });
     });
     return p;
   }
 
   export function getPreferences(context: Context, options: Options): Promise<Preferences> {
     let p = new Promise<Preferences>((resolve: (v: Preferences) => void,
       reject: (error: Error) => void) => {
         let p1 = taskpool.execute(executeGetByOpt, context, options);
         p1.then((e :Any)=>{
           let r =  e as Preferences;
           resolve(r);
         }).catch((error: Error) : Preferences => {
           reject(error);
         });
     });
     return p;
   }
 
   export function deletePreferences(context: Context, name: string, callback: AsyncCallback<void>): void {
     let p1 = taskpool.execute(delPreByName, context, name);
     p1.then((data: Any) => {
       let ret =  data as int;
       hilog.info(0x0000, 'preferences', "in deletePreferences by name callback then. ret is " + ret);
       let err : BusinessError<void>
       callback(err, undefined);
     }).catch((error: Any) => {
       let err =  error as BusinessError<void>;
       callback(err, undefined);
     });
   }
 
   export function deletePreferences(context: Context, options: Options, callback: AsyncCallback<void>): void {
     let p1 = taskpool.execute(delPreByOpt, context, options);
     p1.then((data: Any) => {
       let ret =  data as int;
       hilog.info(0x0000, 'preferences', "in deletePreferences by opt callback then. ret is " + ret);
       let err : BusinessError<void>
       callback(err, undefined);
     }).catch((error: Any) => {
       let err =  error as BusinessError<void>;
       callback(err, undefined);
     });
   }
 
   export function deletePreferences(context: Context, name: string): Promise<void> {
     let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void,
       reject: (error: Error) => void) : void => {
         let p1 = taskpool.execute(delPreByName, context, name);
         p1.then((e : Any) : void =>{
           let ret =  e as int;
           hilog.info(0x0000, 'preferences', "in deletePreferences by name promised then. ret is " + ret);
           resolve(Promise.resolve());
         }).catch((error: Error) : void => {
           reject(error);
         });
     });
     return p;
   }
 
   export function deletePreferences(context: Context, options: Options): Promise<void> {
     let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void,
       reject: (error: Error) => void) : void => {
         let p1 = taskpool.execute(delPreByOpt, context, options);
         p1.then((e : Any) : void=> {
           let ret =  e as int;
           hilog.info(0x0000, 'preferences', "in deletePreferences by opt promised then. ret is " + ret);
           resolve(Promise.resolve());
         }).catch((error: Error) : void => {
           reject(error);
         });
     });
     return p;
   }
 
   export function removePreferencesFromCacheSync(context: Context, name: string): void {
     executeRemoveByName(context, name);
   }
 
   export function removePreferencesFromCacheSync(context: Context, options: Options): void {
     executeRemoveByOpt(context, options);
   }
 
   export function removePreferencesFromCache(context: Context, name: string, callback: AsyncCallback<void>): void {
     let p1 = taskpool.execute(executeRemoveByName, context, name);
     p1.then((data: Any) => {
       let ret =  data as int;
       hilog.info(0x0000, 'preferences', "in removePreferencesFromCache by name callback then. ret is " + ret)
       let err : BusinessError<void>
       callback(err, undefined);
     })
     .catch((error: Any) => {
       let err =  error as BusinessError<void>;
       callback(err, undefined);
     });
   };
 
   export function removePreferencesFromCache(context: Context, options: Options,
     callback: AsyncCallback<void>): void {
     let p1 = taskpool.execute(executeRemoveByOpt, context, options);
     p1.then((data: Any) => {
       let ret =  data as int;
       hilog.info(0x0000, 'preferences', "in removePreferencesFromCache by Options callback then. ret is " + ret)
       let err : BusinessError<void>
       callback(err, undefined);
     }).catch((error: Any) => {
       let err =  error as BusinessError<void>;
       callback(err, undefined);
     });
   };
 
   export function removePreferencesFromCache(context: Context, name: string): Promise<void> {
     let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void,
       reject: (error: Error) => void) : void => {
         let p1 = taskpool.execute(executeRemoveByName, context, name);
         p1.then((e : Any) : void =>{
           resolve(Promise.resolve());
         }).catch((error: Error) : void => {
           reject(error);
         });
     });
     return p;
   };
 
   export function removePreferencesFromCache(context: Context, options: Options): Promise<void> {
     let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void,
       reject: (error: Error) => void) : void => {
         let p1 = taskpool.execute(executeRemoveByOpt, context, options);
         p1.then((e : Any) : void=> {
           resolve(Promise.resolve());
         }).catch((error: Error) : void => {
           reject(error);
         });
     });
     return p;
   };
 
   export interface Preferences {
 
     get(key: string, defValue: ValueType, callback: AsyncCallback<ValueType>): void;
     get(key: string, defValue: ValueType): Promise<ValueType>;
     getSync(key: string, defValue: ValueType): ValueType;
     getAllSync(): Object;
     getAll(callback: AsyncCallback<Object>): void;
     getAll(): Promise<Object>;
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
     flush(): Promise<void>;
     clearSync(): void;
     clear(): Promise<void>;
     clear(callback: AsyncCallback<void>): void;
   }
 
   class PreferencesImpl implements Preferences {
     private nativePtr:long = 0;
     constructor(context:long) {
       hilog.info(0x0000, 'preferences', "in constructor, context is ", context)
       this.nativePtr = context;
     }
 
     getNativePtr(): long {
       return this.nativePtr;
     }
 
     get(key: string, defValue: ValueType, callback: AsyncCallback<ValueType>): void {
       let p1 = taskpool.execute(getInner, this, key, defValue);
       p1.then((data: Any) => {
         let ret =  data as ValueType;
         let err : BusinessError<void>
         callback(err, ret);
       }).catch((error: Any) => {
         let err =  error as BusinessError<void>;
         let data : ValueType;
         callback(err, data);
       });
     }
 
     get(key: string, defValue: ValueType): Promise<ValueType> {
       let p = new Promise<ValueType>((resolve: (v: ValueType) => void,
         reject: (error: Error) => void) => {
           let p1 = taskpool.execute(getInner, this, key, defValue);
           p1.then((e :Any)=>{
             let r =  e as ValueType;
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
 
     getAllSync(): Object {
       return getAllSyncInner(this);
     }
 
     getAll(callback: AsyncCallback<Object>): void {
       let p1 = taskpool.execute(getAllSyncInner, this);
       p1.then((data: Any) => {
         hilog.info(0x0000, 'preferences', "getAll in get callback then.")
         let ret =  data as Object;
         let err : BusinessError<void>
         callback(err, ret);
       }).catch((error: Any) => {
         let err =  error as BusinessError<void>;
         let data : Object;
         callback(err, data);
       });
     }
 
     getAll(): Promise<Object> {
       let p = new Promise<Object>((resolve: (v: Object) => void,
         reject: (error: Error) => void) => {
           let p1 = taskpool.execute(getAllSyncInner, this);
           p1.then((e :Any) : Object => {
             hilog.info(0x0000, 'preferences', "in getAll promise then.")
             let ret =  e as Object;
             resolve(ret);
           }).catch((err: Error) : Object => {
             reject(err);
           });
       });
       return p;
     }
 
     has(key: string, callback: AsyncCallback<boolean>): void {
       let p1 = taskpool.execute(hasSyncInner, this, key);
       p1.then((data: Any) => {
         hilog.info(0x0000, 'preferences', "has in get callback then. data is " + data)
         let ret =  data as boolean;
         let err : BusinessError<void>
         callback(err, ret);
       }).catch((error: Any) => {
         hilog.info(0x0000, 'preferences', "has in get callback then error.")
         let err =  error as BusinessError<void>;
         let data : boolean;
         callback(err, data);
       });
     }
 
     has(key: string): Promise<boolean> {
       let p = new Promise<boolean>((resolve: (v: boolean) => void,
         reject: (error: Error) => void) => {
           let p1 = taskpool.execute(hasSyncInner, this, key);
           p1.then((e :Any) : void =>{
               let r =  e as boolean;
               hilog.info(0x0000, 'preferences', "in promise then, r is: " + r)
               resolve(r);
           }).catch((err: Error) : void => {
             reject(err);
           });
       });
       return p;
     }
 
     hasSync(key: string): boolean {
         return hasSyncInner(this, key);
     }
 
     put(key: string, value: ValueType, callback: AsyncCallback<void>): void {
       let p1 = taskpool.execute(putSyncFunc, this, key, value);
       p1.then((data: Any) => {
         let ret =  data as int;
         hilog.info(0x0000, 'preferences', "put in get callback then. ret is " + ret)
         let err : BusinessError<void>
         callback(err, undefined);
       }).catch((error: Any) => {
         let err =  error as BusinessError<void>;
         callback(err, undefined);
       });
     }
 
     put(key: string, value: ValueType): Promise<void> {
       let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void,
         reject: (error: Error) => void) : void => {
           let p1 = taskpool.execute(putSyncFunc, this, key, value);
           p1.then((e :Any) : void =>{
             hilog.info(0x0000, 'preferences', "end put in promise thread.")
             resolve(Promise.resolve());
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
       let p1 = taskpool.execute(deleteSyncInner, this, key);
       p1.then((data: Any) => {
         let ret =  data as int;
         hilog.info(0x0000, 'preferences', "delete in get callback then. ret is " + ret)
         let err : BusinessError<void>
         callback(err, undefined);
       }).catch((error: Any) => {
         let err =  error as BusinessError<void>;
         callback(err, undefined);
       });
     }
 
     delete(key: string): Promise<void> {
       let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void,
         reject: (error: Error) => void) : void => {
         let p1 = taskpool.execute(deleteSyncInner, this, key);
           p1.then((e :Any) : void=> {
             let r = e as int;
             hilog.info(0x0000, 'preferences', "In delete Promise, ret is: " + r);
             resolve(Promise.resolve());
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
       p1.then((data: Any) => {
         let ret =  data as int;
         hilog.info(0x0000, 'preferences', "flush in get callback then. ret is " + ret)
         let err : BusinessError<void>
         callback(err, undefined);
       }).catch((error: Any) => {
         let err =  error as BusinessError<void>;
         callback(err, undefined);
       });
     }
 
     flush(): Promise<void> {
       let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void,
         reject: (error: Error) => void) : void => {
         let p1 = taskpool.execute(flushSync, this);
           p1.then((e :Any) : void=> {
             let r = e as int;
             hilog.info(0x0000, 'preferences', "In flush Promise, ret is: " + r);
             resolve(Promise.resolve());
         }).catch((err: Error) : void => {
           reject(err);
         });
       });
       return p;
     }
 
     clearSync(): void {
       let ret = clearSyncInner(this);
       hilog.info(0x0000, 'preferences', "clearSyncInner, ret is: " + ret);
     };
 
     clear(): Promise<void> {
       let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void,
         reject: (error: Error) => void) : void => {
         let p1 = taskpool.execute(clearSyncInner, this);
           p1.then((e :Any) : void=> {
             let r = e as int;
             hilog.info(0x0000, 'preferences', "In clear Promise, ret is: " + r);
             resolve(Promise.resolve());
         }).catch((err: Error) : void => {
           reject(err);
         });
       });
       return p;
     };
 
     clear(callback: AsyncCallback<void>): void {
       let p1 = taskpool.execute(clearSyncInner, this);
       p1.then((data: Any) => {
         let ret =  data as int;
         hilog.info(0x0000, 'preferences', "clear in get callback then. ret is " + ret)
         let err : BusinessError<void>
         callback(err, undefined);
       }).catch((error: Any) => {
         let err =  error as BusinessError<void>;
         callback(err, undefined);
       });
     };
   }
 
 }