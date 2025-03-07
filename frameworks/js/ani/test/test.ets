
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
import { preferences } from "../ets/ani_preferences.ets";
import { Options } from "../ets/ani_preferences.ets";

class ContextImpl extends BaseContext {
    name: string = "";
    bundleName: string = "";
    stageMode: boolean = true;
};

class ContextImplTest extends BaseContext {
    name: string = "";
    bundleName: string = "";
};

class OptionsImpl implements Options {
  name: string = "";
  dataGroupId?: string | null | undefined;
}

function main() {
    console.log("hello ani_preferences");
    let context : ContextImpl = {
      name : "/data/123",
      stageMode: true,
      bundleName : "com.example.app 111",
      // dataGroupId : "group123"
    };
    let opt : OptionsImpl = {
        name : "/data/123",
        dataGroupId : "dataGroupId in opt",
    };
    let testArray1 = new Array<number>(1, 2, 3, 4, 5);
    let testArray2 = new Array<string>('a', 'b', 'c', 'd', 'e');
    let testArray3 = new Array<boolean>(true, false, true, false, true);
    let testArray4 = new Uint8Array([10, 20, 30, 40, 50]);
    class TestInf {
        name: string = "";
        age: number = 0;
        toString(): string {
            return "name is " + this.name + ", age is " + this.age;
        }
    }
    const valueTypePerson: TestInf = { name: "Alice", age: 25 };
    const valueTypePerson1: TestInf = { name: "", age: 2};
    console.log("------------------------------");
    console.log(valueTypePerson);
    console.log("------------------------------");
    let fz:string = "";
    let fz1:number = 123;
    let fz10:number = 0;
    let fz2:boolean = false;
    let fz3:Uint8Array = new Uint8Array([1, 2, 3, 4, 5]);
    let fz30:Uint8Array = new Uint8Array();
    let fz4:Array<number> = new Array<number>(1, 2, 3, 4, 5);
    let fz40:Array<number> = new Array<number>();
    let fz5:Array<string> = new Array<string>('a', 'b', 'c', 'd', 'e');
    let fz50:Array<string> = new Array<string>();
    let fz6:Array<boolean> = new Array<boolean>(true, false, true, false, true);
    let fz60:Array<boolean> = new Array<boolean>();
    preferences.getPreferences(context, opt).then<void, void>((value: preferences.Preferences): void => {
        console.log("********************number************************");
        value.putSync("xying", fz1);
        console.log("Test passed fz start ");
        let ret1 = value.getSync("xying", fz10);
        console.log("Test passed 1 . The value is " + ret1);
        console.log("********************boolean************************");
        value.putSync("xying", true);
        console.log("Test passed true start ");
        let ret2 = value.getSync("xying", fz2);
        console.log("Test passed 1 . The value is " + ret2);
        console.log("*********************Uint8Array***********************");
        value.putSync("xying", fz3);
        console.log("Test passed fz3 start ");
        let ret3 = value.getSync("xying", fz30);
        console.log(ret3.toString());
        console.log("******************Array<number>**************************");
        value.putSync("xying", fz4);
        console.log("Test passed fz4 start ");
        let ret4 = value.getSync("xying", fz40);
        console.log(ret4.toString());
        console.log("********************Array<string>************************");
        value.putSync("xying", fz5);
        console.log("Test passed fz5 start ");
        let ret5 = value.getSync("xying", fz50);
        console.log(ret5.toString());
        console.log("********************Array<boolean>************************");
        value.putSync("xying", fz6);
        console.log("Test passed fz6 start ");
        let ret6 = value.getSync("xying", fz60);
        console.log(ret6.toString());
        console.log("********************Object************************");
        value.putSync("xying", valueTypePerson);
        console.log("Test passed fz7 valueTypePerson ");
        let ret7 = value.getSync("xying", valueTypePerson1);
        console.log(ret7.toString());
    }, (err: Object): void => {
        console.log("Test failed 2 . The promise shouldn`t be rejected.");
    });

    console.log("-------------- begin flush test ----------------");
    preferences.getPreferences(context, opt).then<void, void>((value: preferences.Preferences): void => {
        console.log("before flush.");
        value.flush(()=> {
          console.log("Callback: after flush.");
        })
    }, (err: Object): void => {
        console.log("The promise shouldn`t be rejected.");
    });
    console.log("-------------- end flush test ----------------");

    console.log("-------------- begin deleteSync test ----------------");
    preferences.getPreferences(context, opt).then<void, void>((value: preferences.Preferences): void => {
        value.deleteSync("test");
        console.log("Callback: after deleteSync.");
    });
    console.log("-------------- end deleteSync test ----------------");
}