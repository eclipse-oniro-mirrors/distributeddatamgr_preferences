/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTEDDATAMGR_APPDATAMGR_JSUTILS_H
#define DISTRIBUTEDDATAMGR_APPDATAMGR_JSUTILS_H

#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace PreferencesJsKit {
class JSUtils final {
public:
    static constexpr int OK = 0;
    static constexpr int ERR = -1;
    static constexpr int32_t DEFAULT_BUF_SIZE = 1024;
    static constexpr int32_t BUF_CACHE_MARGIN = 4;
    static constexpr int32_t ASYNC_RST_SIZE = 2;
    static constexpr int32_t MAX_VALUE_LENGTH = 8 * 1024;
    static constexpr int32_t SYNC_RESULT_ELEMNT_NUM = 2;

    static int32_t Convert2Bool(napi_env env, napi_value jsBool, bool &output);
    static int32_t Convert2Double(napi_env env, napi_value jsNum, double &output);
    static int32_t Convert2String(napi_env env, napi_value jsStr, std::string &output);

    static int32_t Convert2StrVector(napi_env env, napi_value value, std::vector<std::string> &output);
    static int32_t Convert2BoolVector(napi_env env, napi_value value, std::vector<bool> &output);
    static int32_t Convert2DoubleVector(napi_env env, napi_value value, std::vector<double> &output);

    static int32_t Convert2JSValue(napi_env env, std::string value, napi_value &output);
    static int32_t Convert2JSValue(napi_env env, bool value, napi_value &output);
    static int32_t Convert2JSValue(napi_env env, double value, napi_value &output);
    static int32_t Convert2JSStringArr(napi_env env, std::vector<std::string> value, napi_value &output);
    static int32_t Convert2JSBoolArr(napi_env env, std::vector<bool> value, napi_value &output);
    static int32_t Convert2JSDoubleArr(napi_env env, std::vector<double> value, napi_value &output);

    static napi_value Convert2JSValue(napi_env env, int32_t value);

    static bool Equals(napi_env env, napi_value value, napi_ref copy);
};
} // namespace PreferencesJsKit
} // namespace OHOS

#endif // DISTRIBUTEDDATAMGR_APPDATAMGR_JSUTILS_H
