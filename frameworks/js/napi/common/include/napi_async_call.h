/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef PRE_JS_NAPI_ASYNC_CALL_H
#define PRE_JS_NAPI_ASYNC_CALL_H

#include <functional>
#include <memory>

#include "js_common_utils.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "preferences_error.h"

namespace OHOS {
namespace PreferencesJsKit {

using InputAction = std::function<void(napi_env, size_t, napi_value *, napi_value)>;
using OutputAction = std::function<void(napi_env, napi_value &)>;
using ExecuteAction = std::function<int()>;
extern bool g_async;
extern bool g_sync;
#define ASYNC &g_async
#define SYNC &g_sync

class BaseContext {
public:
    void SetAction(napi_env env, napi_callback_info info, InputAction input, ExecuteAction exec, OutputAction output);
    void SetError(std::shared_ptr<JSError> error);
    virtual ~BaseContext();
    
    napi_env env_ = nullptr;
    bool isAsync_ = true;
    bool sendable_ = false;
    void *boundObj = nullptr;
    int execCode_ = ERR;
    std::shared_ptr<JSError> error;
    
    napi_ref self_ = nullptr;
    napi_ref callback_ = nullptr;
    napi_deferred defer_ = nullptr;
    napi_async_work work_ = nullptr;
    
    OutputAction output_ = nullptr;
    ExecuteAction exec_ = nullptr;
    napi_value result_ = nullptr;
    std::shared_ptr<BaseContext> keep_;
};

class AsyncCall final {
public:
    static napi_value Call(napi_env env, std::shared_ptr<BaseContext> context, const std::string &name);

private:
    enum { ARG_ERROR, ARG_DATA, ARG_BUTT };
    static void OnExecute(napi_env env, void *data);
    static void OnComplete(napi_env env, void *data);
    static void OnReturn(napi_env env, napi_status status, void *data);
    static void OnComplete(napi_env env, napi_status status, void *data);
    static void SetBusinessError(napi_env env, napi_value *businessError, std::shared_ptr<JSError> error);
    static napi_value Async(napi_env env, std::shared_ptr<BaseContext> context, const std::string &name);
    static napi_value Sync(napi_env env, std::shared_ptr<BaseContext> context);
};
} // namespace PreferencesJsKit
} // namespace OHOS
#endif
