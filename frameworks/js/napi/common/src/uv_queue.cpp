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

#include "log_print.h"
#include <memory>
#include "uv_queue.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS::PreferencesJsKit {
constexpr size_t MAX_CALLBACK_ARG_NUM = 6;
UvQueue::UvQueue(napi_env env)
    : env_(env)
{
}

UvQueue::~UvQueue()
{
    LOG_DEBUG("no memory leak for queue-callback");
    env_ = nullptr;
}

void UvQueue::AsyncCall(NapiCallbackGetter getter, NapiArgsGenerator genArgs, bool sendable)
{
    if (!getter) {
        LOG_ERROR("callback is nullptr");
        return;
    }

    auto env = GetEnv();
    auto task = [env, getter, genArgs, sendable]() {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            return;
        }
        napi_value method = getter(env);
        if (method == nullptr) {
            LOG_WARN("the callback is invalid, maybe is cleared!");
            napi_close_handle_scope(env, scope);
            return;
        }
        int argc = 0;
        napi_value argv[MAX_CALLBACK_ARG_NUM] = { nullptr };
        if (genArgs) {
            argc = MAX_CALLBACK_ARG_NUM;
            genArgs(env, sendable, argc, argv);
        }
        napi_value global = nullptr;
        napi_status status = napi_get_global(env, &global);
        if (status != napi_ok) {
            LOG_ERROR("get napi gloabl failed. status: %{public}d.", status);
            return;
        }
        napi_value result;
        status = napi_call_function(env, global, method, argc, argv, &result);
        if (status != napi_ok) {
            LOG_ERROR("notify data change failed status: %{public}d.", status);
        }
        napi_close_handle_scope(env, scope);
    };
    if (napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        LOG_ERROR("Failed to napi_send_event.");
    }
}

napi_env UvQueue::GetEnv()
{
    return env_;
}
} // namespace OHOS::DistributedKVStore
