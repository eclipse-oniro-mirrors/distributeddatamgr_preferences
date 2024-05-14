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

#include "napi_async_call.h"
#include <chrono>

namespace OHOS {
namespace PreferencesJsKit {
bool g_async = true;  // do not reset the value, used in DECLARE_NAPI_FUNCTION_WITH_DATA only
bool g_sync = !g_async;  // do not reset the value, used in DECLARE_NAPI_FUNCTION_WITH_DATA only
static constexpr int64_t ASYNC_PROCESS_WARING_TIME = 500;

void BaseContext::SetAction(
    napi_env env, napi_callback_info info, InputAction input, ExecuteAction exec, OutputAction output)
{
    env_ = env;
    size_t argc = MAX_INPUT_COUNT;
    napi_value self = nullptr;
    napi_value argv[MAX_INPUT_COUNT] = { nullptr };
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &self, &data);
    napi_is_sendable(env, self, &sendable_);
    napi_valuetype valueType = napi_undefined;
    if (status == napi_ok && argc > 0) {
        napi_typeof(env, argv[argc - 1], &valueType);
        if (!sendable_ && valueType == napi_function) {
            status = napi_create_reference(env, argv[argc - 1], 1, &callback_);
            argc = argc - 1;
        }
    }
    if (data) {
        isAsync_ = *reinterpret_cast<bool *>(data);
    }

    // int -->input_(env, argc, argv, self)
    if (status == napi_ok) {
        input(env, argc, argv, self);
    } else {
        error = std::make_shared<InnerError>("Failed to set action.");
    }

    // if input return is not ok, then napi_throw_error context error
    PRE_NAPI_ASSERT_RETURN_VOID(env, error == nullptr, error);

    output_ = std::move(output);
    exec_ = std::move(exec);
    napi_create_reference(env, self, 1, &self_);
}

void BaseContext::SetError(std::shared_ptr<JSError> err)
{
    error = err;
}

BaseContext::~BaseContext()
{
    if (env_ == nullptr) {
        return;
    }
    if (work_ != nullptr) {
        napi_delete_async_work(env_, work_);
    }
    if (callback_ != nullptr) {
        napi_delete_reference(env_, callback_);
    }
    napi_delete_reference(env_, self_);
    env_ = nullptr;
}

void AsyncCall::SetBusinessError(napi_env env, napi_value *businessError, std::shared_ptr<JSError> error)
{
    napi_value code = nullptr;
    napi_value msg = nullptr;
    // if error is not inner error
    if (error != nullptr && error->GetCode() != E_INVALID_PARAM) {
        napi_create_int32(env, error->GetCode(), &code);
        napi_create_string_utf8(env, error->GetMsg().c_str(), NAPI_AUTO_LENGTH, &msg);
        napi_property_descriptor descriptors[] = {
            DECLARE_NAPI_DEFAULT_PROPERTY("code", code),
            DECLARE_NAPI_DEFAULT_PROPERTY("message", msg),
        };
        // 2 represents the current number of incorrect object attributes
        napi_create_object_with_properties(env, businessError, 2, descriptors);
    }
}

napi_value AsyncCall::Call(napi_env env, std::shared_ptr<BaseContext> context, const std::string &name)
{
    return context->isAsync_ ? Async(env, context, name) : Sync(env, context);
}

napi_value AsyncCall::Async(napi_env env, std::shared_ptr<BaseContext> context, const std::string &name)
{
    napi_value promise = nullptr;

    auto start_time = std::chrono::steady_clock::now();
    if (context->callback_ == nullptr) {
        napi_status status = napi_create_promise(env, &context->defer_, &promise);
        PRE_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("Failed to create promise."));
    } else {
        napi_get_undefined(env, &promise);
    }
    context->keep_ = context;
    napi_value resource = nullptr;
    const std::string name_resource = "Preferences" + name;
    napi_create_string_utf8(env, name_resource.c_str(), NAPI_AUTO_LENGTH, &resource);
    // create async work, execute function is OnExecute, complete function is OnComplete
    napi_create_async_work(env, nullptr, resource, AsyncCall::OnExecute, AsyncCall::OnComplete,
                           reinterpret_cast<void *>(context.get()), &context->work_);
    // add async work to execute queue
    napi_queue_async_work_with_qos(env, context->work_, napi_qos_user_initiated);
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    if (duration.count() > ASYNC_PROCESS_WARING_TIME) {
        LOG_ERROR("The execution time of %{public}s is %{public}lld.", name.c_str(), duration.count());
    }
    return promise;
}

napi_value AsyncCall::Sync(napi_env env, std::shared_ptr<BaseContext> context)
{
    OnExecute(env, reinterpret_cast<void *>(context.get()));
    OnComplete(env, reinterpret_cast<void *>(context.get()));
    return context->result_;
}

void AsyncCall::OnExecute(napi_env env, void *data)
{
    BaseContext *context = reinterpret_cast<BaseContext *>(data);
    if (context->exec_) {
        context->execCode_ = context->exec_();
    }
    context->exec_ = nullptr;
}

void AsyncCall::OnComplete(napi_env env, void *data)
{
    BaseContext *context = reinterpret_cast<BaseContext *>(data);
    if (context->execCode_ != NativePreferences::E_OK) {
        context->SetError(std::make_shared<InnerError>(context->execCode_));
        LOG_ERROR("The async execute status is %{public}d", context->execCode_);
    }
    // if async execute status is not napi_ok then un-execute out function
    if ((context->error == nullptr) && context->output_) {
        context->output_(env, context->result_);
    }
    context->output_ = nullptr;
}

void AsyncCall::OnComplete(napi_env env, napi_status status, void *data)
{
    OnComplete(env, data);
    OnReturn(env, status, data);
}

void AsyncCall::OnReturn(napi_env env, napi_status status, void *data)
{
    BaseContext *context = reinterpret_cast<BaseContext *>(data);
    napi_value result[ARG_BUTT] = { 0 };
    // if out function status is ok then async renturn output data, else return error.
    if (context->error == nullptr) {
        napi_get_undefined(env, &result[ARG_ERROR]);
        if (context->result_ != nullptr) {
            result[ARG_DATA] = context->result_;
        } else {
            napi_get_undefined(env, &result[ARG_DATA]);
        }
    } else {
        SetBusinessError(env, &result[ARG_ERROR], context->error);
        napi_get_undefined(env, &result[ARG_DATA]);
    }
    if (context->defer_ != nullptr) {
        // promise
        if (status == napi_ok && (context->error == nullptr)) {
            napi_resolve_deferred(env, context->defer_, result[ARG_DATA]);
        } else {
            napi_reject_deferred(env, context->defer_, result[ARG_ERROR]);
        }
    } else if (!context->sendable_) {
        // callback
        napi_value callback = nullptr;
        napi_get_reference_value(env, context->callback_, &callback);
        napi_value returnValue;
        napi_call_function(env, nullptr, callback, ARG_BUTT, result, &returnValue);
    }
    context->keep_.reset();
}
} // namespace PreferencesJsKit
} // namespace OHOS