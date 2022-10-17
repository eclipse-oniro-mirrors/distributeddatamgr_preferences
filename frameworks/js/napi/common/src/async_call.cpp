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

#include "async_call.h"
#include "js_logger.h"

namespace OHOS {
namespace AppDataMgrJsKit {
AsyncCall::AsyncCall(napi_env env, napi_callback_info info, std::shared_ptr<Context> context) : env_(env)
{
    context->_env = env;
    size_t argc = MAX_INPUT_COUNT;
    napi_value self = nullptr;
    napi_value argv[MAX_INPUT_COUNT] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    if (status != napi_ok) {
        context->errorCode = E_PARAM_ERROR;
        if (context->apivison >= 9) {
            PRE_NAPI_ASSERT_RETURN_VOID(env, status == napi_ok, E_PARAM_ERROR, "Parameter error. Get args failed.");
        } else {
            NAPI_ASSERT_RETURN_VOID(env, context->errorCode == OK, "Parameter error. Get args failed.");
        }
    }

    context_ = new AsyncContext();
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[argc - 1], &valueType);
    if (valueType == napi_function) {
        napi_create_reference(env, argv[argc - 1], 1, &context_->callback);
        argc = argc - 1;
    }
    context->errorCode = (*context)(env, argc, argv, self);
    if (context->apivison > 8) {
        PRE_NAPI_ASSERT_RETURN_VOID(env, context->errorCode == OK, context->errorCode, context->errorMessage.c_str());
    } else {
        NAPI_ASSERT_RETURN_VOID(env, context->errorCode == OK, "Parameter processing function failed.");
    }
    context_->ctx = std::move(context);
    napi_create_reference(env, self, 1, &context_->self);
}

AsyncCall::~AsyncCall()
{
    if (context_ == nullptr) {
        return;
    }

    DeleteContext(env_, context_);
}

napi_value AsyncCall::Call(napi_env env, Context::ExecAction exec)
{
    if ((context_ == nullptr) || (context_->ctx == nullptr)) {
        LOG_DEBUG("context_ or context_->ctx is null");
        return nullptr;
    }
    LOG_DEBUG("async call exec");
    context_->ctx->exec_ = std::move(exec);
    napi_value promise = nullptr;
    if (context_->callback == nullptr) {
        napi_create_promise(env, &context_->defer, &promise);
    } else {
        napi_get_undefined(env, &promise);
    }
    napi_async_work work = context_->work;
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "AsyncCall", NAPI_AUTO_LENGTH, &resource);
    napi_create_async_work(env, nullptr, resource, AsyncCall::OnExecute, AsyncCall::OnComplete, context_, &work);
    context_->work = work;
    context_ = nullptr;
    napi_queue_async_work(env, work);
    LOG_DEBUG("async call exec");
    return promise;
}

napi_value AsyncCall::SyncCall(napi_env env, AsyncCall::Context::ExecAction exec)
{
    if ((context_ == nullptr) || (context_->ctx == nullptr)) {
        LOG_DEBUG("context_ or context_->ctx is null");
        return nullptr;
    }
    context_->ctx->exec_ = std::move(exec);
    napi_value promise = nullptr;
    if (context_->callback == nullptr) {
        napi_create_promise(env, &context_->defer, &promise);
    } else {
        napi_get_undefined(env, &promise);
    }
    AsyncCall::OnExecute(env, context_);
    AsyncCall::OnComplete(env, napi_ok, context_);
    return promise;
}

void AsyncCall::OnExecute(napi_env env, void *data)
{
    LOG_DEBUG("run the async runnable");
    AsyncContext *context = reinterpret_cast<AsyncContext *>(data);
    context->ctx->errorCode = context->ctx->Exec();
}

void SetBusinessError(napi_env env, napi_value *businessError, const int errCode, const std::string errMessage)
{
    napi_value Code = nullptr;
    napi_value Message = nullptr;
    napi_create_int32(env, errCode, &Code);
    if (errMessage.empty()) {
        napi_create_string_utf8(env, "async call failed", NAPI_AUTO_LENGTH, &Message);
    }else{
        napi_create_string_utf8(env, errMessage.c_str(), NAPI_AUTO_LENGTH, &Message);
    }    
    napi_set_named_property(env, *businessError, "code", Code);
    napi_set_named_property(env, *businessError, "message", Message);
}

void AsyncCall::OnComplete(napi_env env, napi_status status, void *data)
{
    LOG_DEBUG("run the js callback function");
    AsyncContext *context = reinterpret_cast<AsyncContext *>(data);
    napi_value output = nullptr;
    int completeStatus = ERR;
    int executeStatus = context->ctx->errorCode;
    if (status == napi_ok && executeStatus == OK) {
        completeStatus = (*context->ctx)(env, output);
    }
    napi_value result[ARG_BUTT] = { 0 };
    if (executeStatus == OK && completeStatus == OK) {
        napi_get_undefined(env, &result[ARG_ERROR]);
        if (output != nullptr) {
            result[ARG_DATA] = output;
        } else {
            napi_get_undefined(env, &result[ARG_DATA]);
        }
    } else {
        napi_value businessError = nullptr;
        napi_create_object(env, &businessError);
        if (context->ctx->apivison > 8) {
            SetBusinessError(env, &businessError, context->ctx->errorCode, context->ctx->errorMessage);
        }
        result[ARG_ERROR] = businessError;
        napi_get_undefined(env, &result[ARG_DATA]);
    }
    if (context->defer != nullptr) {
        // promise
        if (executeStatus == OK && completeStatus == OK) {
            napi_resolve_deferred(env, context->defer, result[ARG_DATA]);
        } else {
            napi_reject_deferred(env, context->defer, result[ARG_ERROR]);
        }
    } else {
        // callback
        napi_value callback = nullptr;
        napi_get_reference_value(env, context->callback, &callback);
        napi_value returnValue;
        napi_call_function(env, nullptr, callback, ARG_BUTT, result, &returnValue);
    }
    DeleteContext(env, context);
}

void AsyncCall::DeleteContext(napi_env env, AsyncContext *context)
{
    if (env != nullptr) {
        napi_delete_reference(env, context->callback);
        napi_delete_reference(env, context->self);
        napi_delete_async_work(env, context->work);
    }
    delete context;
}
} // namespace AppDataMgrJsKit
} // namespace OHOS