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

#include "js_logger.h"
#include "js_utils.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppDataMgrJsKit {

constexpr int MAX_INPUT_COUNT = 10;
constexpr int OK = 0;
constexpr int ERR = -1;

constexpr int E_PARAM_ERROR = 401;

#define PRE_NAPI_ASSERT_BASE(env, assertion, code, message, retVal)         \
    do {                                                                    \
        if (!(assertion)) {                                                 \
            LOG_DEBUG("ThrowError: %{public}s", message);                   \
            napi_throw_error((env), std::to_string(code).c_str(), message); \
            return retVal;                                                  \
        }                                                                   \
    } while (0)

#define PRE_NAPI_ASSERT(env, assertion, code, message) PRE_NAPI_ASSERT_BASE(env, assertion, code, message, nullptr)
#define PRE_NAPI_ASSERT_RETURN_VOID(env, assertion, code, message) \
    PRE_NAPI_ASSERT_BASE(env, assertion, code, message, NAPI_RETVAL_NOTHING)

#define PRE_CALL_RETURN(theCall) \
    do {                         \
        int err = (theCall);     \
        if (err != OK) {         \
            return err;          \
        }                        \
    } while (0)

#define PRE_RETURN_NULLPTR(assertion) \
    do {                              \
        if (!(assertion)) {           \
            return nullptr;           \
        }                             \
    } while (0)

#define PRE_SETERR_RETURN(assertion, SetCall) \
    do {                                      \
        if (!(assertion)) {                   \
            return (SetCall);                 \
        }                                     \
    } while (0)

class AsyncCall final {
public:
    class Context {
    public:
        int errorCode = OK;
        napi_env _env = nullptr;
        std::string errorMessage = "";
        void *boundObj = nullptr;
        using InputAction = std::function<int(napi_env, size_t, napi_value *, napi_value)>;
        using OutputAction = std::function<int(napi_env, napi_value &)>;
        using ExecAction = std::function<int(Context *)>;
        Context(InputAction input, OutputAction output) : input_(std::move(input)), output_(std::move(output)){};
        virtual ~Context(){};
        void SetAction(InputAction input, OutputAction output = nullptr)
        {
            input_ = input;
            output_ = output;
        }

        void SetAction(OutputAction output)
        {
            SetAction(nullptr, std::move(output));
        }

        int SetError(int code, std::string msg, std::string node)
        {
            errorCode = code;
            errorMessage = "Parameter error. The type of '" + node + "' must be " + msg;
            return code;
        }
        
        int SetError(int code, std::string msg)
        {
            errorCode = code;
            errorMessage = msg;
            return code;
        }

        void ClearErrorInfo()
        {
            errorMessage = "";
            errorCode = OK;
        }

        virtual int operator()(napi_env env, size_t argc, napi_value *argv, napi_value self)
        {
            if (input_ == nullptr) {
                return OK;
            }
            ClearErrorInfo();
            return input_(env, argc, argv, self);
        }

        virtual int operator()(napi_env env, napi_value &result)
        {
            if (output_ == nullptr) {
                result = nullptr;
                return OK;
            }
            ClearErrorInfo();
            return output_(env, result);
        }

        virtual int Exec()
        {
            if (exec_ == nullptr) {
                return OK;
            }
            ClearErrorInfo();
            return exec_(this);
        };

    protected:
        friend class AsyncCall;
        InputAction input_ = nullptr;
        OutputAction output_ = nullptr;
        ExecAction exec_ = nullptr;
    };

    // The default AsyncCallback in the parameters is at the end position.
    static constexpr size_t ASYNC_DEFAULT_POS = -1;
    AsyncCall(napi_env env, napi_callback_info info, std::shared_ptr<Context> context);
    ~AsyncCall();
    napi_value Call(napi_env env, Context::ExecAction exec = nullptr);
    napi_value SyncCall(napi_env env, Context::ExecAction exec = nullptr);

private:
    enum { ARG_ERROR, ARG_DATA, ARG_BUTT };
    static void OnExecute(napi_env env, void *data);
    static void OnComplete(napi_env env, napi_status status, void *data);
    struct AsyncContext {
        std::shared_ptr<Context> ctx = nullptr;
        napi_ref callback = nullptr;
        napi_ref self = nullptr;
        napi_deferred defer = nullptr;
        napi_async_work work = nullptr;
    };
    static void DeleteContext(napi_env env, AsyncContext *context);

    AsyncContext *context_ = nullptr;
    napi_env env_ = nullptr;
};
} // namespace AppDataMgrJsKit
} // namespace OHOS
#endif
