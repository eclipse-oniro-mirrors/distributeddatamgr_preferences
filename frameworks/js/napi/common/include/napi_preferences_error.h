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
#ifndef PRE_JS_NAPI_ERROR_H
#define PRE_JS_NAPI_ERROR_H

#include "log_print.h"

namespace OHOS {
namespace PreferencesJsKit {
constexpr int MAX_INPUT_COUNT = 10;
constexpr int OK = 0;
constexpr int ERR = -1;
constexpr int EXCEED_MAX_LENGTH = -2;

constexpr int E_PARAM_ERROR = 401;
constexpr int E_INNER_ERROR = 15500000;
constexpr int E_PREFERENCES_ERROR = 15500010;

const static std::map<int, std::string> ERROR_MAPS = {
};

#define PRE_NAPI_ASSERT_BASE(env, assertion, error, retVal)                        \
    do {                                                                           \
        if (!(assertion)) {                                                        \
            LOG_ERROR("throw error: code = %{public}d , message = %{public}s",     \
                      (error)->GetCode(), (error)->GetMsg().c_str());          \
            napi_throw_error((env), std::to_string((error)->GetCode()).c_str(),    \
                             (error)->GetMsg().c_str());                       \
            return retVal;                                                         \
        }                                                                          \
    } while (0)

#define PRE_NAPI_ASSERT(env, assertion, error) PRE_NAPI_ASSERT_BASE(env, assertion, error, nullptr)

#define PRE_NAPI_ASSERT_RETURN_VOID(env, assertion, error) \
    PRE_NAPI_ASSERT_BASE(env, assertion, error, NAPI_RETVAL_NOTHING)

#define PRE_ASYNC_PARAM_CHECK_FUNCTION(theCall) \
    do {                                        \
        int err = (theCall);                    \
        if (err != OK) {                        \
            return err;                         \
        }                                       \
    } while (0)

#define PRE_CHECK_RETURN_NULLPTR(context, assertion) \
    do {                                             \
        if (!(assertion)) {                          \
            /* avoid cyclic dependence */            \
            (context)->exec_ = nullptr;              \
            (context)->output_ = nullptr;            \
            return nullptr;                          \
        }                                            \
    } while (0)

#define PRE_CHECK_RETURN_CALL_RESULT(assertion, theCall) \
    do {                                                 \
        if (!(assertion)) {                              \
            (theCall);                                   \
            return ERR;                                  \
        }                                                \
    } while (0)

#define PRE_CHECK_PARAM_NUM_VALID(assertion, errMsg)                                        \
    do {                                                                                    \
        if (!(assertion)) {                                                                 \
            std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>(errMsg); \
            context->SetError(paramNumError);                                               \
            return ERR;                                                                     \
        }                                                                                   \
    } while (0)

#define PRE_NAPI_ASSERT_RETURN_VOID(env, assertion, error) \
    PRE_NAPI_ASSERT_BASE(env, assertion, error, NAPI_RETVAL_NOTHING)

class Error {
public:
    virtual ~Error(){};
    virtual std::string GetMsg() = 0;
    virtual int GetCode() = 0;
};

class ParamTypeError : public Error {
public:
    ParamTypeError(const std::string &name, const std::string &wantType) : name(name), wantType(wantType){};
    std::string GetMsg() override
    {
        return "Parameter error. The type of '" + name + "' must be " + wantType;
    };
    int GetCode() override
    {
        return E_PARAM_ERROR;
    };

private:
    std::string name;
    std::string wantType;
};

class InnerError : public Error {
public:
    InnerError(int code)
    {
        auto iter = ERROR_MAPS.find(code);
        if (iter != ERROR_MAPS.end()) {
            code_ = code;
            msg_ = iter->second;
        } else {
            code_ = E_INNER_ERROR;
            msg_ = "Inner error. Error code " + std::to_string(code);
        }
    }

    std::string GetMsg() override
    {
        return msg_;
    }

    int GetCode() override
    {
        return code_;
    }
private:
    int code_;
    std::string msg_;
};

class ParamNumError : public Error {
public:
    ParamNumError(const std::string &wantNum) : wantNum(wantNum){};
    std::string GetMsg() override
    {
        return "Parameter error. Need " + wantNum + " parameters!";
    };
    int GetCode() override
    {
        return E_PARAM_ERROR;
    };

private:
    std::string apiname;
    std::string wantNum;
};

class DeleteError : public Error {
public:
    DeleteError() = default;
    std::string GetMsg() override
    {
        return "Failed to delete preferences file.";
    };
    int GetCode() override
    {
        return E_PREFERENCES_ERROR;
    };

private:
    std::string apiname;
};
} // namespace PreferencesJsKit
} // namespace OHOS

#endif // PRE_JS_NAPI_ERROR_H
