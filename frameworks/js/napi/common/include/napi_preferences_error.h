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

#include <map>

#include "log_print.h"
#include "preferences_errno.h"

namespace OHOS {
namespace PreferencesJsKit {
constexpr int MAX_INPUT_COUNT = 10;
constexpr int OK = 0;
constexpr int ERR = -1;
constexpr int EXCEED_MAX_LENGTH = -2;
constexpr int NAPI_TYPE_ERROR = -3;

constexpr int E_INVALID_PARAM = 401;
constexpr int E_INNER_ERROR = 15500000;
constexpr int E_NOT_STAGE_MODE = 15501001;
constexpr int E_DATA_GROUP_ID_INVALID = 15501002;

const static std::map<int, std::string> ERROR_MAPS = {
    { E_NOT_STAGE_MODE, "Only supported in stage mode" },
    { E_DATA_GROUP_ID_INVALID, "The data group id is not valid" },
    { NativePreferences::E_NOT_SUPPORTED, "Capability not supported" },
    { NativePreferences::E_GET_DATAOBSMGRCLIENT_FAIL, "Failed to obtain subscription service." },
    { NativePreferences::E_DELETE_FILE_FAIL, "Failed to delete preferences file." }
};

#define PRE_REVT_NOTHING

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

#define PRE_CHECK_RETURN_CORE(assertion, theCall, revt)  \
    do {                                                 \
        if (!(assertion)) {                              \
            theCall;                                     \
            return revt;                                 \
        }                                                \
    } while (0)

#define PRE_CHECK_RETURN_VOID_SET(assertion, error) \
    PRE_CHECK_RETURN_CORE(assertion, context->SetError(error), PRE_REVT_NOTHING)

#define PRE_CHECK_RETURN_ERR_SET(assertion, error) \
    PRE_CHECK_RETURN_CORE(assertion, context->SetError(error), ERR)

#define PRE_CHECK_RETURN_NULL(assertion) \
    PRE_CHECK_RETURN_CORE(assertion, PRE_REVT_NOTHING, nullptr)

#define PRE_CHECK_RETURN_VOID(assertion) \
    PRE_CHECK_RETURN_CORE(assertion, PRE_REVT_NOTHING, PRE_REVT_NOTHING)

#define PRE_CHECK_RETURN_ERR(assertion) \
    PRE_CHECK_RETURN_CORE(assertion, PRE_REVT_NOTHING, ERR)


class JSError {
public:
    virtual ~JSError(){};
    virtual std::string GetMsg() = 0;
    virtual int GetCode() = 0;
};

class ParamTypeError : public JSError {
public:
    ParamTypeError(const std::string &errmsg) : errmsg_(errmsg){};
    std::string GetMsg() override
    {
        return "Parameter error. " + errmsg_;
    };
    int GetCode() override
    {
        return E_INVALID_PARAM;
    };

private:
    std::string errmsg_;
};

class InnerError : public JSError {
public:
    InnerError(const std::string &msg)
    {
        code_ = E_INNER_ERROR;
        msg_ = "Inner error. " + msg;
    }

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

class ParamNumError : public JSError {
public:
    ParamNumError(const std::string &wantNum) : wantNum(wantNum){};
    std::string GetMsg() override
    {
        return "Parameter error. Need " + wantNum + " parameters!";
    };
    int GetCode() override
    {
        return E_INVALID_PARAM;
    };

private:
    std::string apiname;
    std::string wantNum;
};
} // namespace PreferencesJsKit
} // namespace OHOS

#endif // PRE_JS_NAPI_ERROR_H
