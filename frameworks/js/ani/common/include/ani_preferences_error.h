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
#ifndef PRE_JS_ANI_ERROR_H
#define PRE_JS_ANI_ERROR_H

#include <map>
#include <optional>
#include <string>
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
constexpr int E_NOT_SUPPORTED = 801;
constexpr int E_GET_DATAOBSMGRCLIENT_FAIL = 15500019;
constexpr int E_DELETE_FILE_FAIL = 15500010;

struct JsErrorCode {
    int32_t nativeCode;
    int32_t jsCode;
    const char *message;
};

const std::optional<JsErrorCode> GetJsErrorCode(int32_t errorCode);

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
        auto errorMsg = GetJsErrorCode(code);
        if (errorMsg.has_value()) {
            auto napiError = errorMsg.value();
            code_ = napiError.jsCode;
            msg_ = napiError.message;
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

#endif // PRE_JS_ANI_ERROR_H
