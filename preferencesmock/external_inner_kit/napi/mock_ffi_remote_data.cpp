/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ffi_remote_data.h"
#include "cj_fn_invoker.h"
#include <mutex>
#include <unordered_map>

namespace OHOS::FFI {

FFIDataManager* FFIDataManager::GetInstance()
{
    static FFIDataManager instance;
    return &instance;
}

void FFIDataManager::StoreFFIData(const sptr<FFIData>& data)
{
    std::lock_guard<std::recursive_mutex> lock(mtx);
    ffiDataStore_[data->GetID()] = data;
}

void FFIDataManager::StoreRemoteData(const sptr<RemoteData>& data)
{
    std::lock_guard<std::recursive_mutex> lock(mtx);
    remoteDataStore_[data->GetID()] = data;
}

int64_t FFIDataManager::NewFFIDataId()
{
    std::lock_guard<std::recursive_mutex> lock(mtx);
    if (curFFIDataId_ >= maxId) {
        return -1;
    }
    return ++curFFIDataId_;
}

int FFIDataManager::FFIDataIdSafeIncrease()
{
    return 0;
}

FFIData::~FFIData() {}

RemoteData::RemoteData(int64_t id) : id_(id), isValid_(true) {}

RemoteData::~RemoteData() {}

int64_t RemoteData::GetID() const
{
    return id_;
}

CJLambdaRemoteData::~CJLambdaRemoteData() {}

} // namespace OHOS::FFI

CJFFIFnInvoker* CJFFIFnInvoker::GetInstance()
{
    static CJFFIFnInvoker instance;
    return &instance;
}

const FFIAtCPackage& CJFFIFnInvoker::GetCJFuncs()
{
    return cjFFIFn_;
}

bool CJFFIFnInvoker::FFIDataExist(int64_t id) const
{
    return false;
}

bool CJFFIFnInvoker::ReleaseFFIData(int64_t id) const
{
    return false;
}

bool CJFFIFnInvoker::ReleaseRemoteData(int64_t id) const
{
    return false;
}

void CJFFIFnInvoker::ThrowCJError(const std::string& msg) const {}

void CJFFIFnInvoker::InvokeLambda(int64_t lambdaId, int32_t argc, void** argv, void* result) const {}