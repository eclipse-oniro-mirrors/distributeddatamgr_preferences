/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ohos.data.dataFabricAddress.impl.hpp"
#include "stdexcept"

#include "data_fabric_address_ani.h"

namespace {
using namespace OHOS::DataFabricAddress;
using namespace ohos::data::dataFabricAddress;

void OnDataFabricAddressInner(JsDataFabricAddressParams const& jsParams,
    taihe::callback_view<void(JsDataProcessingResponse const&)> callback, uintptr_t opq)
{
    DataFabricAddressAni::GetInstance()->OnDataFabricAddress(jsParams, callback, opq);
}

void OffDataFabricAddressInner(JsDataFabricAddressParams const& jsParams, taihe::optional_view<uintptr_t> opq)
{
    DataFabricAddressAni::GetInstance()->OffDataFabricAddress(jsParams, opq);
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_OnDataFabricAddressInner(OnDataFabricAddressInner);
TH_EXPORT_CPP_API_OffDataFabricAddressInner(OffDataFabricAddressInner);
// NOLINTEND