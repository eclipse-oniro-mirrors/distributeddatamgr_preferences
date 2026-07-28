# 首选项组件指引

本文件是 AI Agent 处理本仓库任务时的轻量入口。先读本文件，再按任务类型定位相关代码和文档。

## 阅读策略

不要一开始就读取所有源文件。默认只读本文件。涉及需求设计或代码开发时，按需加载：

1. 如果影响范围不清楚，阅读 **知识地图** 部分的架构概览和目录结构。
2. 如果不确定某个功能在哪个文件实现，查阅 **知识路由** 表格定位关键文件。
3. 如果需要了解约束和最佳实践，阅读 **专家经验** 部分。
4. 规划验证时，阅读 **编译和测试方法** 部分。

本仓库内容较多，一次性加载全部背景知识会浪费上下文，也会降低后续实现的精度。建议按需查阅相关代码文件。

## 仓库定位

`distributeddatamgr_preferences` 是 OpenHarmony 首选项（Preferences）组件。在 OpenHarmony 源码树中的位置是：

```text
//foundation/distributeddatamgr/preferences
```

组件元信息：

- 子系统：`distributeddatamgr`
- 部件：`preferences`
- Bundle：`@ohos.preferences`
- 主要能力面：轻量级 Key-Value 存储、本地持久化、数据观察者、跨进程数据同步。

主要实现语言是 C++，通过 NAPI 和 ANI 暴露到 ArkTS/JavaScript。本仓库同时包含 NDK C API、CJ FFI 和测试代码。

## 知识地图（代码分层目录解释）

### 架构概览

Preferences 组件采用多层架构设计：

```
用户应用层（ArkTS/JavaScript）
    |
    ├─ NAPI 层（@ohos.data.preferences）
    ├─ ANI/Taihe 层（静态绑定）
    ├─ NDK C API 层
    |
Native C++ 核心层
    ├─ PreferencesHelper（实例管理器，静态缓存）
    ├─ PreferencesImpl（XML 文件存储）
    │   ├─ 内存缓存（valuesCache_）
    │   ├─ 异步加载（loaded_ 标志）
    │   ├─ Flush 防重入（queue_ 队列）
    │   └─ XML 序列化（备份恢复机制）
    ├─ PreferencesEnhanceImpl（GSKV 数据库存储）
    │   ├─ 实时写入（无需 Flush）
    │   └─ 大对象缓存（>= 512KB）
持久化层
    ├─ XML 文件存储（默认）
    └─ GSKV 数据库存储（高性能可选）
```

**数据流**：
- **读取流程**：用户调用 Get → PreferencesImpl 从内存缓存读取 → 如果未加载则异步从磁盘加载 → 等待加载完成 → 返回数据
- **写入流程**：用户调用 Put → 写入内存缓存并标记 modifiedKeys → 调用 Flush → 序列化到 XML（备份文件 → 写入文件 → 删除备份）→ 通知观察者

### 核心目录结构

- `interfaces/inner_api/include/`：内部接口头文件，对外暴露的核心 API 定义。
  - `preferences.h`：Preferences 实例核心接口（`PreferencesBase` 抽象基类）。
  - `preferences_helper.h`：Preferences 实例创建和管理的辅助接口（静态缓存管理）。
  - `preferences_errno.h`：错误码定义（15500000 系列，子系统 13 + 模块 6）。
- `frameworks/native/`：Native C++ 核心实现层。
  - `src/`：核心业务逻辑。
    - `preferences_impl.cpp/h`：XML 文件存储实现（内存缓存、异步加载、Flush 防重入）。
    - `preferences_enhance_impl.cpp/h`：GSKV 数据库存储实现（高性能、大对象缓存）。
    - `preferences_helper.cpp/h`：实例管理器（静态缓存、信任名单、类型冲突检测）。
- `interfaces/kits/`：应用层 API 定义。
  - `js/napi/`：NAPI 层实现（`@ohos.data.preferences`）。
  - `c/`：NDK C API 定义和实现。
- `test/`：测试代码目录。

## 知识路由（遇到什么问题看什么文档）

### 任务路由

按任务类型决定重点关注哪些目录和文件：

| 任务或问题 | 关注点和关键文件 |
| --- | --- |
| 需要了解组件整体架构、数据流向 | 阅读 `README_zh.md`，查看 `figures/zh-cn_首选项运行机制.png` 架构图 |
| 修改 Preferences 核心逻辑（读写、实例管理、序列化） | `frameworks/native/src/preferences_impl.cpp`（XML 实现）、`preferences_enhance_impl.cpp`（GSKV 实现）、`preferences_helper.cpp`（实例管理） |
| 修改 Key/Value 校验逻辑 | `frameworks/native/src/preferences_utils.cpp` 的 `CheckKey` 和 `CheckValue` 方法 |
| 修改内存缓存和异步加载机制 | `frameworks/native/src/preferences_impl.cpp` 的 `valuesCache_`、`loaded_`、`AwaitLoadFile` |
| 修改 Flush 机制（防重入、合并写入） | `frameworks/native/src/preferences_impl.cpp` 的 `Flush`、`FlushSync`、`queue_` |
| 修改 XML 序列化（备份恢复、损坏处理） | `frameworks/native/src/preferences_xml_utils.cpp` 的 `WriteToDiskFile`、`RenameFromBackupFile` |
| 修改 NAPI/ArkTS 接口 | `interfaces/kits/js/napi/` 目录下的源文件 |
| 修改 NDK C API | `interfaces/kits/c/` 目录下的源文件 |

### 词汇路由

任务描述或代码中遇到以下术语时，查阅对应文档：

| 术语 | 含义和文档路由 |
| --- | --- |
| NAPI | Node-API，用于将 C++ 暴露到 ArkTS/JS。详见 `interfaces/kits/js/napi/` |
| ANI | Ark NAPI Interface，静态绑定的 NAPI 替代方案。详见 `interfaces/kits/js/` |
| GSKV | 轻量级数据库存储引擎，高性能替代 XML。详见 `frameworks/native/src/preferences_enhance_impl.cpp` |
| NDK C API | 原生 C 接口，供原生应用使用。详见 `interfaces/kits/c/include/` |
| CJ FFI | Cangjie 语言 FFI 绑定。详见相关目录 |
| Flush | 将内存缓存持久化到磁盘。详见 `preferences_impl.cpp` 的 `Flush` 方法 |
| Observer | 数据变化观察者。详见 `PreferencesObserver` 相关代码 |

## 专家经验（硬约束和最佳实践）

### API 兼容性约束（不可违反）

- **Public API 签名不可变更**：`@ohos.data.preferences` 模块的所有公开接口签名受兼容性约束，修改前需经 API 评审。
- **错误码不可变更**：15500000 系列错误码已公开发布，不可修改语义或数值。
- **行为兼容**：Public API 的语义行为需保持向后兼容，如必须变更需走兼容性流程。
- **NDK API 兼容**：`interfaces/kits/c/include/` 下的 C API 头文件受稳定 ABI 约束。

修改 Public API 前，必须：
1. 查阅 `docs/api_change_process.md`（如有）了解变更流程
2. 确认无替代方案后再申请变更
3. 新增 API 需声明 API 级别

### 数据约束（不可违反）

- **Key 长度约束**：Key 键为 String 类型，必须非空且长度不超过 1024 个字符。超过限制会返回 `E_KEY_EXCEED_MAX_LENGTH` 错误。代码实现在 `frameworks/native/src/preferences_utils.cpp` 的 `CheckKey` 方法中。
- **Value 长度约束**：Value 值为 String 类型时，长度不超过 16 * 1024 * 1024 个字符（16MB）。超过限制会返回 `E_VALUE_EXCEED_MAX_LENGTH` 错误。Object 类型的序列化字符串也受此限制。代码实现在 `CheckValue` 方法中。

### 安全边界（不可违反）

- **数据文件隔离**：每个 Preferences 实例绑定唯一文件路径，不可越权访问其他应用或进程的数据文件。
- **沙箱路径约束**：数据文件必须在应用沙箱目录内，不可写入系统目录或其他应用目录。
- **跨进程同步**：跨进程数据同步需通过 `OH_DataObserver` 机制，不可绕过同步直接操作文件。
- **敏感数据**：Preferences 不加密存储，禁止存储密码、密钥等敏感信息。

### 协议兼容约束

- **XML 文件格式稳定**：Preferences 存储的 XML 文件格式跨版本兼容，修改序列化逻辑需确保向后兼容。
- **备份恢复机制**：`WriteToDiskFile` 先写备份文件，确保异常时可恢复。不可破坏此机制。
- **GSKV 格式兼容**：GSKV 数据库格式需跨版本兼容，修改需评估迁移方案。

### 架构分层约束

- **依赖方向**：上层依赖下层，NAPI/NDK 层依赖 Native 层，不可反向依赖。
- **实例管理集中**：所有 Preferences 实例创建必须通过 `PreferencesHelper`，不可绕过实例管理器直接构造。
- **抽象基类约束**：`PreferencesBase` 是核心抽象，新增实现需继承并实现所有虚函数。

### 已知陷阱

- **异步加载竞态**：首次 Get 时若文件未加载完成会阻塞，修改异步加载逻辑需考虑竞态。

### 变更前必须确认

修改以下内容前，需先阅读相关设计文档或咨询维护者：

- Public API 签名或语义
- 错误码定义
- XML 序列化格式
- GSKV 数据库格式
- 跨进程同步机制
- 实例缓存策略

## 编译和测试方法

### 构建命令

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```sh
# 构建所有测试目标
./build.sh --product-name rk3568 --build-target preferences_test --ccache

# 仅构建组件（无测试）
./build.sh --product-name rk3568 --build-target preferences --ccache
```

### 测试命令

```sh
# 运行单元测试（需在设备或模拟器上）
./test.sh preferences_test

# 测试用例位置
# test/unittest/：单元测试
# test/fuzztest/：模糊测试
```

### 静态检查

```sh
# 代码风格检查（如有配置）
# 参考 .clang-format 和 .clang-tidy

# 提交前检查
git pre-commit  # 如果配置了 pre-commit hook
```

## 验证闭环

### 最小验证（必做）

- 构建通过：`./build.sh --product-name rk3568 --build-target preferences_test --ccache`
- 无新增编译错误或警告

### 任务级验证（按需）

| 任务类型 | 验证方法 |
| --- | --- |
| 修改核心逻辑 | 运行 `preferences_test` 单元测试 |
| 修改 NAPI 接口 | 运行 JS 测试用例 |
| 修改 NDK API | 运行 NDK 测试用例 |
| 修改序列化逻辑 | 运行跨版本兼容性测试（如有） |

### Done 定义

任务完成需满足：

1. 代码修改完成，符合编码规范
2. 构建通过，无新增警告
3. 相关测试通过
4. 已添加或更新测试用例（如修改了核心逻辑）
5. 已更新相关文档（如修改了 Public API）

### 响应期望

完成修改后，响应中必须包含：

1. 修改摘要：改了什么、为什么改
2. 验证结果：构建状态、测试结果
3. 影响范围：影响的 API、模块或行为
4. 遗留问题：如有未解决事项需说明

### 验证无法执行时

如果无法执行构建或测试（如无开发环境），响应中必须：

1. 明确说明无法验证的原因
2. 提供手动验证步骤供用户执行
3. 列出需人工确认的风险点