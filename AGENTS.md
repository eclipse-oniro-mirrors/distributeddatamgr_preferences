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

## 知识路由（遇到什么问题看什么文档）

按任务类型决定重点关注哪些目录和文件：

| 任务或问题 | 关注点和关键文件 |
| --- | --- |
| 需要了解组件整体架构、数据流向 | 阅读 `README_zh.md`，查看 `figures/zh-cn_首选项运行机制.png` 架构图 |
| 修改 Preferences 核心逻辑（读写、实例管理、序列化） | `frameworks/native/src/preferences_impl.cpp`（XML 实现）、`preferences_enhance_impl.cpp`（GSKV 实现）、`preferences_helper.cpp`（实例管理） |
| 修改 Key/Value 校验逻辑 | `frameworks/native/src/preferences_utils.cpp` 的 `CheckKey` 和 `CheckValue` 方法 |
| 修改内存缓存和异步加载机制 | `frameworks/native/src/preferences_impl.cpp` 的 `valuesCache_`、`loaded_`、`AwaitLoadFile` |
| 修改 Flush 机制（防重入、合并写入） | `frameworks/native/src/preferences_impl.cpp` 的 `Flush`、`FlushSync`、`queue_` |
| 修改 XML 序列化（备份恢复、损坏处理） | `frameworks/native/src/preferences_xml_utils.cpp` 的 `WriteToDiskFile`、`RenameFromBackupFile` |

## 专家经验（硬约束和最佳实践）

### 数据约束（不可违反）

- **Key 长度约束**：Key 键为 String 类型，必须非空且长度不超过 1024 个字符。超过限制会返回 `E_KEY_EXCEED_MAX_LENGTH` 错误。代码实现在 `frameworks/native/src/preferences_utils.cpp` 的 `CheckKey` 方法中。
- **Value 长度约束**：Value 值为 String 类型时，长度不超过 16 * 1024 * 1024 个字符（16MB）。超过限制会返回 `E_VALUE_EXCEED_MAX_LENGTH` 错误。Object 类型的序列化字符串也受此限制。代码实现在 `CheckValue` 方法中。

## 编译和测试方法

### 构建命令

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```sh
# 构建所有测试目标
./build.sh --product-name rk3568 --build-target preferences_test --ccache
```