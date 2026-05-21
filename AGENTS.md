# 首选项组件指引

## 项目定位

本仓库对应 OpenHarmony `foundation/distributeddatamgr/preferences`。优先按这些目录定位问题：

- `frameworks/native/`：Native C++ 核心实现，包括 Preferences 实例管理、数据读写、XML 序列化。
- `frameworks/ndk/`：NDK 接口实现，对外提供 C API。
- `frameworks/js/napi/`：NAPI 实现，包括 preferences、storage、sendable_preferences。
- `interfaces/inner_api/`：内部接口声明，对外暴露的头文件。
- `interfaces/ndk/`：NDK 公开接口头文件。
- `test/`：单元测试和 fuzz 目标。

## 构建和验证

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```sh
./build.sh --product-name rk3568 --build-target preferences_test --ccache
./build.sh --product-name rk3568 --build-target native_preferences --ccache
prebuilts/build-tools/linux-x86/bin/ninja -C out/rk3568 NativePreferencesTest
prebuilts/build-tools/linux-x86/bin/ninja -C out/rk3568 NDKPreferencesTest
```

涉及数据持久化、跨进程数据同步、内存管理或文件锁行为验证需要补充板侧证据。提交使用 `git commit -s`，并保留 `Co-Authored-By: Agent`。

## 项目约束

- Key 键为 String 类型，要求非空且长度不超过 1024 个字符。
- Value 值为 String 类型时，长度不超过 16 * 1024 * 1024 个字符。
- 存储的数据量应该是轻量级的，建议不超过一万条记录，否则会在内存方面产生较大开销。
- 数据同时加载在内存中以保证访问速度，不适合存储大量数据。
- Flush 和 FlushSync 是异步和同步持久化接口，数据修改后需显式调用才会写入磁盘。
- 支持两种存储类型：XML（默认）和 GSKV（需要 arkdata_database_core 部件）。
- 支持观察者模式，可监听数据变更，包括本地变更和多进程变更。
- C++ 改动优先复用项目中的错误码定义（`E_OK`、`E_INVALID_ARGS` 等）和日志宏。