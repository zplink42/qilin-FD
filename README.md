# Qilin FlowDroid Bridge

这是一个普通 Java 应用工程，用来把 FlowDroid 当作 Qilin 指针分析效果的观测工具，而不是开发
Android 应用或修改 FlowDroid 内部实现。项目支持两种运行方式：

- `qilin`：加载独立 Qilin JAR 运行 PTA，再由本工程将 Qilin call graph 和 points-to
  查询适配给独立 FlowDroid JAR。这是当前主要实验路径。
- `native`：直接使用 FlowDroid/Soot 自身的 call graph 配置，作为不经过 Qilin 的基线。

## 当前结论

默认评估构件是未修改的
`D:/gitdesk/Qilin/artifact/Qilin-0.9.8-SNAPSHOT.jar`。它只负责 Qilin PTA 与其
经典 Soot 数据模型；本工程仅依赖 `qilin.core.PTA` 的 `getCallGraph()` 与
`reachingObjects(...)` 系列接口，并在 `src/main/java/dev/qilinfd/bridge/` 内完成
FlowDroid 所需的 points-to 与 ICFG 适配。

`D:/gitdesk/sootup/build/libs/sootup-qilin-1.0.0-SNAPSHOT.jar` 使用的是
`sootup.core.*` 模型与自己的调用图类型；当前 FlowDroid `soot-infoflow` 使用经典
`soot.*` API，因此该 JAR 不能直接接到同一条 FlowDroid 路径上。

详细接口对应关系见 [docs/qilin-flowdroid-interface.md](docs/qilin-flowdroid-interface.md)。

## 依赖布局

默认运行时的两个核心分析构件是：

- `D:/gitdesk/Qilin/artifact/Qilin-0.9.8-SNAPSHOT.jar`：可替换的 Qilin PTA JAR，
  当前包含与 PTA 配套的经典 Soot `4.7.1`。
- `de.fraunhofer.sit.sse.flowdroid:soot-infoflow:2.15.1`：独立 FlowDroid JAR；
  该版本同样面向 Soot `4.7.1`。

工程显式添加 FlowDroid 运行所需的 Trove 支持库和日志实现，但不引入第二份 Soot。
可将使用的 FlowDroid JAR 同步到本地 `lib/flowdroid/` 供检查：

```powershell
gradle stageFlowDroidJar
```

如本机路径变化，复制 `gradle.properties.example` 为 `gradle.properties` 并修改
`qilinJar`、`analysisJre`。

## 快速验证

运行工程自带的普通 Java 泄漏样例：

```powershell
gradle test verifySmokeQilin verifySmokeNative
```

运行已拉取的 SecuriBench Micro 中已知存在 1 条泄漏的 `Basic1`：

```powershell
gradle verifySecuriBenchBasic1Qilin
```

运行三个 GitHub Java 项目中经源码确认的漏洞路径：

```powershell
gradle verifyGithubCorpusQilin
```

结果写在 `results/`。`qilin` 输出包含 Qilin 调用图边数、PTA 耗时、
FlowDroid 耗时和泄漏结果；`native` 输出提供 FlowDroid/Soot 基线结果。

## 配置实验

配置文件位于 `benchmarks/config/`。关键字段如下：

| 字段 | 作用 | 示例 |
| --- | --- | --- |
| `backend` | 选择后端 | `qilin` / `native` |
| `pta` | Qilin PTA 模式 | `insens` / `1o` |
| `callgraphMode` | 向 FlowDroid 提供 Qilin 公共调用图 | `qilin` |
| `aliasing` | FlowDroid aliasing 算法 | `pts` / `flow` / `lazy` / `none` |
| `nativeCallgraph` | native 后端的 Soot 调用图算法 | `spark` / `cha` / `rta` / `vta` |
| `qilinExtraArgs` | 原样传给可替换 Qilin JAR 的附加 PTA 参数 | `-cd` |

也可以直接运行应用，并用 `--set` 覆盖单个字段：

```powershell
gradle run --args="run --config benchmarks/config/smoke-qilin.properties --set appPath=build/smoke/qilinfd-smoke.jar --set jre=D:/gitdesk/Qilin/artifact/benchmarks/JREs/jre1.8.0_121_debug --set pta=1o --set output=results/smoke-1o.txt"
```

## 测试语料

- `benchmarks/securibench-micro`：原始 Java SecuriBench Micro 子模块，适合 precision/recall
  小测试，且用例带预期漏洞数量。
- `benchmarks/flowdroid-official`：FlowDroid 官方子模块；其中
  `soot-infoflow/test/soot/jimple/infoflow/test/securibench` 提供普通 Java 的官方
  期望结果映射，可继续转成批量 Qilin 实验清单。
- `benchmarks/github/benchmark-java`：OWASP BenchmarkJava，当前选取一个官方标记为
  `true` 的 XSS 用例进行 Qilin/FlowDroid 实测。
- `benchmarks/github/juliet-test-suite`：Juliet Java Test Suite，当前选取 CWE-78
  环境变量到命令执行的明确坏路径。
- `benchmarks/github/vulnerable-app`：SasanLabs VulnerableApp，当前选取命令注入
  Level 1 路由，并以普通 Java harness 模拟 Spring 请求参数输入。
- `benchmarks/smoke`：本工程的最小、可稳定执行的 Java 集成样例。

FlowDroid 官方仓库也含 DroidBench，但它属于 Android 测试集，不作为本工程的默认目标。
三个 GitHub 项目的 source/sink 取证、入口建模方式与实测结果记录在
[docs/github-taint-corpus-report.md](docs/github-taint-corpus-report.md)。
