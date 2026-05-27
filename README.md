# Qilin FlowDroid Bridge

这是一个普通 Java 应用工程，用来把 FlowDroid 当作 Qilin 指针分析效果的观测工具，而不是开发
Android 应用或修改 FlowDroid 内部实现。项目支持两种运行方式：

- `qilin`：加载独立 Qilin JAR 运行 PTA，再由本工程将 Qilin call graph 和 points-to
  查询适配给独立 FlowDroid JAR。这是当前主要实验路径。
- `native`：直接使用 FlowDroid/Soot 自身的 call graph 配置，作为不经过 Qilin 的基线。

## 当前结论

默认评估构件是已复制到本工程、包含 Tamiflex local 登记修复的版本
`lib/qilin/Qilin-0.9.8-SNAPSHOT.jar`，其来源为
`D:/gitdesk/Qilin/artifact/Qilin-0.9.8-SNAPSHOT.jar`。它只负责 Qilin PTA 与其
经典 Soot 数据模型；本工程仅依赖 `qilin.core.PTA` 的 `getCallGraph()` 与
`reachingObjects(...)` 系列接口，并在 `src/main/java/dev/qilinfd/bridge/` 内完成
FlowDroid 所需的 points-to 适配和既有调用图安装。

`D:/gitdesk/sootup/build/libs/sootup-qilin-1.0.0-SNAPSHOT.jar` 使用的是
`sootup.core.*` 模型与自己的调用图类型；当前 FlowDroid `soot-infoflow` 使用经典
`soot.*` API，因此该 JAR 不能直接接到同一条 FlowDroid 路径上。

详细接口对应关系见 [docs/qilin-flowdroid-interface.md](docs/qilin-flowdroid-interface.md)。
第一次接触 FlowDroid 时，请从
[docs/flowdroid-for-qilin-users.md](docs/flowdroid-for-qilin-users.md) 开始阅读，其中
按执行顺序解释了 source/sink、桥接流程与所有常用配置项。

## 依赖布局

默认运行时的两个核心分析构件是：

- `lib/qilin/Qilin-0.9.8-SNAPSHOT.jar`：工程内默认、可替换的 Qilin PTA JAR，
  当前包含与 PTA 配套的经典 Soot `4.7.1`。
- `de.fraunhofer.sit.sse.flowdroid:soot-infoflow:2.15.1`：独立 FlowDroid JAR；
  该版本同样面向 Soot `4.7.1`。

工程显式添加 FlowDroid 运行所需的 Trove 支持库和日志实现，但不引入第二份 Soot。
可将使用的 FlowDroid JAR 同步到本地 `lib/flowdroid/` 供检查：

```powershell
gradle stageFlowDroidJar
```

要评估另一个 Qilin 版本，把兼容的 JAR 放入 `lib/qilin/` 并在命令中选择它：

```powershell
.\gradlew.bat verifySmokeQilin -PqilinJar=lib/qilin/Qilin-my-optimization.jar
```

也可以复制 `gradle.properties.example` 为 `gradle.properties`，长期设置
`qilinJar`。

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

配置文件位于 `benchmarks/config/`。配置分成三部分：

1. 顶层公共字段：描述被分析程序、source/sink 和两条路线共同使用的 FlowDroid 设置。
2. `qilinFlags`：仅描述 Qilin JAR 自身的 PTA/建图参数。
3. `nativeFlags`：仅描述 native FlowDroid/Soot 路线特有的建图参数。

| 公共字段 | 必要性 | 作用 | 示例 |
| --- | --- | --- | --- |
| `backend` | 必需 | 选择执行方向 | `qilin` / `native` |
| `label` | 可选 | 写入结果的实验名称 | `smoke-qilin` |
| `appPath` | 必需 | 被分析的普通 Java 应用 JAR 或目录 | `build/smoke/qilinfd-smoke.jar` |
| `libraries` | 可选 | 应用依赖库 JAR 或目录 | `benchmarks/securibench-micro/lib` |
| `mainClass` | 必需 | 包含 `main(String[])` 的入口类 | `dev.qilinfd.bench.SimpleLeak` |
| `jre` | 通常必需 | 分析目标使用的 JRE；Qilin 接收该路径，native 将其 `lib/*.jar` 加入 classpath | `benchmarks/JREs/jre1.8.0_121_debug` |
| `reflectionLog` | 可选 | 目标程序的反射日志；当前 Qilin 路线会传给 Qilin JAR | `benchmarks/dacapo2006/eclipse-refl.log` |
| `sources` | 必需 | FlowDroid source 签名定义文件 | `benchmarks/definitions/smoke-sources.txt` |
| `sinks` | 必需 | FlowDroid sink 签名定义文件 | `benchmarks/definitions/smoke-sinks.txt` |
| `output` | 可选 | bridge 输出文本结果的位置 | `results/smoke-qilin.txt` |
| `aliasing` | 可选，默认 `pts` | 两条路线共用的 FlowDroid alias 策略 | `pts` / `flow` / `lazy` / `none` |
| `threads` | 可选，默认 `1` | FlowDroid 数据流阶段最大线程数 | `1` |
| `timeoutSeconds` | 可选，默认 `0` | FlowDroid 数据流阶段超时；`0` 表示不设置超时 | `300` |
| `qilinFlags` | `backend=qilin` 时必需 | 可替换 Qilin JAR 特有的选项 | 见下表 |
| `nativeFlags` | `backend=native` 时必需 | native FlowDroid/Soot 特有的选项 | 见下表 |

`appPath`、`libraries`、`mainClass`、`jre`、`sources`、`sinks` 与 FlowDroid 公共设置
故意位于顶层：比较 Qilin 与 native 时，这些内容应保持同一份定义。配置加载器会拒绝
在 `qilinFlags` 或 `nativeFlags` 中再次放入这些选项，防止配置含义重复。

Qilin 路径配置示例：

```properties
backend=qilin
label=smoke-qilin
appPath=build/smoke/qilinfd-smoke.jar
mainClass=dev.qilinfd.bench.SimpleLeak
jre=benchmarks/JREs/jre1.8.0_121_debug
aliasing=pts
threads=1
qilinFlags=-pae -pe -clinit=ONFLY -lcs -mh -se -pta=insens
sources=benchmarks/definitions/smoke-sources.txt
sinks=benchmarks/definitions/smoke-sinks.txt
output=results/smoke-qilin.txt
```

Native 基线配置示例：

```properties
backend=native
label=smoke-native
appPath=build/smoke/qilinfd-smoke.jar
mainClass=dev.qilinfd.bench.SimpleLeak
jre=benchmarks/JREs/jre1.8.0_121_debug
aliasing=pts
threads=1
nativeFlags=-cgalgo=SPARK
sources=benchmarks/definitions/smoke-sources.txt
sinks=benchmarks/definitions/smoke-sinks.txt
output=results/smoke-native.txt
```

### `qilinFlags` 参数

这些参数原样传给可替换的 Qilin JAR。bridge 会依据顶层公共字段自动补充 Qilin
所需的 `-apppath`、`-libpath`、`-mainclass`、`-jre` 和 `-reflectionlog`。
下表覆盖当前 `Qilin-0.9.8-SNAPSHOT.jar` 中应由用户选择的分析选项。

| 参数 | 作用 |
| --- | --- |
| `-includeall` | 意图为包含默认未分析的包；Qilin 0.9.8 源码对该选项的检查存在拼写问题，当前不要依赖它 |
| `-exclude <pkg1;pkg2>` | 排除指定包 |
| `-pta=<pattern>` | 选择 PTA，例如 `insens`、`1o`、`2o1h` |
| `-pae` | 使用更精确的数组元素类型 |
| `-pe` | 更精确地处理异常流 |
| `-clinit=APP|FULL|ONFLY` | 选择类初始化方法的加载方式 |
| `-mh` | 合并 StringBuilder/StringBuffer/Throwable 等 heap |
| `-lcs` | 对 String/Exception 等类型限制 heap context |
| `-se` | 仅使用一个 main 方法入口的轻量模式 |
| `-sc` | 区分并传播字符串常量 |
| `-cga=CHA|VTA|RTA|SPARK|GEOM|QILIN` | 选择 Qilin 运行阶段的调用图算法 |
| `-cd` | 启用 context debloating |
| `-cda=CONCH|DEBLOATERX` | 选择 debloating 方法 |
| `-tc=DEFAULT|PHASE_ONE|PHASE_TWO` | Turner 配置 |
| `-tmd` | 令 Turner 以 modular 方式运行 |
| `-pre` | 仅运行 pre-analysis |
| `-dumpcallgraph` | 输出调用图 |
| `-dumpjimple` | 输出应用 Jimple |
| `-dumpstats` | 输出完整统计 |
| `-dumpsimplestats` | 输出简化统计 |
| `-dumppts` | 输出应用 points-to 结果 |
| `-dumpallpts` | 同时输出库变量 points-to 结果 |
| `-dumppag` | 输出 PAG |

### `nativeFlags` 参数

`native` 表示不调用 Qilin。程序输入和 FlowDroid 公共设置仍读取顶层字段；
当前 native 专属参数只有 Soot 调用图算法：

| 参数 | 作用 |
| --- | --- |
| `-cgalgo=AUTO|CHA|VTA|RTA|SPARK|GEOM|ONDEMAND` | 由 FlowDroid/Soot 构建调用图时采用的算法 |

`BridgeMain` 在无参数启动时读取 `benchmarks/config/dacapo-eclipse-qilin.properties`，
其中顶层字段描述 Eclipse 输入、反射日志与 FlowDroid 设置，`qilinFlags` 只包含
Qilin 分析选择。该配置同时包含 FlowDroid 所需的示例 source/sink。

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
