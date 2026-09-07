# Qilin-FD 三个逐步污点分析实验

本文通过三个可以直接运行的普通 Java 实验，说明如何把一个应用接入 `qilin-FD`：
先从源码确定需要观察的 source 和 sink，再选择 Qilin/FlowDroid 参数，运行分析，
最后将 FlowDroid 报告与人工或官方预期进行对照。

三个实验由小到大：

| 实验 | 应用来源 | 选择动机 | 预期污点流 |
| --- | --- | --- | --- |
| 1. Smoke | 本工程最小样例 | 先看清完整管线，不受库代码影响 | 1 |
| 2. FlowDroid `ConstantTestCode.easyConstantVarTest` | FlowDroid 官方测试代码 | 用官方已有期望结果验证 Qilin 后端可复现 FlowDroid 正例 | 1 |
| 3. Juliet CWE-78 `Environment_01.bad()` | GitHub 上的 Juliet Test Suite | 用实际漏洞类别检验环境输入到命令执行的传播 | 1 |

这三个实验都使用 `backend=qilin`。因此运行顺序始终是：

```mermaid
flowchart LR
    A["编译目标应用与 harness"] --> B["Qilin 构造 call graph 和 points-to 结果"]
    B --> C["bridge 安装 Qilin 结果"]
    C --> D["FlowDroid 按 source/sink 传播污点"]
    D --> E["results/*.txt 与预期对照"]
```

## 1. 准备与读法

### 1.1 前置条件

在项目根目录执行命令。当前三个实验共同依赖：

| 条件 | 位置或含义 |
| --- | --- |
| Qilin JAR | `lib/qilin/Qilin-0.10.10.3-SNAPSHOT.jar`（Soot 4.6.0） |
| FlowDroid JAR | Gradle 依赖 `soot-infoflow:2.14.1` |
| Java 运行环境模型 | `benchmarks/JREs/jre1.8.0_121_debug` |
| 桥接入口 | `dev.qilinfd.bridge.BridgeMain` |

一次运行某个配置文件的通用形式为：

```powershell
.\gradlew.bat run --args="run --config benchmarks/config/<配置文件>.properties" --no-daemon
```

教程所选的三个实验也可以一次执行并检查期望值：

```powershell
.\gradlew.bat verifyGuidedExperimentsQilin --no-daemon --stacktrace
```

### 1.2 分析一个新应用时的步骤

| 步骤 | 要回答的问题 | 本项目中的产物 |
| --- | --- | --- |
| 1. 阅读源码 | 什么值是不可信输入，什么调用是危险使用？ | source/sink 判断依据 |
| 2. 确定入口 | 哪个 `main` 能触发需要分析的方法？ | 原有入口或 analysis-only harness |
| 3. 定义 source/sink | FlowDroid 应给哪些方法返回值加污点、检查哪些参数？ | `benchmarks/definitions/*.txt` |
| 4. 配置分析 | 输入 JAR、入口、Qilin PTA 和 FlowDroid alias 策略是什么？ | `benchmarks/config/*.properties` |
| 5. 运行并核对 | 输出流是否与源码预期一致？ | `results/*.txt` |

这里的 source/sink 不是由 FlowDroid 自动猜测出来的。实验人员根据待检查的安全问题
选定方法签名，FlowDroid 负责判断二者之间是否存在传播路径。

### 1.3 三个实验为何使用同一组选项

三个配置都保留如下分析设置：

```properties
backend=qilin
jre=benchmarks/JREs/jre1.8.0_121_debug
aliasing=pts
threads=1
qilinFlags=-pae -pe -clinit=ONFLY -lcs -mh -se -pta=insens
```

| 设置 | 选择理由 |
| --- | --- |
| `backend=qilin` | 目标是观察 Qilin 为 FlowDroid 提供 call graph 与 points-to 的效果 |
| `aliasing=pts` | FlowDroid 的 alias 查询使用 Qilin points-to 结果，这正是桥接的关键路径 |
| `threads=1` | 小规模教程场景优先保持运行方式简单、输出稳定 |
| `-pta=insens` | 使用清晰的上下文不敏感基线，后续可只替换此项或 JAR 比较优化 |
| `-pae -pe -clinit=ONFLY -lcs -mh` | 延续项目默认 Qilin 建模选项，使三个应用之间可比较 |
| `-se` | 教程 JAR 都通过单一 harness/main 进入，使用单入口模式即可 |

`qilinCallEdges` 表示 Qilin 提供给 FlowDroid 的调用图规模；`flowDroidLeaks` 表示
FlowDroid 找到的 source-to-sink 连接数。运行时间受机器负载影响，不应作为一次运行
是否正确的硬断言。

## 2. 实验一：Smoke 最小样例

### 2.1 动机

Smoke 样例只有一个 source 调用和一个 sink 调用。它用来验证最基本的事实：
Qilin 能够建立包含该调用的调用图，bridge 能安装 points-to/call graph，
FlowDroid 能够从一个定义明确的 source 传播到 sink。

### 2.2 原始源码分析

目标源码是：

- `benchmarks/smoke/src/dev/qilinfd/bench/SimpleLeak.java`
- `benchmarks/smoke/src/dev/qilinfd/bench/TaintApi.java`

关键路径为：

```java
String value = TaintApi.source();
TaintApi.sink(value);
```

肉眼判断：

| 位置 | 角色 | 原因 |
| --- | --- | --- |
| `TaintApi.source()` 的返回值 | source | 它专门表示敏感值的产生位置 |
| `TaintApi.sink(String)` 的参数 | sink | 传入该方法即视为敏感值被使用 |
| `value` | 传播载体 | 同一个本地变量从 source 返回值直接传入 sink |

因此无需任何别名或复杂调用分析，人眼预期恰好有 `1` 条污点流。

### 2.3 Source 与 sink 定义

`benchmarks/definitions/smoke-sources.txt`：

```text
<dev.qilinfd.bench.TaintApi: java.lang.String source()>
```

`benchmarks/definitions/smoke-sinks.txt`：

```text
<dev.qilinfd.bench.TaintApi: void sink(java.lang.String)>
```

定义采用 classic Soot 方法签名格式：`<类名: 返回类型 方法名(参数类型)>`。

### 2.4 配置设计

配置文件为 `benchmarks/config/smoke-qilin.properties`：

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

这里不需要 `libraries`：目标 JAR 只包含本项目的两个类，JRE 之外没有外部依赖。
`appPath` 的 JAR 由 Gradle 的 `smokeJar` 任务在分析前自动构建。

### 2.5 执行

```powershell
.\gradlew.bat verifySmokeQilin --no-daemon --stacktrace
```

该任务先构建 `build/smoke/qilinfd-smoke.jar`，再运行配置，并断言结果文件包含
`flowDroidLeaks=1`。

### 2.6 实际结果与分析

本次实测结果来自 `results/smoke-qilin.txt`：

```text
qilinCallEdges=9
flowDroidLeaks=1
ptaRuntimeMs=921
flowDroidRuntimeMs=192
"<dev.qilinfd.bench.SimpleLeak: void main(java.lang.String[])>","value = staticinvoke <dev.qilinfd.bench.TaintApi: java.lang.String source()>() @line 8","<dev.qilinfd.bench.SimpleLeak: void main(java.lang.String[])>","staticinvoke <dev.qilinfd.bench.TaintApi: void sink(java.lang.String)>(value) @line 9"
```

| 对照项 | 预期 | 实际 | 结论 |
| --- | --- | --- | --- |
| 污点流数量 | 1 | 1 | 符合 |
| source 位置 | `SimpleLeak.java:8` | `SimpleLeak.java:8` | 符合 |
| sink 位置 | `SimpleLeak.java:9` | `SimpleLeak.java:9` | 符合 |

该实验确认最短的 Qilin-to-FlowDroid 数据路径工作正常。它适合作为更换 Qilin JAR
后的第一项回归测试，但不足以评价复杂别名或大规模调用图精度。

## 3. 实验二：FlowDroid 官方 ConstantTestCode

### 3.1 动机与选例依据

FlowDroid 官方仓库的普通 Java 测试代码中包含
`soot.jimple.infoflow.test.ConstantTestCode.easyConstantVarTest()`。选择它有两个原因：

| 理由 | 说明 |
| --- | --- |
| 源码容易人工检查 | source 返回值被直接保存到 `e`，随后传给 sink |
| 官方已有预期 | 官方 `ConstantTests.easyConstantVarTest()` 调用 `checkInfoflow(infoflow, 1)` |

官方 helper 的包名包含 `test.android`，但本实验分析的是普通 Java 类和普通 Java
stub，并不构建或运行 Android 应用。

### 3.2 官方源码与官方预期

官方目标代码位于
`benchmarks/flowdroid-official/soot-infoflow/test/soot/jimple/infoflow/test/ConstantTestCode.java`：

```java
public void easyConstantVarTest(){
    final String e = TelephonyManager.getDeviceId();
    ConnectionManager cm = new ConnectionManager();
    cm.publish(e);
}
```

官方测试位于
`benchmarks/flowdroid-official/soot-infoflow/test/soot/jimple/infoflow/test/junit/ConstantTests.java`：

```java
epoints.add("<soot.jimple.infoflow.test.ConstantTestCode: void easyConstantVarTest()>");
infoflow.computeInfoflow(appPath, libPath, epoints, sources, sinks);
checkInfoflow(infoflow, 1);
```

所以这个实验的预期不是项目自行臆定，而是来自 FlowDroid 自己的回归测试：`1` 条流。

### 3.3 普通 Java 入口适配

官方 JUnit 直接将 `easyConstantVarTest()` 作为入口；`qilin-FD` 的配置入口是包含
`main(String[])` 的普通 Java 类。因此工程新增了仅用于分析的 harness：

`benchmarks/harness/flowdroid-official/src/dev/qilinfd/bench/flowdroid/ConstantTestHarness.java`

```java
public static void main(String[] args) {
    new ConstantTestCode().easyConstantVarTest();
}
```

这个 harness 不改变目标方法中的数据流，只提供一个 Qilin 可识别的应用入口。
Gradle 会将以下类打包为待分析 JAR：

| 类 | 原因 |
| --- | --- |
| `ConstantTestCode` | 包含被验证的数据流 |
| `TelephonyManager` | 定义 source 方法 |
| `ConnectionManager` | 定义 sink 方法 |
| `ConstantTestHarness` | 提供 `main` 入口 |

### 3.4 Source 与 sink 定义

从官方 `JUnitTests` 的 source/sink 常量和目标源码可得到：

`benchmarks/definitions/flowdroid-official-constant-sources.txt`：

```text
<soot.jimple.infoflow.test.android.TelephonyManager: java.lang.String getDeviceId()>
```

`benchmarks/definitions/flowdroid-official-constant-sinks.txt`：

```text
<soot.jimple.infoflow.test.android.ConnectionManager: void publish(java.lang.String)>
```

肉眼传播链为：

```text
TelephonyManager.getDeviceId() -> e -> ConnectionManager.publish(e)
```

### 3.5 配置设计

配置文件为 `benchmarks/config/flowdroid-official-constant-qilin.properties`：

```properties
backend=qilin
label=flowdroid-official-constant-easy-var-qilin
appPath=build/flowdroid-official/constant/flowdroid-official-constant-selected.jar
mainClass=dev.qilinfd.bench.flowdroid.ConstantTestHarness
jre=benchmarks/JREs/jre1.8.0_121_debug
aliasing=pts
threads=1
qilinFlags=-pae -pe -clinit=ONFLY -lcs -mh -se -pta=insens
sources=benchmarks/definitions/flowdroid-official-constant-sources.txt
sinks=benchmarks/definitions/flowdroid-official-constant-sinks.txt
output=results/flowdroid-official-constant-qilin.txt
```

和 smoke 一样，此实验不需要 `libraries`，因为选出的官方类只依赖 JRE 和一同打包
的两个 helper。保持同一套 Qilin flags 能避免因参数变化而影响结果解释。

### 3.6 执行

```powershell
.\gradlew.bat verifyFlowDroidOfficialConstantQilin --no-daemon --stacktrace
```

该任务编译并打包官方选例，运行 Qilin-backed FlowDroid，并检查
`flowDroidLeaks=1`。

### 3.7 实际结果与分析

本次实测结果来自 `results/flowdroid-official-constant-qilin.txt`：

```text
qilinCallEdges=18
flowDroidLeaks=1
ptaRuntimeMs=971
flowDroidRuntimeMs=222
"<soot.jimple.infoflow.test.ConstantTestCode: void easyConstantVarTest()>","e = staticinvoke <soot.jimple.infoflow.test.android.TelephonyManager: java.lang.String getDeviceId()>() @line 35","<soot.jimple.infoflow.test.ConstantTestCode: void easyConstantVarTest()>","virtualinvoke cm.<soot.jimple.infoflow.test.android.ConnectionManager: void publish(java.lang.String)>(e) @line 37"
```

| 对照项 | 官方/人工预期 | 实际 | 结论 |
| --- | --- | --- | --- |
| 污点流数量 | 官方断言 1 | 1 | 符合官方测试 |
| source 位置 | `ConstantTestCode.java:35` | 第 35 行 | 符合 |
| sink 位置 | `ConstantTestCode.java:37` | 第 37 行 | 符合 |

该实验表明：当 FlowDroid 的 source/sink 与官方测试保持一致时，使用 Qilin 提供的
call graph 和 points-to 仍能复现官方正例。它比 smoke 更有价值，因为预期来自
FlowDroid 上游测试集。

## 4. 实验三：Juliet CWE-78 命令注入

### 4.1 为什么选择 Juliet

已有三个 GitHub 实验分别覆盖 OWASP Benchmark XSS、Juliet 命令注入和
VulnerableApp 命令注入。本教程选择 Juliet，原因如下：

| 候选 | 教程上的权衡 |
| --- | --- |
| OWASP Benchmark XSS | 有真实 Web source/sink，但需要先解释 Servlet response 与 XSS 输出语义 |
| VulnerableApp | 接近实际 Spring 应用，但依赖更多库，路径包含多个 OS 分支并报告两条 sink |
| Juliet CWE-78 | source 和 sink 都是 JDK 方法，源码自带 `POTENTIAL FLAW` 标注，预期最直观 |

Juliet 因而适合从单元性质的官方例子过渡到有明确安全含义的公开漏洞样例。

### 4.2 原始源码分析

目标代码为：

`benchmarks/github/juliet-test-suite/src/testcases/CWE78_OS_Command_Injection/CWE78_OS_Command_Injection__Environment_01.java`

其 `bad()` 方法关键语句是：

```java
data = System.getenv("ADD");
...
Process process = Runtime.getRuntime().exec(osCommand + data);
```

源文件注释已经给出漏洞意图：

| 代码位置 | 源码含义 | 污点角色 |
| --- | --- | --- |
| 第 31 行 `System.getenv("ADD")` | 从环境变量读取用户可影响的数据 | source |
| 第 46 行 `Runtime.getRuntime().exec(osCommand + data)` | 将含输入的数据拼接到系统命令执行 | sink |

`goodG2B()` 使用固定字符串 `"foo"`，不会从本实验选定 source 得到污染。为了让分析
目标明确，harness 只调用 `bad()`：

`benchmarks/harness/github/juliet/src/testcases/CWE78_OS_Command_Injection/CWE78EnvironmentHarness.java`

```java
public static void main(String[] args) throws Throwable {
    new CWE78_OS_Command_Injection__Environment_01().bad();
}
```

因此人工预期为：从 `System.getenv` 到 `Runtime.exec(String)` 有且仅有 `1` 条已选
坏路径中的 flow。

### 4.3 Source 与 sink 定义

`benchmarks/definitions/github-juliet-cwe78-sources.txt`：

```text
<java.lang.System: java.lang.String getenv(java.lang.String)>
```

`benchmarks/definitions/github-juliet-cwe78-sinks.txt`：

```text
<java.lang.Runtime: java.lang.Process exec(java.lang.String)>
```

这里的定义比 smoke 更接近真实漏洞分析：环境变量并不总是危险，但针对命令注入问题，
它可以作为攻击者可控数据；`Runtime.exec(String)` 的命令参数则是需检查的敏感使用点。

### 4.4 配置设计

配置文件为 `benchmarks/config/github-juliet-cwe78.properties`：

```properties
backend=qilin
label=github-juliet-cwe78-environment-01
appPath=build/github/juliet/juliet-cwe78-environment-selected.jar
libraries=benchmarks/github/juliet-test-suite/lib/servlet-api.jar
mainClass=testcases.CWE78_OS_Command_Injection.CWE78EnvironmentHarness
jre=benchmarks/JREs/jre1.8.0_121_debug
aliasing=pts
threads=1
qilinFlags=-pae -pe -clinit=ONFLY -lcs -mh -se -pta=insens
sources=benchmarks/definitions/github-juliet-cwe78-sources.txt
sinks=benchmarks/definitions/github-juliet-cwe78-sinks.txt
output=results/github-juliet-cwe78.txt
```

与前两个实验相比，新增 `libraries` 是因为 Juliet 的测试基类源码引用 Servlet API；
它是编译/解析依赖，并不改变本次选择的 `System.getenv` 到 `Runtime.exec` 污点问题。

### 4.5 执行

```powershell
.\gradlew.bat verifyJulietQilin --no-daemon --stacktrace
```

该任务只打包 CWE-78 目标类、必要测试支持类与 harness，而不是将整个 Juliet 大型语料
一次性送入分析；这使教学实验快速且对应关系明确。

### 4.6 实际结果与分析

本次实测结果来自 `results/github-juliet-cwe78.txt`：

```text
qilinCallEdges=45353
flowDroidLeaks=1
ptaRuntimeMs=11312
flowDroidRuntimeMs=1142
"<testcases.CWE78_OS_Command_Injection.CWE78_OS_Command_Injection__Environment_01: void bad()>","data = staticinvoke <java.lang.System: java.lang.String getenv(java.lang.String)>(""ADD"") @line 31","<testcases.CWE78_OS_Command_Injection.CWE78_OS_Command_Injection__Environment_01: void bad()>","process = virtualinvoke $stack11.<java.lang.Runtime: java.lang.Process exec(java.lang.String)>(data) @line 46"
```

| 对照项 | 预期 | 实际 | 结论 |
| --- | --- | --- | --- |
| 漏洞类型 | CWE-78 命令注入 | `System.getenv` 到 `Runtime.exec` | 符合 |
| 污点流数量 | 1 | 1 | 符合 |
| source 位置 | 源码第 31 行 | 第 31 行 | 符合 |
| sink 位置 | 源码第 46 行 | 第 46 行 | 符合 |

`qilinCallEdges=45353` 显著大于前两个实验，并不是该方法的数据流更长，而是分析输入
包含 JRE 与 Juliet 支持代码后，可达调用图更大。该结果已经开始具备评估 Qilin
性能和精度变化的价值。

## 5. 三个实验的横向结论

以下结果记录于 2026-05-27，使用本工程默认 Qilin JAR 执行。耗时来自一次实际执行，
仅用于给出量级。

| 实验 | 预期 flows | 实际 `flowDroidLeaks` | `qilinCallEdges` | `ptaRuntimeMs` | `flowDroidRuntimeMs` |
| --- | ---: | ---: | ---: | ---: | ---: |
| Smoke | 1 | 1 | 9 | 921 | 192 |
| FlowDroid 官方 `easyConstantVarTest` | 1 | 1 | 18 | 971 | 222 |
| Juliet CWE-78 | 1 | 1 | 45353 | 11312 | 1142 |

从这三个层次可以得出：

1. Smoke 证明 bridge 的最小调用链和结果输出没有问题。
2. FlowDroid 官方例子证明当前 Qilin-backed 运行方式能够复现上游已有正例预期。
3. Juliet 证明同一管线可以应用到带有真实漏洞含义、依赖更多可达程序代码的公开项目。
4. 三个例子的 leak 数均匹配预期，但调用图规模与 PTA 耗时差异很大；因此后续评价
   Qilin 优化时，不应只检查是否找到 flow，还应比较边数、时间以及更复杂案例上的
   误报/漏报表现。

## 6. 用这些实验比较新的 Qilin 版本

当你优化 Qilin 但保持 `PTA` 与 `driver.Main.run(String[])` 接口兼容时，将新 jar
放入 `lib/qilin/`，使用 Gradle 参数替换默认 jar：

```powershell
.\gradlew.bat verifyGuidedExperimentsQilin -PqilinJar=lib/qilin/Qilin-my-optimization.jar --no-daemon --stacktrace
```

比较时建议固定：

| 应保持不变的内容 | 原因 |
| --- | --- |
| 三个 `benchmarks/config/*.properties` 文件 | 保证输入应用与 FlowDroid 设置相同 |
| source/sink definitions | 保证评价的是同一安全问题 |
| JRE 与应用依赖 | 保证可达代码范围相同 |
| `aliasing=pts` | 保证 FlowDroid 仍使用被评估 Qilin 的 points-to |

重点观察：

| 结果字段 | 如何解释 |
| --- | --- |
| `flowDroidLeaks` 与 CSV 路径 | 与预期对照，首先确认没有丢失明确正例 |
| `qilinCallEdges` | 检查可达性/调用图变化是否符合优化意图 |
| `ptaRuntimeMs` | 衡量 Qilin 阶段的成本变化 |
| `flowDroidRuntimeMs` | Qilin 结果是否改变了后续污点求解成本 |

Smoke 与官方例子适合作为快速回归；Juliet 更适合作为第一项具有漏洞含义的评估案例。
在这三项稳定后，可继续运行 `verifyGithubCorpusQilin`，把 OWASP Benchmark 和
VulnerableApp 一并加入比较。

## 7. 文件索引

| 用途 | 文件 |
| --- | --- |
| Smoke 源码 | `benchmarks/smoke/src/dev/qilinfd/bench/SimpleLeak.java`、`TaintApi.java` |
| Smoke 配置 | `benchmarks/config/smoke-qilin.properties` |
| FlowDroid 官方目标源码 | `benchmarks/flowdroid-official/soot-infoflow/test/soot/jimple/infoflow/test/ConstantTestCode.java` |
| FlowDroid 官方预期断言 | `benchmarks/flowdroid-official/soot-infoflow/test/soot/jimple/infoflow/test/junit/ConstantTests.java` |
| FlowDroid 官方 harness | `benchmarks/harness/flowdroid-official/src/dev/qilinfd/bench/flowdroid/ConstantTestHarness.java` |
| FlowDroid 官方配置 | `benchmarks/config/flowdroid-official-constant-qilin.properties` |
| Juliet 目标源码 | `benchmarks/github/juliet-test-suite/src/testcases/CWE78_OS_Command_Injection/CWE78_OS_Command_Injection__Environment_01.java` |
| Juliet harness | `benchmarks/harness/github/juliet/src/testcases/CWE78_OS_Command_Injection/CWE78EnvironmentHarness.java` |
| Juliet 配置 | `benchmarks/config/github-juliet-cwe78.properties` |
| 三实验聚合验证任务 | Gradle `verifyGuidedExperimentsQilin` |
