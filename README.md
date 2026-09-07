# Qilin–FlowDroid：FSpec 下游污点分析实验

本项目研究 **Qilin 中的泛型特化机制 FSpec 对下游污点分析的影响**。实验使用改造后的
`qilin-generics` 构件，通过关闭或开启 `-generic=FS`，比较同一个 FlowDroid 客户端的
检测结果和分析成本。

我们在固定 OWASP 语料、Qilin 构件、PTA 模式和 FlowDroid 配置下，配对比较关闭与开启
FSpec 的效果。Qilin 提供调用图和 points-to 信息，经桥接适配后供 FlowDroid 执行污点分析。
我们在双方正常完成的批次交集上，比较测试级检测结果、调用图规模、传播次数、各阶段耗时
与端到端耗时，并单独报告覆盖率和失败情况。**现有论文快照显示，在该配对子集上，测试级
检测结果保持不变，投影调用图和累计传播次数下降，累计端到端时间有所改善。**

## 1. 实验比较什么

两组都使用同一个 Qilin JAR 和同一条 Qilin–FlowDroid 桥接路径，主要实验变量是 FSpec 开关。

生成配置时，两组的 Qilin 参数分别为：

```text
baseline: -pae -pe -clinit=ONFLY -lcs -mh -se -pta=1o
fspec:    -pae -pe -clinit=ONFLY -lcs -mh -se -pta=1o -generic=FS
```

基础配置见 [owasp-benchmark-qilin.properties](benchmarks/config/owasp-benchmark-qilin.properties)。
项目还提供 `native` 后端，让 FlowDroid/Soot 自己建图，供其他验证使用；**当前 OWASP 实验中的 baseline 指关闭 FSpec 的 Qilin 配置**。

### 语料与执行单位

使用 OWASP Benchmark Java v1.2，固定 revision 为`3bcffb0f6b5a9e45f5874c8cf0deec476ba4dc7b`。从全部 2,740 个测试中选择七类source-to-sink 污点测试，共 **1,698 个测试**：

| 类别 | 脚本中的名称 | 测试数 |
|---|---|---:|
| 命令注入 | `cmdi` | 251 |
| LDAP 注入 | `ldapi` | 59 |
| 路径遍历 | `pathtraver` | 268 |
| SQL 注入 | `sqli` | 504 |
| 信任边界违规 | `trustbound` | 126 |
| XPath 注入 | `xpathi` | 35 |
| 跨站脚本 | `xss` | 455 |

共生成 **851 个 batch**；每个 batch 分别在独立 JVM 中执行 baseline 和 fspec，全量目标为 **1,702 次分析**。批次与测试的对应关系保存在`build/owasp-benchmark/batch-manifest.csv`。

## 2. src：负责把 Qilin 与 FlowDroid 接起来

[src](src) 保存 Java bridge 及其配置测试。Qilin 的 PTA/FSpec 实现在外部 Qilin 构件中，本工程负责调用它、适配分析结果、启动 FlowDroid，并输出实验数据。

主要实现位于 `src/main/java/dev/qilinfd/bridge/`：

| 源码 | 职责 |
|---|---|
| [BridgeMain.java](src/main/java/dev/qilinfd/bridge/BridgeMain.java) | 命令行入口，读取配置并选择分析后端。 |
| [AnalysisConfig.java](src/main/java/dev/qilinfd/bridge/AnalysisConfig.java) | 解析程序路径、库、入口、source/sink 和分析设置，组合 Qilin 参数。 |
| [QilinFlowDroidBackend.java](src/main/java/dev/qilinfd/bridge/QilinFlowDroidBackend.java) | 执行 Qilin PTA，安装调用图和点集 adapter，运行 FlowDroid，记录耗时、状态和污点结果。 |
| [QilinSootPointsToAnalysis.java](src/main/java/dev/qilinfd/bridge/flowdroid/QilinSootPointsToAnalysis.java) | 把 FlowDroid/Soot 的 points-to 查询转发给 Qilin；查询原 local/field 时合并对应的 FSpec 特化变体。 |
| [QilinSootPointsToSet.java](src/main/java/dev/qilinfd/bridge/flowdroid/QilinSootPointsToSet.java) | 包装 Qilin 点集，提供集合相交、类型等查询，并将特化分配位置对应回原程序。 |
| [QilinBiDirICFGFactory.java](src/main/java/dev/qilinfd/bridge/flowdroid/QilinBiDirICFGFactory.java)、[QilinJimpleBasedICFG.java](src/main/java/dev/qilinfd/bridge/flowdroid/QilinJimpleBasedICFG.java) | 基于 Qilin 已安装的调用图构建跨过程控制流图，并维护语句与所属方法的对应关系。 |
| [QilinInfoflow.java](src/main/java/dev/qilinfd/bridge/flowdroid/QilinInfoflow.java)、[SafePtsBasedAliasStrategy.java](src/main/java/dev/qilinfd/bridge/flowdroid/SafePtsBasedAliasStrategy.java) | 接入 points-to 别名策略，对 FlowDroid 无法表示的 access path 做保护处理并记录计数。 |
| [NativeFlowDroidBackend.java](src/main/java/dev/qilinfd/bridge/NativeFlowDroidBackend.java) | 提供不经过 Qilin 的 FlowDroid/Soot 运行路径。 |
| [AnalysisConfigTest.java](src/test/java/dev/qilinfd/bridge/AnalysisConfigTest.java) | 验证配置解析与参数约束。 |

一次 OWASP 分析的执行链为：

```text
batch 配置
  → BridgeMain / AnalysisConfig
  → Qilin PTA：关闭或开启 FSpec
  → 安装原程序投影调用图和 Qilin points-to adapter
  → FlowDroid：使用既有调用图进行污点分析
  → 输出状态、指标和 source-to-sink 记录
```

桥接中同时处理调用图投影和点集映射：FlowDroid 查询原程序变量时，能够看到其特化变体对应的分析结果。FlowDroid 使用 `UseExistingCallgraph`，不会在这条路径上重新用 Spark替换 Qilin 调用图。具体接口见 [Qilin 与 FlowDroid 接口说明](docs/qilin-flowdroid-interface.md)。

## 3. scripts：负责组织实验、汇总和出图

[scripts](scripts) 中的 Python 脚本把 Java bridge 组织成批量实验流程：

| 脚本 | 作用 | 主要输出 |
|---|---|---|
| [run_owasp_fspec.py](scripts/run_owasp_fspec.py) | 主 runner。支持 `prepare`、`run`、`compare`、`all`；固定语料、生成 harness、准备构件、执行两组配置，支持分片和续跑。 | `build/owasp-benchmark/` 中的输入；`results/owasp/` 中的配置、日志、raw 和初步汇总。 |
| [paper/run_owasp_downstream.py](scripts/paper/run_owasp_downstream.py) | 包装主 runner，统一传入 PTA、heap、超时和 batch 参数；通过 `--workers` 启动多个 worker。 | 主 runner 的结果，以及多 worker 模式下的 `worker-logs/`。 |
| [paper/summarize_owasp_downstream.py](scripts/paper/summarize_owasp_downstream.py) | 对双方均成功的 batch 做配对统计，生成检测指标、成本指标、差异和完成状态。 | 默认写入 `results/owasp/analysis/`，可用 `--output-dir` 指定目录。 |
| [paper/plot_owasp_downstream.py](scripts/paper/plot_owasp_downstream.py) | 读取 paired summary 的 `ALL` 行，绘制相对于 baseline 的调用图、传播次数和端到端时间。 | 默认写入 `reports/owasp-paper/data/FlowDroid.pdf` 和 `.png`。 |
| [package_linux_release.py](scripts/package_linux_release.py) | 构建并打包 Linux 运行组件、预编译 OWASP 输入、依赖和校验文件。 | `release/` 下的运行包与 benchmark 包。 |

需要区分两种“比较”：

- 主 runner 的 `compare` 生成**初步汇总**，主表分别使用两侧各自成功的样本。
- `summarize_owasp_downstream.py` 生成**论文配对汇总**，两侧使用同一个成功 batch 交集。

## 4. results：原始证据、过程记录与配对统计

**`results` 是实验输出目录，但目录中的文件并不都等同于“最终实验结果”。**
其中既有每次分析的原始结果，也有运行配置、日志、诊断记录和用于论文比较的汇总。

### 4.1 目录中的文件分别是什么

| 路径 | 含义 | 在实验中的用途 |
|---|---|---|
| `results/*.txt` | smoke、SecuriBench、FlowDroid 官方样例、Juliet 等单项验证结果；也包含早期单个 OWASP XSS 用例。 | 检查接线与回归，不代表 OWASP 批量实验的总体结果。 |
| `results/owasp/configs/` | 为每个 batch、PTA 和 mode 生成的 `.properties`。 | 记录这次分析输入了什么配置。 |
| `results/owasp/logs/` | 每次 Java 分析的完整控制台日志。 | 排查异常、超时、内存问题及分析过程。 |
| `results/owasp/raw/` | 每个 batch、每个配置侧的一份原始结果。 | 重新评分和核验统计的基础证据。 |
| `results/owasp/failures/` | 进程失败时生成的原因、命令和日志路径；没有此类失败时目录可能不存在。 | 判断哪些配置需要补跑。 |
| `results/owasp/workers/` | 已有运行留下的 worker 日志和 PID 文件。 | 执行过程记录；当前 paper wrapper 的多 worker 日志写在项目根目录 `worker-logs/`。 |
| `results/owasp/focused/` | 针对单个 OWASP 用例的诊断或回归结果，例如 XPath 00442。 | 检查特定污点流与适配行为。 |
| `results/owasp/diagnostics/` | 旧版本、旧接口或诊断阶段的结果归档。 | 追踪问题，不混入当前正式配对统计。 |
| `results/owasp/summary-1o.csv` | 普通 `compare` 的分类汇总，两侧成功范围可能不同。 | 初步查看运行情况，不直接作为配对性能或准确率比较。 |
| `results/owasp/differences-1o.csv` | 普通比较器在共同测试范围上得到的测试级报告差异。 | 初步定位新增或消失的告警。 |
| `results/owasp/preliminary-report-1o.md` | 普通比较器生成的可读报告。 | 初步结果说明。 |
| `results/owasp/analysis/` | 论文配对汇总及覆盖率、状态等文件。 | 查看配对子集的定量比较，同时核对数据来源。 |

### 4.2 论文比较主要看哪些文件

配对汇总器默认输出以下文件，也可以写入独立的本轮结果目录：

| 文件 | 含义 |
|---|---|
| `paired-summary-1o.csv` | **主要定量结果表**。每类一行，另有 `ALL` 总体行；包含两侧检测指标、耗时、调用图、传播次数和变化比例。 |
| `paired-differences-1o.csv` | 配对子集中两侧报告不一致的测试编号、真实标签和变化方向。 |
| `run-status-1o.csv` | 每个 batch 的两侧状态、失败原因、是否形成成功配对，以及部分运行指标。 |
| `coverage-summary-1o.txt` | 预期运行数、原始结果文件数、成功配对数、两侧完成数与失败情况。 |
| `remaining-failures-1o.csv` | 尚未形成成功配对的 batch，供检查或补跑。 |
| `compare-1o.log`（如存在） | 保存的普通 compare 执行记录，不是指标表。 |

### 4.3 当前本地结果与论文快照

- `results/owasp/raw/` 有 **14 份原始结果，即 7 个完整配对 batch、14 个测试**。
- `reports/owasp-paper/data/` 保存的论文快照覆盖 **641 个完整配对 batch、1,278 个测试**。
- 当前 `results/owasp/analysis/` 中的 paired summary 和 run-status 与该论文快照相同。

两侧均报告 420 个测试，测试集合不变；投影调用图均值下降 11.33%，累计传播次数下降 13.61%，累计端到端时间下降 15.19%。

## 5. 常用执行顺序

从项目根目录执行。构建和运行 bridge 使用 JDK 21，目标程序使用配置中的 Java 8 JRE；Python 需要 3.10 或以上，绘图另需 Matplotlib。Linux 环境将 `python` 换为 `python3`。

先验证基础接线：

```powershell
.\gradlew.bat test verifySmokeQilin verifySmokeFspec
```

准备固定语料、生成 batch 并构建分析输入：

```powershell
python scripts/run_owasp_fspec.py prepare --categories all --batch-size 2
```

需要构建并复制相邻 `qilin-generics` 仓库中的新 Qilin JAR 时，才给 `prepare` 增加`--refresh-qilin`。正式比较应固定所选构件及其依赖。

执行两组实验，下面是一组显式资源设置示例；实际 heap 和 worker 数按机器资源设置：

```powershell
python scripts/paper/run_owasp_downstream.py run --categories all --modes baseline,fspec --pta 1o --heap 32g --timeout 7200 --process-timeout 14400 --workers 1
```

单独从当前 raw 生成配对统计。这里使用新目录，保留已有论文快照：

```powershell
python scripts/paper/summarize_owasp_downstream.py --pta 1o --force-raw --output-dir results/owasp/analysis-current
```

检查该目录中的 `coverage-summary`、`run-status` 和 `paired-summary` 后，再显式选择本轮summary 出图：

```powershell
python scripts/paper/plot_owasp_downstream.py --summary results/owasp/analysis-current/paired-summary-1o.csv --output-dir reports/owasp-current
```

当前主 runner 会跳过已经存在的 raw；修改构件或配置后应明确管理新一轮结果，不能直接把旧文件当作新运行。普通 compare、结果完整性判断以及失败重跑后的旧结果处理仍有已确认的边界问题；`--force-raw` 只保证使用本地 raw，不会修复这些问题。
