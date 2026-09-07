# OWASP / Qilin / FlowDroid 实验逻辑审查

审查日期：2026-09-06。依据当前源码、配置、构件、原始结果和已保存的论文汇总。

本次没有重新运行完整 PTA / FlowDroid 实验，没有修改实验程序和既有结果。核验包括：语料 revision、manifest 与 ground truth 的一致性、已有配置对、Qilin JAR 一致性、本地原始结果重新汇总，以及在临时目录中复现统计边界问题。

## 1. 判断

**实验的核心设计成立：固定下游 FlowDroid 客户端，比较 Qilin 的 FSpec 开关对下游分析的影响。但当前不能认定整套脚本和结果表述完全没有问题。**

成立的部分：两组使用同一输入和同一桥接路径，FSpec 通过调用图和 points-to 查询影响 FlowDroid；论文汇总器采用双方均成功的批次交集；准确率按 OWASP 测试编号和 ground truth 计算。

需要修正的部分：普通 `compare` 没有统一两侧计分样本；论文汇总可能回退到历史数据；结果完整性校验不严格；失败重跑可能复用旧结果；跨资源设置续跑缺少实验身份记录。现有论文汇总支持的也不是检测准确率提升或 FlowDroid 阶段普遍加速。

## 2. 两组究竟比较什么

| 项目 | baseline | fspec |
|---|---|---|
| 后端 | `backend=qilin` | `backend=qilin` |
| Qilin 构件 | 同一个 `Qilin-0.10.10.3-SNAPSHOT.jar` | 同左 |
| 主 PTA | `-pta=1o` | `-pta=1o` |
| FSpec | 不指定 `-generic` | `-generic=FS` |
| 其他 Qilin 参数 | `-pae -pe -clinit=ONFLY -lcs -mh -se` | 同左 |
| FlowDroid | 2.14.1 | 同左 |
| 调用图 | 投影回原程序的调用图 | 同左 |
| 别名策略 | `PtsBased`，通过项目内的 guarded strategy 使用 Qilin 点集 | 同左 |
| source / sink | 同一套 source，同类别同一套 sink | 同左 |
| FlowDroid 线程 | 1 | 1 |

实现入口：`scripts/run_owasp_fspec.py:350` 的 `write_run_config()`。实际检查过的七组本地配置，仅 `label`、`output` 和 `qilinFlags` 不同；`qilinFlags` 的差异正是追加 `-generic=FS`。

因此，准确名称是：**同一 Qilin 实现中关闭 / 开启 FSpec 的配对消融实验**。它可以回答“FSpec 带来什么变化”。目前没有分别加载原版 Qilin 与 qilin-generics 两个独立 JAR，也没有证明关闭 FSpec 的构件与某个原版 Qilin revision 完全等价。

项目还提供 `NativeFlowDroidBackend`，由 FlowDroid / Soot 自己建图，但当前 OWASP 批量 runner 不使用这条路径。不要把这里的 baseline 写成 native FlowDroid / Spark。

检查实际使用的 Qilin JAR 字节码，`FS` 会打开 `handleGenericMethodOnly` 与 `handleGenericFilterType`，二者初始值均为 `false`。每个配置启动独立 JVM，避免前一组的静态开关影响后一组。

## 3. 整个项目如何协作

### 3.1 工程入口与依赖

- `BridgeMain` 读取 properties，选择 Qilin 或 native 后端。
- `AnalysisConfig` 解析被分析应用、库、入口、目标 JRE、source / sink 和分析选项，组合 Qilin 命令行。
- `build.gradle` 用 Java 21 构建 bridge，选择 FlowDroid 2.14.1，Qilin JAR 提供 classic Soot；OWASP 分析输入按 Java 8 编译。
- `benchmarks/config` 保存实验配置；`benchmarks/definitions` 保存 source / sink；`benchmarks/harness` 保存少量手写回归入口。
- `build/owasp-benchmark` 保存批次清单、分析 JAR 和库依赖；`results/owasp` 保存配置、日志、原始结果与汇总；`reports` 保存说明和论文快照；`release` 保存部署包及补跑包。

### 3.2 一次分析的调用链

```text
某个 batch 的 properties
  -> BridgeMain -> AnalysisConfig
  -> QilinFlowDroidBackend
  -> driver.Main.run(...)：执行 Qilin PTA
  -> 取调用图，安装 Qilin points-to adapter
  -> QilinInfoflow.computeInfoflow(...)：执行 FlowDroid
  -> 将结果对应回原程序方法 / 语句并输出 raw 文件
```

关键接线在 `QilinFlowDroidBackend.java:49`：

1. `Main.run(...)` 得到 `PTA`。
2. `pta.getCICallGraph()` 得到原程序投影视图，并通过 `Scene.v().setCallGraph(...)` 安装。
3. `Scene.v().setPointsToAnalysis(new QilinSootPointsToAnalysis(pta))` 安装 points-to 查询。
4. FlowDroid 设为 `UseExistingCallgraph`，不会在这条路线重新用 Spark 建图。
5. `QilinBiDirICFGFactory` 基于已安装调用图建立 FlowDroid ICFG；source / sink 交给 `DefaultSourceSinkManager`。

所以当前确实是在评价 **Qilin 分析结果对 FlowDroid 的下游影响**，并非先运行 Qilin 后再运行一个不使用它的 FlowDroid。

### 3.3 FSpec 结果为什么要做两种适配

FSpec 可能生成特化方法、局部变量、字段和分配语句。FlowDroid 当前处理原程序视图，因此必须同时适配：

- 调用图：把特化方法和调用点映射回原程序。
- 点集：查询原 local / field 时，合并原对象及其全部特化变体的 points-to 集合；查询特化对象自身时保留直接查询。

`QilinSootPointsToAnalysis.java:171` 实现 local / field 变体选择；`QilinSootPointsToSet.java:83` 把分配位置对应到原始分配表达式，用于别名交集判断。

这避免了“调用图已回到原程序，而查询仍然只看到未特化变量空点集”的接口错误。但合并和投影会丢掉部分特化区分。因此，**Qilin 内部更精确不必然转化为 FlowDroid 测试级标签变化**。完整的接口语义正确性仍需针对性回归验证，单凭报出相同测试集合不能证明所有点集 / 污点流都等价。

## 4. scripts 中每个脚本的职责

| 文件 | 实际职责 | 容易误解的地方 |
|---|---|---|
| `scripts/run_owasp_fspec.py` | 固定语料、生成 harness、准备构件、运行配置、保存 raw、初步比较 | `compare` 中两侧主表使用各自成功样本集 |
| `scripts/paper/run_owasp_downstream.py` | 包装主 runner，统一资源参数，启动多个 worker | `compare` / `all` 最后仍调用普通 `compare`，不会自动运行论文配对汇总器 |
| `scripts/paper/summarize_owasp_downstream.py` | 基于双方成功批次生成 paired summary、差异、状态和失败清单 | raw 不足时默认可能复制历史论文数据；当前数据复核应显式 `--force-raw` |
| `scripts/paper/plot_owasp_downstream.py` | 用 `ALL` 行绘制调用图、传播次数、端到端时间相对 baseline 的图 | 图中的 Runtime 是 `totalRuntimeMs`，不是 `flowDroidRuntimeMs` |
| `scripts/package_linux_release.py` | 构建并打包 Linux bridge / Qilin / FlowDroid 和预编译 OWASP 输入 | 是部署工具，不执行准确率统计；当前打包清单未包含 `scripts/paper` |
| `scripts/paper/generate_owasp_rerun_package.py` | 根据状态表生成失败侧精确补跑任务、worker 和进度脚本 | 默认读取论文快照；加大资源后只重跑失败侧会影响性能比较口径 |

主 runner 默认资源是 `16g / 3600s / 7200s`，paper wrapper 默认是 `32g / 7200s / 14400s`，补跑生成器默认是 `96g / 14400s / 28800s`。三者依次为 JVM 最大堆、FlowDroid 数据流超时、整个 Java 进程超时。它们不是同一套默认预算。

## 5. 当前实验方法，按执行顺序描述

### 5.1 固定语料与评测范围

OWASP Benchmark Java v1.2 固定 revision 为：

```text
3bcffb0f6b5a9e45f5874c8cf0deec476ba4dc7b
```

本次核验本地 checkout 正好处于该 revision，工作区干净。官方 CSV 共 2,740 个测试，选择七个与 source-to-sink 污点分析相符的类别，共 1,698 个测试：

| 类别 | 测试数 | batch 数 |
|---|---:|---:|
| Command Injection | 251 | 126 |
| LDAP Injection | 59 | 30 |
| Path Traversal | 268 | 134 |
| SQL Injection | 504 | 252 |
| Trust Boundary Violation | 126 | 63 |
| XPath Injection | 35 | 18 |
| XSS | 455 | 228 |
| 合计 | 1,698 | 851 |

其余四类没有混入此实验。应称“OWASP 的七类污点测试”，不应称“OWASP 全集”。

### 5.2 生成分析入口

每个类别内按测试编号排序，每两个测试组成一个 batch，尾部不足两个的单独成批。实际为 847 个双测试 batch 和 4 个单测试 batch。

每个 batch 生成一个 `main()`，逐个创建测试 servlet，调用 `doPost(null, null)`。这是供静态分析使用的简化入口，没有运行 Web 服务器，也没有真实发送 HTTP 请求。不同 batch 使用同一个完整 OWASP 分析 JAR，通过不同 `mainClass` 限定入口；不是为每个 batch 删减出一个独立程序。

`batch-manifest.csv` 记录 batch 与测试编号对应关系。batch key 包含类别、编号和测试列表 hash。本次确认 manifest 中 1,698 个唯一测试恰好覆盖所选 ground truth，并与论文 `run-status` 中的 batch key 和测试列表一致。

### 5.3 对每个 batch 执行两个配置

两侧共享 app JAR、库、目标 JRE、harness、sources、类别 sinks、PTA 模式和下游设置，仅开关 FSpec。每侧启动一个独立 Java 进程，故全量目标是 851 × 2 = 1,702 次分析。

多 worker 根据 `batch.index % shard_count` 分片，在每个类别中覆盖不同批次。每个 worker 内按 batch 顺序运行 baseline / fspec。主脚本默认已有 raw 文件就跳过；失败写入 `failures`，然后继续下一项。外层 worker 正常退出只表示任务循环走完，不表示全部分析成功。

输出包括：

- 配置与完整运行日志。
- specialized / projected 调用图边数。
- PTA、FlowDroid、bridge 内端到端耗时。
- FlowDroid propagation count、终止状态和无法表示的 alias access path 计数。
- 投影回原方法 / 语句后的 source-to-sink 记录。

`totalRuntimeMs` 的范围是 bridge 内计时，包括 PTA、适配和 FlowDroid 阶段，不包括 JVM 启动以及最后结果文件写入；多批次求和也不是服务器并行实验的真实历时。

### 5.4 由污点记录转成测试级判定

`parse_result()` 把 finding 归给 sink 所属的 `BenchmarkTestNNNNN`，按测试编号去重。同一个测试报出多条 source-to-sink 流，仍只算一个“报告为有漏洞”的测试。

若一条记录能够同时识别 source 所属测试和 sink 所属测试，且二者不同，则增加 cross-test 计数。存在这种可识别跨测试流的 batch 从准确率比较中排除。

这是一道污染检测，不是 batch 完全独立的证明：共享 helper 内的 source / sink 或无法归属的记录，不一定被这条基于编号的检测捕获。需要特别说明的是，sink 未包含可识别测试编号时，当前解析器也不会把它计入某个 OWASP 测试。

### 5.5 在双方成功批次交集上评分

论文汇总的预期规则是：baseline 和 fspec 都正常完成、无 FlowDroid 超时 / OOM / 非正常终止、无可识别 cross-test 流，该 batch 才参与两侧准确率及成本比较。

对这同一个测试集合，分别用 ground truth 计算：

```text
TP = 有漏洞且报告；FN = 有漏洞但未报告
FP = 无漏洞但报告；TN = 无漏洞且未报告
TPR = TP / (TP + FN)
FPR = FP / (FP + TN)
score = TPR - FPR
```

代码中的 `score` 不是通常的 `(TP + TN) / 全部测试数`。`TPR` 相当于 recall；脚本未单独输出 precision。`ALL` 行在测试层合并计数，属于 micro 口径，不是先算各类别得分再等权平均。

两侧测试报告集合的差集进一步分为：移除 FP、丢失 TP、新增 TP、新增 FP。判断“准确率提升”必须查看这些标签变化和 ground truth，不能只看图变小、路径数变少或时间下降。

## 6. 已确认的问题及影响

### 6.1 普通 compare 不是配对主表

位置：`run_owasp_fspec.py:538`、`:550`；paper wrapper 的 `:150`。

普通 `compare()` 分别用各 mode 成功批次生成 `summary-1o.csv`。只有后面的 differences 使用双方共同测试。若一侧成功更多，主表两行实际覆盖的测试不同；时间、传播次数等还会汇总 attempted raw，包括部分未完成结果。

本次临时构造一侧成功两个 batch、另一侧成功一个 batch，主表确实输出 baseline `tests=2`、fspec `tests=1`。因此不能直接比较这份表中的 TP / FP / TPR / 总时间来评价提升。

论文定量比较应显式运行 `summarize_owasp_downstream.py`。`run_owasp_downstream.py all` 的名称并不意味着已经完成这一步。

### 6.2 默认论文汇总可能使用历史数据

位置：`summarize_owasp_downstream.py:140`。

当 raw 文件数少于预期一半，且论文目录有汇总时，程序直接把论文文件复制到输出目录后返回。绘图也有找不到当前 summary 时回退到论文目录的行为。

本地 `results/owasp/raw` 实际有 14 份文件，但 `results/owasp/analysis` 中的 summary / status 与论文目录快照逐字节相同，显示的是 641 对。该数值不能解释为本地这 14 份 raw 的新汇总。

从当前原始结果核验时必须 `--force-raw`；历史快照应保留来源说明，并与新实验输出目录区分。

### 6.3 空 / 截断文件可能被当成成功

位置：`summarize_owasp_downstream.py:80`、`run_owasp_fspec.py:538`，以及补跑生成器中的 `valid()`。

完整性判断将缺失的超时 / OOM 字段视为 false，将缺失终止状态视为 0。对空文件，`parse_result()` 只补出 `crossTestFlowCount=0`，`is_completed()` 仍返回 true。本次已复现。

这样会把未完成分析误当成“成功且无告警”，制造 FN / TN，也可能让补跑程序错误跳过。需要求必要元数据、预期配置身份、明确终止状态和 flow 表头存在，并采用完成后原子写入结果的方式。该缺陷已证实存在，但没有证据表明当前 14 份真实 raw 是空 / 截断文件。

### 6.4 强制重跑失败会残留旧成功结果

位置：`run_owasp_fspec.py:396`、`:403`；`summarize_owasp_downstream.py:153`。

`--force` 不会先归档旧 raw。新进程失败只写 failure 文件，旧 raw 仍在；汇总器优先读取 raw，不会因为同时存在 failure 文件而否定它。

本次在临时目录模拟旧成功 raw 和一次失败强制重跑，得到 raw / failure 同时存在，论文汇总仍判为 completed / paired。

应把每次尝试分开记录，或归档旧结果、成功后再提交新结果，明确失败 marker 与 raw 的先后关系。

### 6.5 续跑和补跑缺少完整实验身份

位置：`run_owasp_fspec.py:85`、`:396`；补跑默认参数见 `generate_owasp_rerun_package.py:39`。

raw 文件名识别 batch / PTA / mode，却不识别 Qilin 与 bridge 构件 hash、source / sink hash、heap、超时、机器和重复次数。修改这些设置后，不加 force 会复用旧结果，加 force 又可能覆盖旧实验。

补跑包会保留已成功侧，用更大堆或更长超时重试失败侧。这可以扩大成功覆盖，但不能自动构成相同预算的性能对照。若性能结论包含这些补跑结果，应让该配对两侧在相同环境与预算下重新测量，或按资源设置分层报告。

本次确认本地 `lib/qilin`、`build/bridge-runtime/lib` 和 `release/linux-runtime/lib/qilin` 的 Qilin JAR hash 相同。但仅此不能证明服务器历史各次运行使用同一构件 / 环境。

### 6.6 下游建模与结论范围

这些不是“两侧配置不公平”，但应限定实验解释：

- servlet 入口使用 null request / response，没有完整容器和库对象模型；无显式 OWASP sanitizer / taint wrapper 安装。参数 source、容器元素和库传播覆盖均会影响检测率。
- FlowDroid 禁用 code elimination、反射跟踪和异常污点跟踪；`PtsBased` 是 flow-insensitive aliasing，但污点求解器本身仍可具有 flow / context sensitivity，不能把整个 FlowDroid 称作流不敏感。
- 项目 `QilinInfoflow` 使用 `SafePtsBasedAliasStrategy`，跳过无法构造的 access path。两侧都使用它，因此开关比较仍一致，但不是完全未定制的 FlowDroid；也不能据此证明不存在因 access path 表示限制而漏失的流。
- 保存的 641 对快照中，两侧 rejected alias access path 计数分别约 1,083 万和 892 万。这是被跳过构造的次数，不是独立漏洞数；应作为客户端兼容性限制分析。
- 按双方成功筛选是公平配对的必要条件，但仍有成功样本选择偏差。不能外推为全部 1,698 个测试，更不能外推为生产应用总体表现。
- “报告测试集合相同”不等于每条 source-to-sink 流都相同，也不等于所有真实漏洞均被发现。论文中的 `every taint finding` 应限定为 test-level reported findings，除非另做逐流配对。

## 7. 当前数据真正支持什么

### 7.1 当前机器可从 raw 重算的结果

本次使用 `--force-raw` 在临时输出目录重新汇总，得到 7 对 / 14 个测试。两侧均为 TP=6、FN=6、FP=0、TN=2，报告测试集合无变化。这是每类第一批的 pilot，并非随机抽样。

### 7.2 已保存的论文快照

来源：`reports/owasp-paper/data/paired-summary-1o.csv` 和 `run-status-1o.csv`。本次核对了清单一致性，并从 status 独立复算配对数、总时间和 projected CG 均值；本机缺少其余原始日志，因此未逐条重算该快照全部污点记录或核验服务器执行环境。

- 总计 851 个 batch；641 个完整配对，占 75.32%。
- 配对覆盖 1,278 个测试，约占所选 1,698 个测试的 75.27%。
- baseline 成功 644 侧，fspec 成功 660 侧；尚有 398 个未成功侧，对应 210 个未配对 batch。
- 配对两侧报告集合相同：420 个测试被报告，TP=255、FP=165、FN=397、TN=461。
- TPR=39.11%，FPR=26.36%，TPR−FPR=12.75 个百分点，两侧没有准确率差异。

| 配对汇总指标 | baseline | fspec | FSpec 变化 |
|---|---:|---:|---:|
| 原程序投影 CG 边数，批次均值 | 66,546 | 59,005 | −11.33% |
| FlowDroid edge propagation count，累计 | 127,271,234 | 109,953,092 | −13.61% |
| Qilin PTA 阶段时间，累计 | 54.80 h | 32.13 h | −41.37% |
| FlowDroid 阶段时间，累计 | 1.17 h | 15.40 h | **+1211.34%** |
| bridge 内端到端时间，累计 | 56.17 h | 47.63 h | −15.19% |
| 单 batch 端到端时间，中位数 | 49.34 s | 90.19 s | 上升 |

因此，收益主要来自 PTA 阶段，不能把端到端收益写成 FlowDroid 阶段加速。传播次数减少也不保证运行时间减少，现有数据已直接展示这种差异；没有 profiling 不能断言其具体耗时原因。

按类别看，SQL 的累计总时间下降 26.43%，其余六类都上升，约 59%–96%。剔除 SQL 后，总时间由约 5.97 h 上升到 10.71 h，约 +79.23%。整体累计收益由 SQL 主导，不能解释为多数测试变快。

## 8. 可直接用于描述当前实验的表述

> 我们以 OWASP Benchmark Java v1.2 的七类 source-to-sink 测试作为下游评测语料，将同类别测试按编号排序并以两个测试为一个批次生成 Java 分析入口。在相同 Qilin 构件、1-object-sensitive PTA、输入依赖、source / sink 定义和 FlowDroid 配置下，分别关闭和开启 FSpec。Qilin 先生成调用图和 points-to 结果，bridge 将特化结果适配到原程序视图，再交由 FlowDroid 进行污点分析。我们仅在双方均正常完成且未检测到跨测试污点流的批次交集上，对照 OWASP ground truth 计算测试级 TP、FP、FN、TN、TPR 和 FPR，同时比较投影调用图规模、传播次数、PTA 时间、FlowDroid 时间和端到端时间，并单独报告未完成批次与覆盖率。
>
> 已保存的论文快照覆盖 641 个完整配对批次、1,278 个测试。两侧报告的测试集合相同，未观察到测试级检测准确率提升；FSpec 减少了投影调用图和累计传播次数，并降低了配对子集的累计端到端时间。该时间收益由 SQL 类别及 Qilin PTA 阶段主导，FlowDroid 阶段累计时间反而增加。上述观察限定于已完成配对子集和当前桥接 / 建模设置，不能作为全量 OWASP 精度提升或 FlowDroid 普遍加速的证据。

## 9. 后续使用现有脚本的正确顺序

1. `prepare` 固定 revision，生成 batch manifest，编译分析输入并固定构件。
2. `run` 运行 baseline / fspec，保留配置、日志和每次运行资源信息。
3. 单独调用论文汇总器，明确从当前 raw 汇总，并使用新输出目录。
4. 检查 coverage / run-status / remaining-failures，再解释 paired summary。
5. 对需要补跑的项目保留尝试历史；性能测量保证每对两侧预算一致。
6. 绘图时显式指定本轮 paired summary，避免读到旧数据。

从当前本地 raw 生成独立审查汇总的命令示例：

```powershell
python scripts/paper/summarize_owasp_downstream.py --pta 1o --force-raw --output-dir results/owasp/audit-current-raw
```

此命令只修正“数据来源”和“配对样本集”的使用方式，不会修复前述空文件 / 旧结果有效性缺陷。正式新实验应先修复这些已复现的问题，再生成用于论文的最终结果。
