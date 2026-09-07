# FSpec 对 FlowDroid/OWASP Benchmark Java 的初步影响报告

## 结论

这轮实验已经完成“接口正确性验证”和“跨类别 pilot”，但没有在本机完成 1,698 个
taint-style 测试的全量 baseline/FSpec 配对。

目前最稳妥的结论是：

1. 修复投影接口后，FSpec 可以作为 Qilin 的内部特化表示被 FlowDroid 无感使用；现有
   配对测试没有因为 FSpec 丢失已知污点流。
2. 七个类别的首批 14 个测试中，baseline 与 FSpec 报告的测试集合完全相同。
3. FSpec 将投影到原程序后的调用图稳定减少 9.1%–12.5%，平均约 10.0%。
4. 性能影响不是单向的：六个普通批次中 FSpec 更慢，但最重的 SQL 批次从 730.2 秒
   降到 388.7 秒。七批累计时间由 baseline 的 1,164.1 秒降到 FSpec 的
   1,073.3 秒（-7.8%），该总体收益主要由 SQL 长尾消除贡献。
5. 因而，当前数据支持“FSpec 可被下游客户端正确消费，并缩小客户端调用图”，不支持
   “FSpec 已提高 FlowDroid 精度或性能”。论文中不应使用旧的、未完整投影 points-to
   结果所得出的显著加速结论。

## 实验范围与配置

- OWASP Benchmark Java v1.2，固定 revision：
  `3bcffb0f6b5a9e45f5874c8cf0deec476ba4dc7b`
- OWASP 全集：2,740 个测试。
- 与普通 source-to-sink 污点语义相符的七类：1,698 个测试。
  - Command Injection：251
  - LDAP Injection：59
  - Path Traversal：268
  - SQL Injection：504
  - Trust Boundary Violation：126
  - XPath Injection：35
  - Cross-Site Scripting：455
- Weak Cryptography、Weak Hashing、Weak Randomness 和 Secure Cookie Flag 不属于同一
  source-to-sink 语义，没有混入本实验。
- 主 PTA：1OBJ（`-pta=1o`）。
- FlowDroid：`soot-infoflow` 2.14.1，`PtsBased` aliasing。
- 客户端调用图：`flowDroidCallGraph=projected`。
- 唯一实验变量：是否启用 `-generic=FS`。

选择 1OBJ 是为了在 CI 的大点集和 2OBJ 的更高成本之间取得中间点，并避免使用过强的
上下文区分掩盖 FSpec 自身影响。2OBJ 更适合后续在选定子集上做稳健性检查。

## 下游接口审计与修复

仅投影调用图是不够的。FlowDroid 查询的是原程序 local/field，而 FSpec 的点集位于
特化后的 local/field 上。如果只把调用图投影回原程序，FlowDroid 会得到不完整点集并
产生假阴性。

本轮完成了以下处理：

1. `PTA.getCICallGraph()` 将特化 method/unit 投影到原程序，并按调用点、caller、callee
   去重；FlowDroid bridge 默认使用该视图。
2. 克隆特化 method body 时记录“特化 local → 原 local”及反向一对多映射；特化 field
   同样记录映射。
3. FlowDroid 查询原 local/field 时，adapter 合并其全部特化变体；若查询对象本身就是
   特化对象，则保留精确查询。
4. points-to 交集按 Qilin 的 allocation-origin 语义计算，并缓存投影后的 allocation
   key，避免 FlowDroid 重复别名查询退化成昂贵的两两比较。
5. FlowDroid 无法构造合法 `AccessPath` 时，只跳过无法表示的别名路径并记录计数，不
   改变 Qilin 的点集相交判断。
6. 修复 `GenericDeduceUtil.deduceBySource` 的边界错误：当签名中的类型实参数量大于
   origin class placeholder 数量时，只处理双方共有部分，避免 `get(i)` 越界。

关键回归是 Command Injection `BenchmarkTest00006`：修复前 FSpec 为 0 条流；完整
points-to 投影后恢复为 1 条，与 baseline 一致。

## batch=2 的隔离验证

逐测试运行最干净，但每个 harness 都要重新完成一次完整 Qilin PTA。为降低固定成本，
最终脚本默认每个 harness 放两个测试。

当前 Soot 4.6.0/FlowDroid 2.14.1 组合下，七个类别的首批 batch=2 均完成且没有跨测试流。
其中 Command Injection 首批为两个阳性：

| 诊断批次 | 预期 | Baseline | FSpec | 跨测试流 |
|---|---|---|---|---:|
| `BenchmarkTest00006` + `00007` | 两个阳性 | 两个均报告 | 两个均报告 | 0 |

比较器也增加了两道保护：

- finding 归属 sink 所在的 `BenchmarkTestNNNNN`，不会因为 source 侧类名而误报；
- source 与 sink 属于不同 OWASP 测试类时，将该批标为 cross-test 并从准确率计算中排除。

batch=2 生成 851 个批次，baseline/FSpec 合计 1,702 次分析。

## 七类别首批 pilot

每类取排序后的第一个 batch（两个测试），使用同一套配置。七类均形成完整配对。

| 类别 | 预期阳性数 | Baseline 报告 | FSpec 报告 | FSpec 调用图缩减 | Baseline 总时间 | FSpec 总时间 |
|---|---:|---:|---:|---:|---:|---:|
| Command Injection | 2 | 2 | 2 | 10.1% | 78.7 s | 122.2 s |
| LDAP Injection | 2 | 1 | 1 | 9.3% | 68.3 s | 126.1 s |
| Path Traversal | 2 | 2 | 2 | 9.1% | 71.3 s | 99.0 s |
| SQL Injection | 0 | 0 | 0 | 12.5% | 730.2 s | 388.7 s |
| Trust Boundary Violation | 2 | 1 | 1 | 10.1% | 78.8 s | 117.9 s |
| XPath Injection | 0 | 0 | 0 | 9.5% | 67.7 s | 107.4 s |
| Cross-Site Scripting | 2 | 0 | 0 | 9.3% | 69.0 s | 111.9 s |

这些是按测试编号取得的性能 pilot，不是随机或分层样本，不能据此报告 OWASP 的总体
TPR/FPR。LDAP、Trust Boundary 和 XSS 中 baseline/FSpec 共同出现的漏报更可能来自
source/sink/sanitizer 建模或 FlowDroid 能力边界，而不是 FSpec，因为两侧结果完全一致。

七个完成批次中：

- baseline 与 FSpec 的 reported-test 集合没有任何差异；
- 没有 timeout、OOM 或跨测试流；
- PTA 累计时间从 1,127.4 秒降到 1,046.6 秒（-7.2%）；
- FlowDroid 累计时间从 33.7 秒降到 24.6 秒（-27.0%）；
- 总时间从 1,164.1 秒降到 1,073.3 秒（-7.8%）。

该累计结果由 SQL 长尾主导。排除 SQL 后，六个普通批次中 FSpec 总时间由 433.8 秒
上升到 684.6 秒（+57.8%）。因此不能把 -7.8% 写成普遍 speedup；更准确的结论是
FSpec 对重型批次可能显著缓解长尾，但存在稳定的特化开销。

## SQL Injection 长尾

SQL 首批为 `BenchmarkTest00008` + `BenchmarkTest00018`。

- baseline，10 GB heap：PTA 718.1 秒，FlowDroid 10.6 秒，总计 730.2 秒；
- FSpec，10 GB heap：PTA 380.2 秒，FlowDroid 7.5 秒，总计 388.7 秒；
- 两侧均正常结束、无 OOM/timeout，且均报告 0 个测试；
- FSpec 将投影调用图从 126,989 条边降到 111,068 条（-12.5%），总时间减少 46.8%。

尽管能够完成，baseline 单批约 12 分钟意味着 252 个 SQL batch 仍可能成为全量实验的
主要瓶颈。因此 Linux 服务器应先执行 SQL batch 0 做内存和吞吐校准。

## 其他诊断

- `SimpleLeak`：baseline/FSpec 均为 1 条流。
- OWASP XPath `BenchmarkTest00442`：baseline/FSpec 均为 1 条流；投影调用图从
  37,702 降到 34,110（-9.5%）。完整 points-to 投影后两侧 FlowDroid propagation
  edge 都为 3,520。
- 先前 Soot 4.7.1/FlowDroid 2.15.1 的 raw results 已归档到
  `results/owasp/diagnostics/pre-soot46-stack`，没有混入当前 CSV。
- 旧的“35 个 XPath 合并入口中 FSpec 6.3 秒完成而 baseline 超时”来自不完整的
  专用 local points-to 投影，且大批入口会引入跨测试污染，不作为论文证据。

## 构建与回归状态

- Qilin `:qilin.core:compileJava`、`:qilin.pta:compileJava` 和 `fatJar` 成功。
- qlin-FD `test`、`verifySmokeQilin`、`verifySmokeFspec` 和
  `verifyOwaspXpathFocusedPair` 成功。
- Qilin 的完整 `:qilin.pta:test` 在测试源码编译阶段失败；失败来自工作区内原有的
  未跟踪 `qilin.pta/test/qilin/test/paper` 与 `fspec` 测试引用已不存在的
  `PaperGeneric*`、`TopObjectType` 等类/符号，不是本轮生产代码的编译错误。该问题未被
  擅自修改或清理。

## 执行方式

Windows 与 Linux 共用同一个 Python runner；脚本会自动选择 `gradlew.bat` 或
`gradlew`，支持断点续跑、失败标记和 shard。

准备语料、生成 batch=2 harness，并替换最新 Qilin jar：

```text
python scripts/run_owasp_fspec.py prepare --categories all --batch-size 2 --refresh-qilin
```

实验室服务器建议每个 worker 至少预留 24–32 GB 内存。四个 worker 的示例：

```text
python scripts/run_owasp_fspec.py run --categories all --modes baseline,fspec --pta 1o --heap 24g --timeout 3600 --shard-count 4 --shard-index 0
python scripts/run_owasp_fspec.py run --categories all --modes baseline,fspec --pta 1o --heap 24g --timeout 3600 --shard-count 4 --shard-index 1
python scripts/run_owasp_fspec.py run --categories all --modes baseline,fspec --pta 1o --heap 24g --timeout 3600 --shard-count 4 --shard-index 2
python scripts/run_owasp_fspec.py run --categories all --modes baseline,fspec --pta 1o --heap 24g --timeout 3600 --shard-count 4 --shard-index 3
python scripts/run_owasp_fspec.py compare --pta 1o
```

10 GB 已能完成当前 SQL batch 0，但运行接近堆上限且吞吐较差。服务器仍应先以 24–32 GB
运行 SQL batch 0 做容量校准。`compare` 会排除 timeout、
OOM、非零退出和 cross-test 批次，不会把截断结果计作假阴性。

## 对论文的当前建议

保留 `Downstream Client Case Study`，但在全量服务器结果出来前只把它写成接口与可用性
验证，不要写成新的 RQ，也不要声称 FSpec 已提升 FlowDroid 的准确率或性能。

如果服务器全量结果继续表现为“报告集合不变、调用图缩小约 10%、重型批次长尾下降”，这个
case study 仍有价值：它证明 FSpec 可以无感接入真实下游客户端，同时揭示传统
context-insensitive points-to API 会重新合并特化精度。只是贡献点应定位为
interoperability/semantic preservation，而不是 downstream speedup。
