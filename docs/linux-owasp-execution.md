# Linux 上执行 Qilin/FSpec + FlowDroid + OWASP Benchmark

## 发布包

需要将下面两个 ZIP 解压到同一个空目录：

1. `qilin-fd-linux-runtime.zip`
   - `qilin-FD.jar`
   - `lib/qilin/Qilin-0.10.10.3-SNAPSHOT.jar`
   - `lib/flowdroid/soot-infoflow-2.14.1.jar`
2. `owasp-benchmark-qilinfd-v1.2.zip`
   - 已编译的 OWASP Benchmark Java v1.2 和 851 个 batch=2 harness
   - OWASP 的 130 个依赖 JAR
   - Java 8 分析库 `rt.jar`、`jce.jar`、`jsse.jar`
   - source/sink 定义、batch manifest、ground truth 和跨平台 runner

Java 字节码和 JAR 与操作系统无关，因此服务器端不需要重新编译 OWASP 源码。

## 环境要求

- Linux x86-64
- JDK 21
- Python 3.10 或更新版本
- 每个并发 worker 建议预留 24–32 GB RAM
- 建议至少预留 20 GB 磁盘保存日志和结果

检查：

```bash
java -version
python3 --version
ulimit -n 65535
```

校验发布包：

```bash
sha256sum -c SHA256SUMS-runtime
sha256sum -c SHA256SUMS-benchmark
```

检查三个运行时 JAR 能否正常装载：

```bash
java -Xmx2g -jar qilin-FD.jar print-qilin-args \
  --config benchmarks/config/owasp-benchmark-qilin.properties
```

执行约十秒的端到端 smoke test：

```bash
java -Xmx4g -jar qilin-FD.jar run \
  --config benchmarks/config/smoke-qilin.properties
grep 'projectedFlowDroidLeaks=1' results/smoke-qilin.txt
```

## 先做 SQL 容量校准

本地 10 GB heap 可以完成 SQL batch 0，但 baseline 约需 12 分钟并接近堆上限，
因此服务器应先执行：

```bash
python3 -u scripts/run_owasp_fspec.py run \
  --categories sqli \
  --batch-indices 0 \
  --modes baseline,fspec \
  --pta 1o \
  --heap 32g \
  --timeout 3600 \
  --process-timeout 7200
```

如果 JVM 仍接近堆上限，先提高到 `--heap 40g`，不要直接启动全量 worker。

## 全量并行执行

假设服务器可以安全运行 4 个 32 GB worker，在四个终端分别执行：

```bash
python3 -u scripts/run_owasp_fspec.py run --categories all --modes baseline,fspec --pta 1o --heap 32g --timeout 3600 --process-timeout 7200 --shard-count 4 --shard-index 0 2>&1 | tee worker-0.log
python3 -u scripts/run_owasp_fspec.py run --categories all --modes baseline,fspec --pta 1o --heap 32g --timeout 3600 --process-timeout 7200 --shard-count 4 --shard-index 1 2>&1 | tee worker-1.log
python3 -u scripts/run_owasp_fspec.py run --categories all --modes baseline,fspec --pta 1o --heap 32g --timeout 3600 --process-timeout 7200 --shard-count 4 --shard-index 2 2>&1 | tee worker-2.log
python3 -u scripts/run_owasp_fspec.py run --categories all --modes baseline,fspec --pta 1o --heap 32g --timeout 3600 --process-timeout 7200 --shard-count 4 --shard-index 3 2>&1 | tee worker-3.log
```

并发数按物理内存调整。除了 `-Xmx`，每个 JVM 还应预留数 GB native/GC 开销。

后台运行示例：

```bash
nohup python3 -u scripts/run_owasp_fspec.py run \
  --categories all --modes baseline,fspec --pta 1o \
  --heap 32g --timeout 3600 --process-timeout 7200 \
  --shard-count 4 --shard-index 0 \
  > worker-0.log 2>&1 &
```

监控：

```bash
tail -f worker-0.log
find results/owasp/raw -maxdepth 1 -name '*.txt' | wc -l
find results/owasp/failures -maxdepth 1 -name '*.txt' 2>/dev/null | wc -l
free -h
```

## 汇总与断点续跑

全部 worker 结束后：

```bash
python3 scripts/run_owasp_fspec.py compare --pta 1o
```

主要输出：

- `results/owasp/summary-1o.csv`
- `results/owasp/differences-1o.csv`
- `results/owasp/preliminary-report-1o.md`
- `results/owasp/raw/`：每个批次的原始结果
- `results/owasp/logs/`：完整控制台日志
- `results/owasp/failures/`：OOM、异常或硬超时标记

相同命令可以直接重新执行。已有 raw result 会被跳过，没有结果的失败批次会重试。
`--force` 会覆盖已有结果，通常不要使用。

`--timeout` 只限制 FlowDroid 阶段；`--process-timeout` 限制完整的
Qilin + FlowDroid JVM，防止 PTA 阶段无限运行。
