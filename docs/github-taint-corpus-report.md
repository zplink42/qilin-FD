# GitHub Java 项目污点分析实验

本实验将三个规模明显大于最小样例的公开 Java 项目作为本地子模块，先从其源码中选出
明确的 source/sink 路径，再通过本工程的 Qilin-backed FlowDroid 后端验证。分析目标仍是
普通 Java 字节码；对于 Web 框架入口，只补充静态可达的 `main` harness，不运行服务器或
Android 生命周期。

## 项目与选定路径

| 项目 | 本地目录 | 选定漏洞 | 源码 source | 源码 sink |
| --- | --- | --- | --- | --- |
| [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) | `benchmarks/github/benchmark-java` | `BenchmarkTest00380`，官方 oracle 标记 `xss,true` | `request.getParameter("BenchmarkTest00380")` | `response.getWriter().print(bar)` |
| [Juliet Test Suite](https://github.com/find-sec-bugs/juliet-test-suite) | `benchmarks/github/juliet-test-suite` | `CWE78_OS_Command_Injection__Environment_01.bad()` | `System.getenv("ADD")` | `Runtime.getRuntime().exec(osCommand + data)` |
| [SasanLabs VulnerableApp](https://github.com/SasanLabs/VulnerableApp) | `benchmarks/github/vulnerable-app` | `CommandInjection` Level 1 | `@RequestParam(IP_ADDRESS) String ipAddress` | 两个操作系统分支中的 `new ProcessBuilder(...)` |

## 源码取证

### OWASP BenchmarkJava

- `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00380.java:43` 读取请求参数。
- 同一文件第 68 行将派生值写入 `PrintWriter.print`。
- `expectedresults-1.2.csv:381` 将该测试标记为 `BenchmarkTest00380,xss,true,79`。
- `BenchmarkTest00380Harness` 仅调用 servlet 方法，使该真实 endpoint 从普通 Java
  `main` 可达；source 与 sink 均仍来自原项目类。

### Juliet Test Suite

- `CWE78_OS_Command_Injection__Environment_01.java:31` 从 `System.getenv("ADD")` 获取数据。
- 同一文件第 46 行在 `bad()` 路径执行 `Runtime.getRuntime().exec(...)`。
- `CWE78EnvironmentHarness` 直接调用 `bad()`，避免反射型测试启动器影响 Qilin 调用图。

### VulnerableApp

- `CommandInjection.java:69` 声明 Spring 外部输入 `@RequestParam(IP_ADDRESS) String ipAddress`。
- 同一文件第 47 和 52 行把该值拼入两个 `ProcessBuilder` 命令数组。
- 普通 Java 分析没有 Spring 参数绑定生命周期，因此
  `CommandInjectionHarness` 用 `System.getenv("ipaddress")` 作为外部输入模型，再调用
  原项目 `getVulnerablePayloadLevel1`。该 harness 只建模框架入口；两个 sink 均位于原源码。

## 定义与任务

对应 source/sink 定义位于：

- `benchmarks/definitions/github-owasp-benchmark-xss-{sources,sinks}.txt`
- `benchmarks/definitions/github-juliet-cwe78-{sources,sinks}.txt`
- `benchmarks/definitions/github-vulnerable-app-command-{sources,sinks}.txt`

分析配置位于 `benchmarks/config/github-*.properties`。运行全部回归验证：

```powershell
gradle verifyGithubCorpusQilin
```

## 已观测结果

使用独立 Qilin 与 FlowDroid 组合的顶层 `aliasing=pts` 和
`qilinFlags=... -pta=insens ...` 配置运行后：

| 配置标签 | Qilin/FlowDroid 检出的污点流数量 | 含义 |
| --- | ---: | --- |
| `github-owasp-benchmark-xss-00380` | 1 | 请求参数到 XSS 输出 |
| `github-juliet-cwe78-environment-01` | 1 | 环境变量到命令执行 |
| `github-vulnerable-app-command-level1` | 2 | 外部请求参数模型到 Windows/Unix 两个命令构造分支 |

结果文件生成于 `results/github-*.txt`，包含带源码行号的 source/sink statement、
调用图边数与分析耗时。
VulnerableApp 的两条结果来自同一漏洞的两个平台分支，并非两个不同的请求入口。

## 当前限制

- FlowDroid `PtsBased` 是 flow-insensitive alias 策略；本工程在 Qilin 与 native
  两条路径中均显式关闭独立的 flow-sensitive aliasing 开关，以使日志和配置语义一致。
- VulnerableApp 分析过程中，Soot 对 Java 8 JRE 中一个 AWT 方法输出一次类型提升诊断，
  但分析正常完成且预期的两条命令注入路径被检出；它未改变本次验证结论。
