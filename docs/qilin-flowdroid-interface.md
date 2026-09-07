# Qilin 与 FlowDroid 接口关系

## 组件边界

本工程不使用 `qilin-generics` 中临时集成的 FlowDroid 入口。默认组合为：

| 组件 | 文件或坐标 | 职责 |
| --- | --- | --- |
| Qilin | `lib/qilin/Qilin-0.10.10.3-SNAPSHOT.jar`（复制自 `D:/gitdesk/qilin-generics/artifact/Qilin-0.10.10.3-SNAPSHOT.jar`） | 运行指针分析，提供 PTA 查询、特化/投影调用图以及 FSpec local/field 映射；保持 classic Soot `4.6.0`。 |
| FlowDroid | `de.fraunhofer.sit.sse.flowdroid:soot-infoflow:2.14.1` | 使用既有调用图与 qlin-FD 提供的 points-to adapter 执行污点分析。 |
| bridge | `qilin-FD/src/main/java/dev/qilinfd/bridge` | 在两个独立构件之间完成适配、配置与结果输出。 |

Qilin JAR 可以被替换，只要替换版本保持下面使用的 PTA/API 与同一 classic Soot 类型边界。
构建时可使用 `-PqilinJar=lib/qilin/<另一个兼容 JAR>` 选择被评估版本。

## Qilin 契约

原版源码 `D:/gitdesk/Qilin/qilin.core/src/qilin/core/PTA.java` 定义的关键能力为：

- `PTA.getCallGraph()`：返回 Qilin 的特化调用图。
- `PTA.getCICallGraph()`：返回投影到原程序 method/unit 的调用图。
- `PTA.reachingObjects(...)`：返回本地、字段、数组元素等查询的
  `qilin.core.sets.PointsToSet`。
- `driver.Main.run(String[])`：根据 Qilin 自身参数运行 PTA 并返回 `PTA` 对象。

原版 `PTA` 不实现 `soot.PointsToAnalysis`，也不含 FlowDroid 类。因此桥接必须在本工程完成。
替换 Qilin JAR 时，核心分析契约是 `PTA` 接口；默认启动器目前还调用
`driver.Main.run(String[])`。若后续优化版本调整了启动类，只需替换 bridge 中获取
`PTA` 对象的这一处入口，不影响 FlowDroid 适配代码。

## Bridge 实现

| 本工程类 | 作用 |
| --- | --- |
| `QilinFlowDroidBackend` | 调用 `driver.Main.run`，安装 Qilin 调用图与 points-to 适配器，再以 `UseExistingCallgraph` 运行 `Infoflow`。 |
| `flowdroid.QilinSootPointsToAnalysis` | 将 FlowDroid/Soot 的 points-to 查询转发给 Qilin，并在查询原程序 local/field 时合并 FSpec 特化变体。 |
| `flowdroid.QilinSootPointsToSet` | 在 qlin-FD 内将一个或多个 `qilin.core.sets.PointsToSet` 包装成 `soot.PointsToSet`。 |
| `flowdroid.QilinBiDirICFGFactory` | 在 qlin-FD 内基于 Qilin 已安装的调用图构建 FlowDroid ICFG。 |

当前 bridge 默认使用 `PTA.getCICallGraph()` 的原程序投影视图，并通过
`Scene.v().setCallGraph(...)` 与 `SootIntegrationMode.UseExistingCallgraph` 交给
FlowDroid。全部 FlowDroid points-to/ICFG 适配实现都位于 qlin-FD；qilin-generics
只维护生成特化 local/field 时的原始对象映射。

## 依赖选择

`Qilin-0.10.10.3-SNAPSHOT.jar` 编译于 Java 21，并保持 Soot `4.6.0`。为避免在同一
JVM 中交换不一致的 `soot.*` 对象，本工程采用已在该组合上编译验证的 FlowDroid
`2.14.1`。版本适配由 qlin-FD 负责，不要求 qlin-generics 升级 Soot。

## SootUp 状态

`D:/gitdesk/sootup/src/main/java/qilin/core/PTA.java` 使用 `sootup.core.*` 模型及
SootUp 调用图类型。FlowDroid 当前 `Infoflow` 面向 classic Soot `soot.*`，因此该 JAR
仍不能替代本工程默认 Qilin 后端，除非另行实现跨模型适配。

## 参考

- [FlowDroid 官方仓库](https://github.com/secure-software-engineering/FlowDroid)
- [FlowDroid `soot-infoflow 2.14.1` Maven Central](https://central.sonatype.com/artifact/de.fraunhofer.sit.sse.flowdroid/soot-infoflow/2.14.1)
- [SecuriBench Micro](https://github.com/too4words/securibench-micro)
