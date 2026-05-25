# Qilin 与 FlowDroid 接口关系

## 组件边界

本工程不使用 `qilin-generics` 中临时集成的 FlowDroid 入口。默认组合为：

| 组件 | 文件或坐标 | 职责 |
| --- | --- | --- |
| Qilin | `D:/gitdesk/Qilin/artifact/Qilin-0.9.8-SNAPSHOT.jar` | 运行指针分析，提供 PTA 查询与调用图；包含其匹配的 classic Soot `4.7.1`。 |
| FlowDroid | `de.fraunhofer.sit.sse.flowdroid:soot-infoflow:2.15.1` | 使用既有调用图与 points-to 查询执行污点分析；该发布版同样基于 Soot `4.7.1`。 |
| bridge | `qilin-FD/src/main/java/dev/qilinfd/bridge` | 在两个独立构件之间完成适配、配置与结果输出。 |

Qilin JAR 可以被替换，只要替换版本保持下面使用的 PTA/API 与同一 classic Soot 类型边界。

## Qilin 契约

原版源码 `D:/gitdesk/Qilin/qilin.core/src/qilin/core/PTA.java` 定义的关键能力为：

- `PTA.getCallGraph()`：返回 Qilin 求得的 `soot.jimple.toolkits.callgraph.CallGraph`。
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
| `QilinPointsToAnalysisAdapter` | 将 FlowDroid/Soot 发起的 points-to 查询转发给 `PTA.reachingObjects(...)`。 |
| `QilinPointsToSetAdapter` | 将 `qilin.core.sets.PointsToSet` 包装成 `soot.PointsToSet`。 |
| `ExistingCallGraphICFGFactory` | 让 FlowDroid 的 ICFG 使用已安装到 `Scene` 的 Qilin 调用图。 |

由于当前契约只使用原版 `PTA.getCallGraph()`，配置项 `callgraphMode` 的稳定值是 `qilin`。
特化或投影调用图只有在未来可替换 Qilin JAR 通过稳定接口显式暴露时，才适合加入 bridge 契约。

## 依赖选择

`Qilin-0.9.8-SNAPSHOT.jar` 编译于 Java 21，并依赖 Soot `4.7.1`。FlowDroid `2.14.1`
基于 Soot `4.6.0`，运行时会访问已在 Soot `4.7.1` 移动的类；因此本工程采用
FlowDroid `2.15.1`，其官方父 POM 声明的 Soot 版本同为 `4.7.1`。

## SootUp 状态

`D:/gitdesk/sootup/src/main/java/qilin/core/PTA.java` 使用 `sootup.core.*` 模型及
SootUp 调用图类型。FlowDroid 当前 `Infoflow` 面向 classic Soot `soot.*`，因此该 JAR
仍不能替代本工程默认 Qilin 后端，除非另行实现跨模型适配。

## 参考

- [FlowDroid 官方仓库](https://github.com/secure-software-engineering/FlowDroid)
- [FlowDroid `soot-infoflow 2.15.1` Maven Central](https://central.sonatype.com/artifact/de.fraunhofer.sit.sse.flowdroid/soot-infoflow/2.15.1)
- [SecuriBench Micro](https://github.com/too4words/securibench-micro)
