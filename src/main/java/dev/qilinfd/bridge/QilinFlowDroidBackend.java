package dev.qilinfd.bridge;

import driver.Main;
import qilin.core.PTA;
import qilin.core.PTAScene;
import qilin.pta.PTAConfig;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.infoflow.Infoflow;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.InfoflowConfiguration.CodeEliminationMode;
import soot.jimple.infoflow.InfoflowConfiguration.SootIntegrationMode;
import soot.jimple.infoflow.results.DataFlowResult;
import soot.jimple.infoflow.results.InfoflowPerformanceData;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.sourcesSinks.manager.DefaultSourceSinkManager;
import soot.jimple.toolkits.callgraph.CallGraph;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

public final class QilinFlowDroidBackend implements AnalysisBackend {
    @Override
    public void run(AnalysisConfig config) throws IOException {
        PTAScene.reset();
        PTAConfig.reset();

        long totalStart = System.nanoTime();
        long ptaStart = System.nanoTime();
        PTA pta = Main.run(config.qilinArguments().toArray(String[]::new));
        long ptaMillis = elapsedMillis(ptaStart);

        CallGraph callGraph = pta.getCallGraph();
        Scene.v().setCallGraph(callGraph);
        Scene.v().setPointsToAnalysis(new QilinPointsToAnalysisAdapter(pta));

        Infoflow infoflow = createInfoflow(config);
        long flowDroidStart = System.nanoTime();
        infoflow.computeInfoflow(
                config.applicationPath().toString(),
                config.optionalLibraryPath() == null ? null : config.optionalLibraryPath().toString(),
                config.entryPoint(),
                new DefaultSourceSinkManager(config.definitions("sources"), config.definitions("sinks")));
        long flowDroidMillis = elapsedMillis(flowDroidStart);
        long totalMillis = elapsedMillis(totalStart);

        writeResults(config, pta, infoflow.getResults(), ptaMillis, flowDroidMillis, totalMillis);
    }

    private static Infoflow createInfoflow(AnalysisConfig config) {
        Infoflow infoflow = new Infoflow(null, false, null);
        infoflow.setThrowExceptions(true);
        InfoflowConfiguration flowConfig = infoflow.getConfig();
        flowConfig.setSootIntegrationMode(SootIntegrationMode.UseExistingCallgraph);
        flowConfig.setAliasingAlgorithm(config.aliasingAlgorithm());
        flowConfig.setFlowSensitiveAliasing(
                config.aliasingAlgorithm() == InfoflowConfiguration.AliasingAlgorithm.FlowSensitive);
        flowConfig.setCodeEliminationMode(CodeEliminationMode.NoCodeElimination);
        flowConfig.setEnableReflection(false);
        flowConfig.setEnableExceptionTracking(false);
        flowConfig.setPathAgnosticResults(true);
        flowConfig.setLogSourcesAndSinks(true);
        flowConfig.setIgnoreFlowsInSystemPackages(false);
        flowConfig.setMaxThreadNum(config.maxThreadNum());
        if (config.dataFlowTimeoutSeconds() > 0L) {
            flowConfig.setDataFlowTimeout(config.dataFlowTimeoutSeconds());
        }
        return infoflow;
    }

    private static void writeResults(AnalysisConfig config, PTA pta, InfoflowResults results,
                                     long ptaMillis, long flowDroidMillis, long totalMillis) throws IOException {
        int leaks = results == null ? 0 : results.numConnections();
        InfoflowPerformanceData performanceData = results == null ? null : results.getPerformanceData();
        List<String> lines = new ArrayList<>();
        lines.add("backend=qilin");
        lines.add("label=" + config.value("label", "qilin-flowdroid"));
        lines.add("entryPoint=" + config.entryPoint());
        lines.add("pta=" + PTAConfig.v().getPtaConfig().ptaName);
        lines.add("flowDroidCallGraph=qilin");
        lines.add("aliasing=" + config.aliasingAlgorithm());
        lines.add("qilinCallEdges=" + pta.getCallGraph().size());
        lines.add("flowDroidLeaks=" + leaks);
        lines.add("ptaRuntimeMs=" + ptaMillis);
        lines.add("flowDroidRuntimeMs=" + flowDroidMillis);
        lines.add("totalRuntimeMs=" + totalMillis);
        lines.add("sourceDefinitions=" + config.definitions("sources").size());
        lines.add("sinkDefinitions=" + config.definitions("sinks").size());
        if (performanceData != null) {
            lines.add("flowDroidSourceCount=" + performanceData.getSourceCount());
            lines.add("flowDroidSinkCount=" + performanceData.getSinkCount());
            lines.add("flowDroidTaintPropagationSeconds=" + performanceData.getTaintPropagationSeconds());
            lines.add("flowDroidEdgePropagationCount=" + performanceData.getEdgePropagationCount());
        }
        lines.add("sourceMethod,sourceStmt,sinkMethod,sinkStmt");
        lines.addAll(flowRows(results));

        lines.forEach(System.out::println);
        Path output = config.optionalPath("output");
        if (output != null) {
            if (output.getParent() != null) {
                Files.createDirectories(output.getParent());
            }
            Files.write(output, lines, StandardCharsets.UTF_8);
        }
    }

    private static List<String> flowRows(InfoflowResults results) {
        if (results == null || results.isEmpty()) {
            return List.of();
        }
        Map<Unit, SootMethod> owners = buildOwnerMap();
        return results.getResultSet().stream()
                .sorted(Comparator.comparing(DataFlowResult::toString))
                .map(result -> {
                    Unit source = result.getSource().getStmt();
                    Unit sink = result.getSink().getStmt();
                    return csv(signature(owners.get(source))) + "," + csv(statement(source)) + ","
                            + csv(signature(owners.get(sink))) + "," + csv(statement(sink));
                })
                .toList();
    }

    private static Map<Unit, SootMethod> buildOwnerMap() {
        Map<Unit, SootMethod> owners = new IdentityHashMap<>();
        for (SootClass sootClass : Scene.v().getClasses()) {
            for (SootMethod method : sootClass.getMethods()) {
                if (method.isConcrete() && method.hasActiveBody()) {
                    for (Unit unit : method.getActiveBody().getUnits()) {
                        owners.put(unit, method);
                    }
                }
            }
        }
        return owners;
    }

    private static String signature(SootMethod method) {
        return method == null ? "<unknown>" : method.getSignature();
    }

    private static String statement(Unit unit) {
        int line = unit.getJavaSourceStartLineNumber();
        return line > 0 ? unit + " @line " + line : unit.toString();
    }

    private static long elapsedMillis(long start) {
        return Math.round((System.nanoTime() - start) / 1_000_000.0);
    }

    private static String csv(String text) {
        return "\"" + text.replace("\"", "\"\"") + "\"";
    }
}
