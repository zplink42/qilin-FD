package dev.qilinfd.bridge;

import driver.Main;
import dev.qilinfd.bridge.flowdroid.QilinBiDirICFGFactory;
import dev.qilinfd.bridge.flowdroid.QilinInfoflow;
import dev.qilinfd.bridge.flowdroid.QilinSootPointsToAnalysis;
import dev.qilinfd.bridge.flowdroid.SafePtsBasedAliasStrategy;
import qilin.core.PTA;
import qilin.core.PTAScene;
import qilin.generic.tag.GenericTagUtil;
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
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public final class QilinFlowDroidBackend implements AnalysisBackend {
    private record NormalizedFlow(String sourceMethod, String sourceStmt, String sinkMethod, String sinkStmt) {
        String toCsvRow() {
            return csv(sourceMethod) + "," + csv(sourceStmt) + ","
                    + csv(sinkMethod) + "," + csv(sinkStmt);
        }
    }

    @Override
    public void run(AnalysisConfig config) throws IOException {
        PTAScene.reset();
        PTAConfig.reset();

        long totalStart = System.nanoTime();
        long ptaStart = System.nanoTime();
        PTA pta = Main.run(config.qilinArguments().toArray(String[]::new));
        long ptaMillis = elapsedMillis(ptaStart);

        CallGraph specializedCallGraph = pta.getCallGraph();
        CallGraph projectedCallGraph = pta.getCICallGraph();
        String callGraphMode = config.value("flowDroidCallGraph", "projected").toLowerCase();
        CallGraph flowDroidCallGraph = switch (callGraphMode) {
            case "specialized" -> specializedCallGraph;
            case "projected" -> projectedCallGraph;
            default -> throw new IllegalArgumentException(
                    "flowDroidCallGraph must be 'specialized' or 'projected', found: "
                            + callGraphMode);
        };
        Scene.v().setCallGraph(flowDroidCallGraph);
        Scene.v().setPointsToAnalysis(new QilinSootPointsToAnalysis(pta));

        String requestedEntryPoint = config.entryPoint();
        String flowDroidEntryPoint = callGraphMode.equals("projected")
                ? requestedEntryPoint
                : resolveSpecializedEntryPoint(requestedEntryPoint, flowDroidCallGraph);

        Infoflow infoflow = createInfoflow(config);
        long flowDroidStart = System.nanoTime();
        infoflow.computeInfoflow(
                config.applicationPath().toString(),
                config.optionalLibraryPath() == null ? null : config.optionalLibraryPath().toString(),
                flowDroidEntryPoint,
                new DefaultSourceSinkManager(config.definitions("sources"), config.definitions("sinks")));
        long flowDroidMillis = elapsedMillis(flowDroidStart);
        long totalMillis = elapsedMillis(totalStart);

        writeResults(config, pta, requestedEntryPoint, flowDroidEntryPoint, callGraphMode,
                specializedCallGraph, projectedCallGraph, infoflow.getResults(),
                ptaMillis, flowDroidMillis, totalMillis);
    }

    private static Infoflow createInfoflow(AnalysisConfig config) {
        Infoflow infoflow = new QilinInfoflow(null, false, new QilinBiDirICFGFactory());
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

    private static void writeResults(AnalysisConfig config, PTA pta, String requestedEntryPoint,
                                     String flowDroidEntryPoint, String callGraphMode,
                                     CallGraph specializedCallGraph,
                                     CallGraph projectedCallGraph, InfoflowResults results,
                                     long ptaMillis, long flowDroidMillis, long totalMillis) throws IOException {
        int rawLeaks = results == null ? 0 : results.numConnections();
        int rawResultSize = results == null ? 0 : results.size();
        Set<NormalizedFlow> projectedFlows = normalizeResults(results);
        InfoflowPerformanceData performanceData = results == null ? null : results.getPerformanceData();
        List<String> lines = new ArrayList<>();
        lines.add("backend=qilin");
        lines.add("label=" + config.value("label", "qilin-flowdroid"));
        lines.add("entryPoint=" + requestedEntryPoint);
        lines.add("flowDroidEntryPoint=" + flowDroidEntryPoint);
        lines.add("pta=" + PTAConfig.v().getPtaConfig().ptaName);
        lines.add("genericMode=" + genericMode(config.qilinArguments()));
        lines.add("flowDroidCallGraph=" + callGraphMode);
        lines.add("aliasing=" + config.aliasingAlgorithm());
        lines.add("qilinCallEdgesSpecialized=" + specializedCallGraph.size());
        lines.add("qilinCallEdgesProjected=" + projectedCallGraph.size());
        lines.add("rawFlowDroidLeaks=" + rawLeaks);
        lines.add("rawFlowDroidResultSize=" + rawResultSize);
        lines.add("projectedFlowDroidLeaks=" + projectedFlows.size());
        lines.add("flowDroidTerminationState="
                + (results == null ? "unavailable" : results.getTerminationState()));
        lines.add("flowDroidTimedOut="
                + (results != null && results.wasAbortedTimeout()));
        lines.add("flowDroidOutOfMemory="
                + (results != null && results.wasTerminatedOutOfMemory()));
        lines.add("flowDroidRejectedAliasAccessPaths="
                + SafePtsBasedAliasStrategy.rejectedAccessPathCount());
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
        projectedFlows.stream().map(NormalizedFlow::toCsvRow).forEach(lines::add);

        lines.forEach(System.out::println);
        Path output = config.optionalPath("output");
        if (output != null) {
            if (output.getParent() != null) {
                Files.createDirectories(output.getParent());
            }
            Files.write(output, lines, StandardCharsets.UTF_8);
        }
    }

    private static Set<NormalizedFlow> normalizeResults(InfoflowResults results) {
        Set<NormalizedFlow> flows = new TreeSet<>(Comparator
                .comparing(NormalizedFlow::sourceMethod)
                .thenComparing(NormalizedFlow::sourceStmt)
                .thenComparing(NormalizedFlow::sinkMethod)
                .thenComparing(NormalizedFlow::sinkStmt));
        if (results == null || results.isEmpty()) {
            return flows;
        }
        Map<Unit, SootMethod> owners = buildOwnerMap();
        for (DataFlowResult result : results.getResultSet()) {
            Unit source = originUnit(result.getSource().getStmt());
            Unit sink = originUnit(result.getSink().getStmt());
            flows.add(new NormalizedFlow(
                    signature(originOwner(owners, source)),
                    statement(source),
                    signature(originOwner(owners, sink)),
                    statement(sink)));
        }
        return flows;
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
        if (unit == null) {
            return "<unknown>";
        }
        int line = unit.getJavaSourceStartLineNumber();
        return line > 0 ? unit + " @line " + line : unit.toString();
    }

    private static Unit originUnit(Unit unit) {
        return unit == null ? null : GenericTagUtil.getOriginUnit(unit);
    }

    private static SootMethod originOwner(Map<Unit, SootMethod> owners, Unit unit) {
        SootMethod method = owners.get(unit);
        return method == null ? null : GenericTagUtil.getOriginMethod(method);
    }

    private static String resolveSpecializedEntryPoint(String requestedEntryPoint, CallGraph callGraph) {
        Set<String> candidates = new LinkedHashSet<>();
        for (Iterator<soot.jimple.toolkits.callgraph.Edge> it = callGraph.iterator(); it.hasNext();) {
            soot.jimple.toolkits.callgraph.Edge edge = it.next();
            addEntryPointCandidate(candidates, edge.src(), requestedEntryPoint);
            addEntryPointCandidate(candidates, edge.tgt(), requestedEntryPoint);
        }
        if (candidates.isEmpty()) {
            for (SootClass sootClass : Scene.v().getClasses()) {
                for (SootMethod method : sootClass.getMethods()) {
                    addEntryPointCandidate(candidates, method, requestedEntryPoint);
                }
            }
        }
        return candidates.isEmpty() ? requestedEntryPoint : candidates.iterator().next();
    }

    private static void addEntryPointCandidate(Set<String> candidates, SootMethod method,
                                               String requestedEntryPoint) {
        if (method != null && GenericTagUtil.getOriginMethod(method).getSignature().equals(requestedEntryPoint)) {
            candidates.add(method.getSignature());
        }
    }

    private static String genericMode(List<String> args) {
        for (int i = 0; i < args.size(); i++) {
            String arg = args.get(i);
            if (arg.equals("-generic")) {
                return i + 1 < args.size() ? args.get(i + 1) : "enabled";
            }
            if (arg.startsWith("-generic=")) {
                return arg.substring(arg.indexOf('=') + 1);
            }
        }
        return "baseline";
    }

    private static long elapsedMillis(long start) {
        return Math.round((System.nanoTime() - start) / 1_000_000.0);
    }

    private static String csv(String text) {
        return "\"" + text.replace("\"", "\"\"") + "\"";
    }
}
