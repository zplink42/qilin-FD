package dev.qilinfd.bridge;

import soot.G;
import soot.jimple.infoflow.Infoflow;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.InfoflowConfiguration.CodeEliminationMode;
import soot.jimple.infoflow.InfoflowConfiguration.SootIntegrationMode;
import soot.jimple.infoflow.results.DataFlowResult;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.sourcesSinks.manager.DefaultSourceSinkManager;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class NativeFlowDroidBackend implements AnalysisBackend {
    @Override
    public void run(AnalysisConfig config) throws IOException {
        G.reset();
        long start = System.nanoTime();

        Infoflow infoflow = new Infoflow();
        InfoflowConfiguration flowConfig = infoflow.getConfig();
        flowConfig.setSootIntegrationMode(SootIntegrationMode.CreateNewInstance);
        flowConfig.setCallgraphAlgorithm(config.nativeCallgraphAlgorithm());
        flowConfig.setAliasingAlgorithm(config.aliasingAlgorithm());
        flowConfig.setFlowSensitiveAliasing(
                config.aliasingAlgorithm() == InfoflowConfiguration.AliasingAlgorithm.FlowSensitive);
        flowConfig.setCodeEliminationMode(CodeEliminationMode.NoCodeElimination);
        flowConfig.setEnableReflection(false);
        flowConfig.setEnableExceptionTracking(false);
        flowConfig.setPathAgnosticResults(true);
        flowConfig.setLogSourcesAndSinks(true);
        flowConfig.setIgnoreFlowsInSystemPackages(false);
        flowConfig.setMaxThreadNum(config.integer("threads", 1));
        if (config.longValue("timeoutSeconds", 0L) > 0L) {
            flowConfig.setDataFlowTimeout(config.longValue("timeoutSeconds", 0L));
        }

        infoflow.computeInfoflow(
                config.path("appPath").toString(),
                config.nativeLibraryClasspath(),
                config.entryPoint(),
                new DefaultSourceSinkManager(config.definitions("sources"), config.definitions("sinks")));

        InfoflowResults results = infoflow.getResults();
        List<String> lines = new ArrayList<>();
        int leaks = results == null ? 0 : results.numConnections();
        lines.add("backend=native");
        lines.add("entryPoint=" + config.entryPoint());
        lines.add("callgraph=" + config.nativeCallgraphAlgorithm());
        lines.add("aliasing=" + config.aliasingAlgorithm());
        lines.add("flowDroidLeaks=" + leaks);
        lines.add("runtimeMs=" + elapsedMillis(start));
        lines.add("sourceStmt,sinkStmt");
        if (results != null) {
            results.getResultSet().stream()
                    .sorted(Comparator.comparing(DataFlowResult::toString))
                    .forEach(result -> lines.add(csv(result.getSource().getStmt().toString()) + ","
                            + csv(result.getSink().getStmt().toString())));
        }
        lines.forEach(System.out::println);
        Path output = config.optionalPath("output");
        if (output != null) {
            if (output.getParent() != null) {
                Files.createDirectories(output.getParent());
            }
            Files.write(output, lines, StandardCharsets.UTF_8);
        }
    }

    private static long elapsedMillis(long start) {
        return Math.round((System.nanoTime() - start) / 1_000_000.0);
    }

    private static String csv(String text) {
        return "\"" + text.replace("\"", "\"\"") + "\"";
    }
}
