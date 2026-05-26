package dev.qilinfd.bridge;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AnalysisConfigTest {
    @Test
    void passesOnlyQilinOptionsToTheReplaceablePtaJar() throws Exception {
        Path configFile = Files.createTempFile("qilinfd", ".properties");
        Files.writeString(configFile, String.join(System.lineSeparator(),
                "backend=qilin",
                "appPath=target.jar",
                "mainClass=example.Main",
                "jre=jre8",
                "reflectionLog=reflection.log",
                "aliasing=lazy",
                "threads=2",
                "qilinFlags=-pae -pta=1o",
                "sources=sources.txt",
                "sinks=sinks.txt"));

        AnalysisConfig config = AnalysisConfig.load(configFile, Map.of());
        var args = config.qilinArguments();

        assertEquals("qilin", config.backend());
        assertTrue(args.contains("-pta=1o"));
        assertTrue(args.stream().anyMatch(value -> value.endsWith("target.jar")));
        assertTrue(args.contains("-reflectionlog"));
        assertTrue(args.stream().anyMatch(value -> value.endsWith("reflection.log")));
        assertTrue(config.applicationPath().toString().endsWith("target.jar"));
        assertEquals("<example.Main: void main(java.lang.String[])>", config.entryPoint());
        assertEquals(soot.jimple.infoflow.InfoflowConfiguration.AliasingAlgorithm.Lazy, config.aliasingAlgorithm());
        assertEquals(2, config.maxThreadNum());
    }

    @Test
    void readsAllNativeExecutionOptionsFromNativeFlags() throws Exception {
        Path configFile = Files.createTempFile("qilinfd-native", ".properties");
        Files.writeString(configFile, String.join(System.lineSeparator(),
                "backend=native",
                "appPath=native.jar",
                "mainClass=example.NativeMain",
                "aliasing=flow",
                "threads=3",
                "timeoutSeconds=45",
                "nativeFlags=-cgalgo=cha",
                "sources=sources.txt",
                "sinks=sinks.txt"));

        AnalysisConfig config = AnalysisConfig.load(configFile, Map.of());

        assertEquals("<example.NativeMain: void main(java.lang.String[])>", config.entryPoint());
        assertEquals(soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm.CHA,
                config.nativeCallgraphAlgorithm());
        assertEquals(soot.jimple.infoflow.InfoflowConfiguration.AliasingAlgorithm.FlowSensitive,
                config.aliasingAlgorithm());
        assertEquals(3, config.maxThreadNum());
        assertEquals(45, config.dataFlowTimeoutSeconds());
    }

    @Test
    void rejectsCommonInputsRepeatedInsideBackendFlags() throws Exception {
        Path configFile = Files.createTempFile("qilinfd-duplicate", ".properties");
        Files.writeString(configFile, String.join(System.lineSeparator(),
                "backend=qilin",
                "appPath=target.jar",
                "mainClass=example.Main",
                "qilinFlags=-pta=insens -apppath duplicated-target.jar",
                "sources=sources.txt",
                "sinks=sinks.txt"));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> AnalysisConfig.load(configFile, Map.of()));

        assertTrue(exception.getMessage().contains("-apppath"));
        assertTrue(exception.getMessage().contains("common configuration input"));
    }
}
