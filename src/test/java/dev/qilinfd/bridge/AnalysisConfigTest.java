package dev.qilinfd.bridge;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
                "pta=1o",
                "sources=sources.txt",
                "sinks=sinks.txt",
                "callgraphMode=specialized",
                "aliasing=lazy",
                "threads=2"));

        AnalysisConfig config = AnalysisConfig.load(configFile, Map.of());
        var args = config.qilinArguments();

        assertEquals("qilin", config.backend());
        assertTrue(args.contains("-pta=1o"));
        assertTrue(args.stream().anyMatch(value -> value.endsWith("target.jar")));
        assertTrue(args.stream().noneMatch(value -> value.startsWith("-fd")));
        assertTrue(args.stream().noneMatch(value -> value.equals("specialized") || value.equals("lazy")));
    }
}
