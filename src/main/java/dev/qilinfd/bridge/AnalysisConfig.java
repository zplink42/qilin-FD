package dev.qilinfd.bridge;

import soot.jimple.infoflow.InfoflowConfiguration.AliasingAlgorithm;
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;

public final class AnalysisConfig {
    private final Path sourceFile;
    private final Properties values;

    private AnalysisConfig(Path sourceFile, Properties values) {
        this.sourceFile = sourceFile;
        this.values = values;
    }

    public static AnalysisConfig load(Path path, Map<String, String> overrides) throws IOException {
        Properties properties = new Properties();
        try (var reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        overrides.forEach(properties::setProperty);
        return new AnalysisConfig(path.toAbsolutePath().normalize(), properties);
    }

    public String backend() {
        return value("backend", "qilin").toLowerCase(Locale.ROOT);
    }

    public String required(String name) {
        String result = values.getProperty(name);
        if (result == null || result.isBlank()) {
            throw new IllegalArgumentException("Missing required configuration property '" + name
                    + "' in " + sourceFile);
        }
        return result.trim();
    }

    public String value(String name, String fallback) {
        String result = values.getProperty(name);
        return result == null || result.isBlank() ? fallback : result.trim();
    }

    public boolean has(String name) {
        String result = values.getProperty(name);
        return result != null && !result.isBlank();
    }

    public int integer(String name, int fallback) {
        return Integer.parseInt(value(name, Integer.toString(fallback)));
    }

    public long longValue(String name, long fallback) {
        return Long.parseLong(value(name, Long.toString(fallback)));
    }

    public Path path(String name) {
        return resolve(required(name));
    }

    public Path optionalPath(String name) {
        return has(name) ? resolve(required(name)) : null;
    }

    public String entryPoint() {
        if (has("entryPoint")) {
            return required("entryPoint");
        }
        return "<" + required("mainClass") + ": void main(java.lang.String[])>";
    }

    public List<String> definitions(String name) throws IOException {
        return Files.readAllLines(path(name), StandardCharsets.UTF_8).stream()
                .map(String::trim)
                .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                .collect(Collectors.toList());
    }

    public AliasingAlgorithm aliasingAlgorithm() {
        return switch (value("aliasing", "pts").toLowerCase(Locale.ROOT)) {
            case "none" -> AliasingAlgorithm.None;
            case "flow", "flowsensitive", "flow-sensitive" -> AliasingAlgorithm.FlowSensitive;
            case "pts", "ptsbased", "points-to" -> AliasingAlgorithm.PtsBased;
            case "lazy" -> AliasingAlgorithm.Lazy;
            default -> AliasingAlgorithm.valueOf(required("aliasing"));
        };
    }

    public CallgraphAlgorithm nativeCallgraphAlgorithm() {
        return switch (value("nativeCallgraph", "spark").toLowerCase(Locale.ROOT)) {
            case "auto", "automatic" -> CallgraphAlgorithm.AutomaticSelection;
            case "cha" -> CallgraphAlgorithm.CHA;
            case "vta" -> CallgraphAlgorithm.VTA;
            case "rta" -> CallgraphAlgorithm.RTA;
            case "spark" -> CallgraphAlgorithm.SPARK;
            case "geom" -> CallgraphAlgorithm.GEOM;
            case "ondemand", "on-demand" -> CallgraphAlgorithm.OnDemand;
            default -> CallgraphAlgorithm.valueOf(required("nativeCallgraph"));
        };
    }

    public String nativeLibraryClasspath() throws IOException {
        List<String> paths = new ArrayList<>();
        if (has("libraries")) {
            paths.add(path("libraries").toString());
        }
        if (has("jre")) {
            Path lib = path("jre").resolve("lib");
            if (Files.isDirectory(lib)) {
                try (var jars = Files.list(lib)) {
                    jars.filter(p -> p.getFileName().toString().endsWith(".jar"))
                            .sorted()
                            .map(Path::toString)
                            .forEach(paths::add);
                }
            }
        }
        return String.join(java.io.File.pathSeparator, paths);
    }

    public List<String> qilinArguments() {
        List<String> args = new ArrayList<>();
        args.addAll(tokens(value("qilinFlags", "-pae -pe -clinit=ONFLY -lcs -mh -se")));
        args.add("-apppath");
        args.add(path("appPath").toString());
        args.add("-mainclass");
        args.add(required("mainClass"));
        if (has("libraries")) {
            args.add("-libpath");
            args.add(path("libraries").toString());
        }
        if (has("jre")) {
            args.add("-jre=" + path("jre"));
        }
        args.add("-pta=" + value("pta", "insens"));
        args.addAll(tokens(value("qilinExtraArgs", "")));
        return Collections.unmodifiableList(args);
    }

    private Path resolve(String raw) {
        Path path = Path.of(raw);
        if (!path.isAbsolute()) {
            path = Path.of("").toAbsolutePath().resolve(path);
        }
        return path.normalize();
    }

    private static List<String> tokens(String raw) {
        if (raw == null || raw.isBlank()) {
            return Collections.emptyList();
        }
        return Arrays.asList(raw.trim().split("\\s+"));
    }
}
