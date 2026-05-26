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
import java.util.Set;
import java.util.stream.Collectors;

public final class AnalysisConfig {
    private static final Set<String> COMMON_OPTIONS_NOT_ALLOWED_IN_FLAGS = Set.of(
            "apppath", "libpath", "mainclass", "jre", "reflectionlog", "aliasing", "maxthreadnum", "timeout");
    private static final Set<String> DEPRECATED_PROPERTIES = Set.of(
            "entryPoint", "pta", "qilinExtraArgs", "callgraphMode", "nativeCallgraph");

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
        rejectDeprecatedProperties(path, properties);
        AnalysisConfig config = new AnalysisConfig(path.toAbsolutePath().normalize(), properties);
        config.rejectCommonOptionsInBackendFlags();
        return config;
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
        return switch (flagValue("nativeFlags", "cgalgo", "spark").toLowerCase(Locale.ROOT)) {
            case "auto", "automatic" -> CallgraphAlgorithm.AutomaticSelection;
            case "cha" -> CallgraphAlgorithm.CHA;
            case "vta" -> CallgraphAlgorithm.VTA;
            case "rta" -> CallgraphAlgorithm.RTA;
            case "spark" -> CallgraphAlgorithm.SPARK;
            case "geom" -> CallgraphAlgorithm.GEOM;
            case "ondemand", "on-demand" -> CallgraphAlgorithm.OnDemand;
            default -> CallgraphAlgorithm.valueOf(flagValue("nativeFlags", "cgalgo", "spark"));
        };
    }

    public Path applicationPath() {
        return path("appPath");
    }

    public Path optionalLibraryPath() {
        return optionalPath("libraries");
    }

    public String nativeLibraryClasspath() throws IOException {
        List<String> paths = new ArrayList<>();
        Path libraries = optionalLibraryPath();
        if (libraries != null) {
            paths.add(libraries.toString());
        }
        Path jre = optionalPath("jre");
        if (jre != null) {
            Path lib = jre.resolve("lib");
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
        List<String> args = new ArrayList<>(tokens(required("qilinFlags")));
        args.add("-apppath");
        args.add(applicationPath().toString());
        args.add("-mainclass");
        args.add(required("mainClass"));
        Path libraries = optionalLibraryPath();
        if (libraries != null) {
            args.add("-libpath");
            args.add(libraries.toString());
        }
        Path jre = optionalPath("jre");
        if (jre != null) {
            args.add("-jre=" + jre);
        }
        Path reflectionLog = optionalPath("reflectionLog");
        if (reflectionLog != null) {
            args.add("-reflectionlog");
            args.add(reflectionLog.toString());
        }
        return Collections.unmodifiableList(args);
    }

    public int maxThreadNum() {
        return integer("threads", 1);
    }

    public long dataFlowTimeoutSeconds() {
        return longValue("timeoutSeconds", 0);
    }

    private String flagValue(String property, String name, String fallback) {
        String value = optionalFlagValue(property, name);
        return value == null || value.isBlank() ? fallback : value;
    }

    private String optionalFlagValue(String property, String name) {
        List<String> flags = tokens(required(property));
        for (int i = 0; i < flags.size(); i++) {
            String token = flags.get(i);
            if (!optionName(token).equals(name)) {
                continue;
            }
            int separator = token.indexOf('=');
            if (separator >= 0) {
                return token.substring(separator + 1);
            }
            if (i + 1 >= flags.size() || flags.get(i + 1).startsWith("-")) {
                throw new IllegalArgumentException("Flag '-" + name + "' needs a value in " + sourceFile);
            }
            return flags.get(i + 1);
        }
        return null;
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

    private static String optionName(String token) {
        String withoutPrefix = token.startsWith("--") ? token.substring(2)
                : token.startsWith("-") ? token.substring(1) : token;
        int separator = withoutPrefix.indexOf('=');
        return separator >= 0 ? withoutPrefix.substring(0, separator) : withoutPrefix;
    }

    private void rejectCommonOptionsInBackendFlags() {
        for (String property : List.of("qilinFlags", "nativeFlags")) {
            if (!has(property)) {
                continue;
            }
            for (String token : tokens(required(property))) {
                String option = optionName(token);
                if (COMMON_OPTIONS_NOT_ALLOWED_IN_FLAGS.contains(option)) {
                    throw new IllegalArgumentException("Option '-" + option + "' is a common configuration input in "
                            + sourceFile + "; remove it from " + property + " and set its top-level property.");
                }
            }
        }
    }

    private static void rejectDeprecatedProperties(Path sourceFile, Properties properties) {
        for (String property : DEPRECATED_PROPERTIES) {
            if (properties.containsKey(property)) {
                throw new IllegalArgumentException("Configuration property '" + property
                        + "' is no longer supported in " + sourceFile
                        + "; move backend-specific choices into qilinFlags or nativeFlags.");
            }
        }
    }
}
