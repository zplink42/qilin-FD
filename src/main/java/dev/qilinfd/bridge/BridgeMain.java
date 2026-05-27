package dev.qilinfd.bridge;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

public final class BridgeMain {
//    private static final String DEFAULT_CONFIG = "benchmarks/config/smoke-qilin.properties";

//    private static final String DEFAULT_CONFIG = "benchmarks/config/dacapo-eclipse-qilin.properties";

    private static final String DEFAULT_CONFIG = "benchmarks/config/github-juliet-cwe78.properties";

    private BridgeMain() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            args = new String[] {"run", "--config", DEFAULT_CONFIG};
        }
        CliRequest request = CliRequest.parse(args);
        AnalysisConfig config = AnalysisConfig.load(request.configPath(), request.overrides());
        if ("print-qilin-args".equals(request.command())) {
            config.qilinArguments().forEach(System.out::println);
            return;
        }
        if (!"run".equals(request.command())) {
            throw new IllegalArgumentException("Unknown command: " + request.command());
        }

        AnalysisBackend backend = switch (config.backend()) {
            case "qilin" -> new QilinFlowDroidBackend();
            case "native", "flowdroid" -> new NativeFlowDroidBackend();
            default -> throw new IllegalArgumentException("Unknown backend: " + config.backend());
        };
        backend.run(config);
    }

    private record CliRequest(String command, Path configPath, Map<String, String> overrides) {
        static CliRequest parse(String[] args) {
            if (args.length < 3 || !"--config".equals(args[1])) {
                throw new IllegalArgumentException(
                        "Usage: run|print-qilin-args --config <properties> [--set key=value ...]");
            }
            String command = args[0];
            Path configPath = Path.of(args[2]);
            Map<String, String> overrides = new LinkedHashMap<>();
            for (int i = 3; i < args.length; i++) {
                if (!"--set".equals(args[i]) || i + 1 >= args.length) {
                    throw new IllegalArgumentException("Expected --set key=value after config path.");
                }
                String pair = args[++i];
                int separator = pair.indexOf('=');
                if (separator <= 0) {
                    throw new IllegalArgumentException("Invalid override: " + pair);
                }
                overrides.put(pair.substring(0, separator), pair.substring(separator + 1));
            }
            return new CliRequest(command, configPath, Map.copyOf(overrides));
        }
    }
}
