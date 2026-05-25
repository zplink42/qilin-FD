package dev.qilinfd.bench;

public final class TaintApi {
    private TaintApi() {
    }

    public static String source() {
        return "sensitive";
    }

    public static void sink(String value) {
    }
}
