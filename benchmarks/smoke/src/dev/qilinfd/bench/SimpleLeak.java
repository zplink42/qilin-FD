package dev.qilinfd.bench;

public final class SimpleLeak {
    private SimpleLeak() {
    }

    public static void main(String[] args) {
        String value = TaintApi.source();
        TaintApi.sink(value);
    }
}
