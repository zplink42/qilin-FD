package org.owasp.benchmark.testcode;

/**
 * Mixed negative/positive command-injection harness used to check that a
 * two-case batch does not manufacture cross-test taint flows.
 */
public final class BenchmarkTest00051And00077Harness {
    private BenchmarkTest00051And00077Harness() {
    }

    public static void main(String[] args) throws Exception {
        new BenchmarkTest00051().doPost(null, null);
        new BenchmarkTest00077().doPost(null, null);
    }
}
