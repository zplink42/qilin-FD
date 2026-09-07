package org.owasp.benchmark.testcode;

/**
 * Two-case command-injection harness used to measure whether very small
 * batches remain precise enough for the final OWASP experiment.
 */
public final class BenchmarkTest00006And00007Harness {
    private BenchmarkTest00006And00007Harness() {
    }

    public static void main(String[] args) throws Exception {
        new BenchmarkTest00006().doPost(null, null);
        new BenchmarkTest00007().doPost(null, null);
    }
}
