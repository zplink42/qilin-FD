package dev.qilinfd.bench.flowdroid;

import soot.jimple.infoflow.test.ConstantTestCode;

public final class ConstantTestHarness {
    private ConstantTestHarness() {
    }

    public static void main(String[] args) {
        new ConstantTestCode().easyConstantVarTest();
    }
}
