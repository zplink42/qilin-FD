package dev.qilinfd.bridge;

import soot.Body;
import soot.Local;
import soot.Value;
import soot.ValueBox;
import soot.jimple.infoflow.FlowDroidLocalSplitter;
import soot.jimple.infoflow.Infoflow;
import soot.jimple.infoflow.cfg.BiDirICFGFactory;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Infoflow variant that normalizes Qilin-owned Soot bodies immediately before
 * FlowDroid's mandatory local-splitting preprocessing pass.
 */
final class QilinCompatibleInfoflow extends Infoflow {
    private final RepairingLocalSplitter localSplitter = new RepairingLocalSplitter();

    QilinCompatibleInfoflow(BiDirICFGFactory icfgFactory) {
        super(null, false, icfgFactory);
    }

    @Override
    protected FlowDroidLocalSplitter getLocalSplitter() {
        return localSplitter;
    }

    int repairedMissingLocalDeclarations() {
        return localSplitter.repairedMissingLocalDeclarations;
    }

    static int declareMissingLocals(Body body) {
        Set<Local> declaredLocals = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Local local : body.getLocals()) {
            declaredLocals.add(local);
        }

        int repairs = 0;
        for (ValueBox box : body.getUseAndDefBoxes()) {
            Value value = box.getValue();
            if (value instanceof Local local && declaredLocals.add(local)) {
                body.getLocals().add(local);
                repairs++;
            }
        }
        return repairs;
    }

    private static final class RepairingLocalSplitter extends FlowDroidLocalSplitter {
        private int repairedMissingLocalDeclarations;

        @Override
        protected void internalTransform(Body body, String phaseName, Map<String, String> options) {
            repairedMissingLocalDeclarations += declareMissingLocals(body);
            super.internalTransform(body, phaseName, options);
        }
    }
}
