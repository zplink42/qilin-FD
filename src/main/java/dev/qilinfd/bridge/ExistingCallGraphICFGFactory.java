package dev.qilinfd.bridge;

import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;
import soot.jimple.infoflow.cfg.BiDirICFGFactory;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;

final class ExistingCallGraphICFGFactory implements BiDirICFGFactory {
    @Override
    public IInfoflowCFG buildBiDirICFG(CallgraphAlgorithm callgraphAlgorithm, boolean enableExceptionTracking) {
        JimpleBasedInterproceduralCFG baseCfg = new JimpleBasedInterproceduralCFG(enableExceptionTracking, true);
        baseCfg.setIncludePhantomCallees(true);
        return new InfoflowCFG(baseCfg);
    }
}
