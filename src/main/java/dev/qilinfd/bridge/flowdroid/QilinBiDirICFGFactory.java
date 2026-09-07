package dev.qilinfd.bridge.flowdroid;

import soot.Scene;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm;
import soot.jimple.infoflow.cfg.BiDirICFGFactory;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.jimple.toolkits.callgraph.Edge;

import java.util.Iterator;

/**
 * Builds FlowDroid's ICFG over the call graph that Qilin has already installed
 * in Soot's global scene.
 */
public final class QilinBiDirICFGFactory implements BiDirICFGFactory {
    @Override
    public IInfoflowCFG buildBiDirICFG(
            CallgraphAlgorithm callgraphAlgorithm, boolean enableExceptionTracking) {
        QilinJimpleBasedICFG baseCFG =
                new QilinJimpleBasedICFG(enableExceptionTracking, true);
        baseCFG.setIncludePhantomCallees(true);
        initializeOwnersFromCallGraph(baseCFG);
        return new InfoflowCFG(baseCFG);
    }

    private static void initializeOwnersFromCallGraph(QilinJimpleBasedICFG baseCFG) {
        for (Iterator<Edge> it = Scene.v().getCallGraph().iterator(); it.hasNext();) {
            Edge edge = it.next();
            initializeOwner(baseCFG, edge.src());
            initializeOwner(baseCFG, edge.tgt());
            Unit unit = edge.srcUnit();
            if (unit != null && edge.src() != null && edge.src().hasActiveBody()) {
                baseCFG.setOwnerStatement(unit, edge.src().getActiveBody());
            }
        }
    }

    private static void initializeOwner(
            QilinJimpleBasedICFG baseCFG, SootMethod method) {
        if (method != null && method.isConcrete() && method.hasActiveBody()) {
            baseCFG.registerBody(method.getActiveBody());
        }
    }
}
