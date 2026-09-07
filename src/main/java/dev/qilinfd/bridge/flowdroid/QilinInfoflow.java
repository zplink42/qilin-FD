package dev.qilinfd.bridge.flowdroid;

import soot.Unit;
import soot.jimple.infoflow.Infoflow;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.aliasing.IAliasingStrategy;
import soot.jimple.infoflow.cfg.BiDirICFGFactory;
import soot.jimple.infoflow.data.Abstraction;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;
import soot.jimple.infoflow.solver.executors.InterruptableExecutor;
import soot.jimple.infoflow.solver.memory.IMemoryManager;
import soot.jimple.infoflow.sourcesSinks.manager.ISourceSinkManager;

import java.io.File;

/**
 * Installs the guarded points-to alias strategy while retaining FlowDroid's
 * standard implementations for all other aliasing modes.
 */
public final class QilinInfoflow extends Infoflow {
    public QilinInfoflow(File androidPath, boolean forceAndroidJar,
                         BiDirICFGFactory icfgFactory) {
        super(androidPath, forceAndroidJar, icfgFactory);
    }

    @Override
    protected IAliasingStrategy createAliasAnalysis(
            ISourceSinkManager sourceSinkManager,
            IInfoflowCFG icfg,
            InterruptableExecutor executor,
            IMemoryManager<Abstraction, Unit> memoryManager) {
        if (getConfig().getAliasingAlgorithm()
                == InfoflowConfiguration.AliasingAlgorithm.PtsBased) {
            SafePtsBasedAliasStrategy.resetStatistics();
            return new SafePtsBasedAliasStrategy(manager);
        }
        return super.createAliasAnalysis(
                sourceSinkManager, icfg, executor, memoryManager);
    }
}
