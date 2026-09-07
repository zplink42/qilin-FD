package dev.qilinfd.bridge.flowdroid;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Sets;
import com.google.common.collect.Table;
import heros.solver.PathEdge;
import soot.Local;
import soot.PointsToAnalysis;
import soot.PointsToSet;
import soot.Scene;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.ArrayRef;
import soot.jimple.DefinitionStmt;
import soot.jimple.FieldRef;
import soot.jimple.InstanceFieldRef;
import soot.jimple.StaticFieldRef;
import soot.jimple.Stmt;
import soot.jimple.infoflow.InfoflowManager;
import soot.jimple.infoflow.aliasing.AbstractBulkAliasStrategy;
import soot.jimple.infoflow.data.Abstraction;
import soot.jimple.infoflow.data.AccessPath;
import soot.jimple.infoflow.data.AccessPathFactory;
import soot.jimple.infoflow.data.AccessPathFragment;
import soot.jimple.infoflow.solver.IInfoflowSolver;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * FlowDroid 2.14.1's points-to-based alias strategy assumes that
 * {@link AccessPathFactory#copyWithNewValue(AccessPath, Value)} never returns
 * {@code null}. Real-world bytecode can violate that assumption when two values
 * alias but their declared types cannot form the same access path.
 *
 * <p>This implementation is intentionally identical to FlowDroid's strategy
 * except that it skips access paths that FlowDroid cannot represent. It keeps
 * all alias decisions based on the Qilin points-to sets installed in
 * {@link Scene}.</p>
 */
public final class SafePtsBasedAliasStrategy extends AbstractBulkAliasStrategy {
    private static final AtomicLong REJECTED_ACCESS_PATHS = new AtomicLong();

    private final Table<SootMethod, Abstraction, Set<Abstraction>> aliases = HashBasedTable.create();

    public SafePtsBasedAliasStrategy(InfoflowManager manager) {
        super(manager);
    }

    public static long rejectedAccessPathCount() {
        return REJECTED_ACCESS_PATHS.get();
    }

    public static void resetStatistics() {
        REJECTED_ACCESS_PATHS.set(0L);
    }

    @Override
    public void computeAliasTaints(Abstraction d1, Stmt src, Value targetValue,
                                   Set<Abstraction> taintSet, SootMethod method,
                                   Abstraction newAbs) {
        computeAliasTaintsInternal(d1, method, newAbs, Collections.emptyList(),
                newAbs.getAccessPath().getTaintSubFields(), src);
    }

    public void computeAliasTaintsInternal(Abstraction d1, SootMethod method,
                                           Abstraction newAbs,
                                           List<AccessPathFragment> appendFragments,
                                           boolean taintSubFields, Stmt actStmt) {
        actStmt = newAbs.getActivationUnit() == null
                ? actStmt
                : (Stmt) newAbs.getActivationUnit();

        synchronized (aliases) {
            if (aliases.contains(method, newAbs)) {
                Set<Abstraction> d1s = aliases.get(method, newAbs);
                if (d1s.contains(d1)) {
                    return;
                }
                d1s.add(d1);
            } else {
                Set<Abstraction> d1s = Sets.newIdentityHashSet();
                d1s.add(d1);
                aliases.put(method, newAbs, d1s);
            }
        }

        AccessPath ap = newAbs.getAccessPath();
        if ((ap.isInstanceFieldRef() && ap.getFirstField() != null)
                || (ap.isStaticFieldRef() && ap.getFragmentCount() > 1)) {
            List<AccessPathFragment> appendList = new LinkedList<>(appendFragments);
            appendList.add(0, ap.getLastFragment());
            Abstraction shortened = newAbs.deriveNewAbstraction(ap.dropLastField(), null);
            if (shortened != null) {
                computeAliasTaintsInternal(d1, method, shortened, appendList,
                        taintSubFields, actStmt);
            }
        }

        if (ap.getFragmentCount() > 1) {
            return;
        }

        PointsToSet ptsTaint = getPointsToSet(ap);
        AccessPathFragment[] appendFragmentsArray =
                appendFragments.toArray(new AccessPathFragment[0]);
        boolean beforeActUnit = method.getActiveBody().getUnits().contains(actStmt);
        AccessPathFactory apFactory = manager.getAccessPathFactory();

        for (Unit unit : method.getActiveBody().getUnits()) {
            Stmt stmt = (Stmt) unit;
            if (stmt == actStmt) {
                beforeActUnit = false;
            }

            PointsToSet originalBasePointsTo =
                    getPointsToSet(newAbs.getAccessPath().getPlainValue());
            for (ValueBox valueBox : stmt.getUseAndDefBoxes()) {
                Value value = valueBox.getValue();
                PointsToSet candidatePointsTo = getPointsToSet(value);
                if (candidatePointsTo == null
                        || !candidatePointsTo.hasNonEmptyIntersection(originalBasePointsTo)) {
                    continue;
                }

                AccessPath copied = apFactory.copyWithNewValue(ap, value);
                if (copied == null) {
                    REJECTED_ACCESS_PATHS.incrementAndGet();
                    continue;
                }
                AccessPath newAccessPath =
                        apFactory.appendFields(copied, appendFragmentsArray, taintSubFields);
                if (newAccessPath == null) {
                    REJECTED_ACCESS_PATHS.incrementAndGet();
                    continue;
                }

                Abstraction calleeAbstraction =
                        newAbs.deriveNewAbstraction(newAccessPath, stmt);
                if (calleeAbstraction == null) {
                    REJECTED_ACCESS_PATHS.incrementAndGet();
                    continue;
                }
                calleeAbstraction = beforeActUnit
                        ? calleeAbstraction.deriveInactiveAbstraction(actStmt)
                        : calleeAbstraction.getActiveCopy();
                manager.getMainSolver().processEdge(
                        new PathEdge<>(d1, unit, calleeAbstraction));
                break;
            }

            if (!(unit instanceof DefinitionStmt assignment)) {
                continue;
            }

            Value right = assignment.getRightOp();
            Value left = assignment.getLeftOp();
            if (isAliasedAtStmt(ptsTaint, right) && !appendFragments.isEmpty()) {
                AccessPath leftAccessPath = manager.getAccessPathFactory()
                        .createAccessPath(left, appendFragmentsArray, taintSubFields);
                Abstraction leftAlias = leftAccessPath == null
                        ? null
                        : newAbs.deriveNewAbstraction(leftAccessPath, stmt);
                if (leftAlias != null) {
                    leftAlias = beforeActUnit
                            ? leftAlias.deriveInactiveAbstraction(actStmt)
                            : leftAlias.getActiveCopy();
                    computeAliasTaints(d1, stmt, left, Collections.emptySet(),
                            method, leftAlias);
                }
            }

            if (isAliasedAtStmt(ptsTaint, left) && isValidAccessPathRoot(right)) {
                AccessPath rightAccessPath = manager.getAccessPathFactory()
                        .createAccessPath(right, appendFragmentsArray, taintSubFields);
                Abstraction rightAlias = rightAccessPath == null
                        ? null
                        : newAbs.deriveNewAbstraction(rightAccessPath, stmt);
                if (rightAlias != null) {
                    rightAlias = beforeActUnit
                            ? rightAlias.deriveInactiveAbstraction(actStmt)
                            : rightAlias.getActiveCopy();
                    manager.getMainSolver().processEdge(
                            new PathEdge<>(d1, unit, rightAlias));
                }
            }
        }
    }

    private boolean isValidAccessPathRoot(Value value) {
        return value instanceof FieldRef
                || value instanceof Local
                || value instanceof ArrayRef;
    }

    private boolean isAliasedAtStmt(PointsToSet taintPointsTo, Value value) {
        if (taintPointsTo == null) {
            return false;
        }
        PointsToSet valuePointsTo = getPointsToSet(value);
        return valuePointsTo != null
                && taintPointsTo.hasNonEmptyIntersection(valuePointsTo);
    }

    private PointsToSet getPointsToSet(Value value) {
        PointsToAnalysis pointsToAnalysis = Scene.v().getPointsToAnalysis();
        synchronized (pointsToAnalysis) {
            if (value instanceof Local local) {
                return pointsToAnalysis.reachingObjects(local);
            }
            if (value instanceof InstanceFieldRef instanceFieldRef) {
                return pointsToAnalysis.reachingObjects(
                        (Local) instanceFieldRef.getBase(), instanceFieldRef.getField());
            }
            if (value instanceof StaticFieldRef staticFieldRef) {
                return pointsToAnalysis.reachingObjects(staticFieldRef.getField());
            }
            if (value instanceof ArrayRef arrayRef) {
                return pointsToAnalysis.reachingObjects((Local) arrayRef.getBase());
            }
            return null;
        }
    }

    private PointsToSet getPointsToSet(AccessPath accessPath) {
        PointsToAnalysis pointsToAnalysis = Scene.v().getPointsToAnalysis();
        if (accessPath.isLocal()) {
            return pointsToAnalysis.reachingObjects(accessPath.getPlainValue());
        }
        if (accessPath.isInstanceFieldRef()) {
            return pointsToAnalysis.reachingObjects(
                    accessPath.getPlainValue(), accessPath.getFirstField());
        }
        if (accessPath.isStaticFieldRef()) {
            return pointsToAnalysis.reachingObjects(accessPath.getFirstField());
        }
        throw new IllegalArgumentException("Unexpected access path type: " + accessPath);
    }

    @Override
    public void injectCallingContext(Abstraction abstraction, IInfoflowSolver solver,
                                     SootMethod callee, Unit callSite,
                                     Abstraction source, Abstraction d1) {
        // Points-to-based aliasing is flow-insensitive and needs no calling context.
    }

    @Override
    public boolean isFlowSensitive() {
        return false;
    }

    @Override
    public boolean requiresAnalysisOnReturn() {
        return true;
    }

    @Override
    public IInfoflowSolver getSolver() {
        return null;
    }

    @Override
    public void cleanup() {
        aliases.clear();
    }
}
