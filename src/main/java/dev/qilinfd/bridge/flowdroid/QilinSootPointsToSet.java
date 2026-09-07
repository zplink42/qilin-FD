package dev.qilinfd.bridge.flowdroid;

import qilin.core.PTA;
import qilin.core.pag.AllocNode;
import qilin.core.pag.MethodPAG;
import qilin.generic.tag.GenericTagUtil;
import soot.Type;
import soot.Unit;
import soot.jimple.AnyNewExpr;
import soot.jimple.AssignStmt;
import soot.jimple.ClassConstant;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Union view over one or more Qilin points-to sets. Allocation-site
 * intersections are projected back to original FSpec allocation statements.
 */
public final class QilinSootPointsToSet implements soot.PointsToSet {
    private final PTA pta;
    private final List<qilin.core.sets.PointsToSet> delegates;
    private volatile Set<Object> projectedAllocationKeys;

    QilinSootPointsToSet(
            PTA pta, qilin.core.sets.PointsToSet delegate) {
        this(pta, delegate == null ? List.of() : List.of(delegate));
    }

    QilinSootPointsToSet(
            PTA pta, List<qilin.core.sets.PointsToSet> delegates) {
        this.pta = pta;
        this.delegates = delegates.stream()
                .filter(java.util.Objects::nonNull)
                .distinct()
                .collect(Collectors.toUnmodifiableList());
    }

    List<qilin.core.sets.PointsToSet> delegates() {
        return delegates;
    }

    @Override
    public boolean isEmpty() {
        return delegates.stream()
                .allMatch(qilin.core.sets.PointsToSet::isEmpty);
    }

    @Override
    public boolean hasNonEmptyIntersection(soot.PointsToSet other) {
        if (delegates.isEmpty() || other == null) {
            return false;
        }
        if (other instanceof QilinSootPointsToSet qpts) {
            if (pta != null && pta == qpts.pta) {
                Set<Object> left = projectedAllocationKeys();
                Set<Object> right = qpts.projectedAllocationKeys();
                Set<Object> smaller =
                        left.size() <= right.size() ? left : right;
                Set<Object> larger =
                        left.size() <= right.size() ? right : left;
                return smaller.stream().anyMatch(larger::contains);
            }
            for (qilin.core.sets.PointsToSet left : delegates) {
                for (qilin.core.sets.PointsToSet right : qpts.delegates) {
                    if (left.hasNonEmptyIntersection(right)) {
                        return true;
                    }
                }
            }
            return false;
        }
        Set<Type> thisTypes = possibleTypes();
        Set<Type> otherTypes = other.possibleTypes();
        return thisTypes != null
                && otherTypes != null
                && !Collections.disjoint(thisTypes, otherTypes);
    }

    private Set<Object> projectedAllocationKeys() {
        Set<Object> result = projectedAllocationKeys;
        if (result != null) {
            return result;
        }
        synchronized (this) {
            if (projectedAllocationKeys != null) {
                return projectedAllocationKeys;
            }
            result = new HashSet<>();
            for (qilin.core.sets.PointsToSet delegate : delegates) {
                for (AllocNode allocation : delegate.toCollection()) {
                    Object key = allocation.getNewExpr();
                    if (allocation.getMethod() != null
                            && allocation.getNewExpr()
                            instanceof AnyNewExpr newExpression) {
                        MethodPAG methodPAG = pta.getPag()
                                .getMethodPAG(allocation.getMethod());
                        Unit unit = methodPAG.getNewExprUnit(newExpression);
                        if (unit != null) {
                            Unit originUnit =
                                    GenericTagUtil.getOriginUnit(unit);
                            if (originUnit instanceof AssignStmt assignment) {
                                key = assignment.getRightOp();
                            }
                        }
                    }
                    result.add(key);
                }
            }
            projectedAllocationKeys =
                    Collections.unmodifiableSet(result);
            return projectedAllocationKeys;
        }
    }

    @Override
    public Set<Type> possibleTypes() {
        Set<Type> result = new HashSet<>();
        delegates.forEach(
                delegate -> result.addAll(delegate.possibleTypes()));
        return result;
    }

    @Override
    public Set<String> possibleStringConstants() {
        Set<String> result = new HashSet<>();
        for (qilin.core.sets.PointsToSet delegate : delegates) {
            Set<String> constants = delegate.possibleStringConstants();
            if (constants == null) {
                return null;
            }
            result.addAll(constants);
        }
        return result;
    }

    @Override
    public Set<ClassConstant> possibleClassConstants() {
        Set<ClassConstant> result = new HashSet<>();
        for (qilin.core.sets.PointsToSet delegate : delegates) {
            Set<ClassConstant> constants =
                    delegate.possibleClassConstants();
            if (constants == null) {
                return null;
            }
            result.addAll(constants);
        }
        return result;
    }

    @Override
    public String toString() {
        return delegates.toString();
    }
}
