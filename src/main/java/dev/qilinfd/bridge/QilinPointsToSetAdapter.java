package dev.qilinfd.bridge;

import soot.Type;
import soot.jimple.ClassConstant;

import java.util.Collections;
import java.util.Set;

final class QilinPointsToSetAdapter implements soot.PointsToSet {
    private final qilin.core.sets.PointsToSet delegate;

    QilinPointsToSetAdapter(qilin.core.sets.PointsToSet delegate) {
        this.delegate = delegate;
    }

    static QilinPointsToSetAdapter empty() {
        return new QilinPointsToSetAdapter(null);
    }

    qilin.core.sets.PointsToSet delegate() {
        return delegate;
    }

    @Override
    public boolean isEmpty() {
        return delegate == null || delegate.isEmpty();
    }

    @Override
    public boolean hasNonEmptyIntersection(soot.PointsToSet other) {
        if (delegate == null || other == null) {
            return false;
        }
        if (other instanceof QilinPointsToSetAdapter adapter) {
            return adapter.delegate != null && delegate.hasNonEmptyIntersection(adapter.delegate);
        }
        return !Collections.disjoint(possibleTypes(), other.possibleTypes());
    }

    @Override
    public Set<Type> possibleTypes() {
        return delegate == null ? Collections.emptySet() : delegate.possibleTypes();
    }

    @Override
    public Set<String> possibleStringConstants() {
        return delegate == null ? Collections.emptySet() : delegate.possibleStringConstants();
    }

    @Override
    public Set<ClassConstant> possibleClassConstants() {
        return delegate == null ? Collections.emptySet() : delegate.possibleClassConstants();
    }
}
