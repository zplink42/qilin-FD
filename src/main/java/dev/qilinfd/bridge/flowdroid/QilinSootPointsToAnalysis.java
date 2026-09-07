package dev.qilinfd.bridge.flowdroid;

import qilin.core.PTA;
import qilin.generic.tag.GenericTagUtil;
import soot.Context;
import soot.Local;
import soot.SootField;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Exposes Qilin points-to results through Soot's client API. For an original
 * program local or field, all FSpec-specialized variants are conservatively
 * unioned. The mapping itself is maintained by Qilin's generic core.
 */
public final class QilinSootPointsToAnalysis
        implements soot.PointsToAnalysis {
    private final PTA pta;
    private final Map<Local, soot.PointsToSet> localCache =
            Collections.synchronizedMap(new IdentityHashMap<>());
    private final Map<SootField, soot.PointsToSet> fieldCache =
            Collections.synchronizedMap(new IdentityHashMap<>());
    private final Map<Local, Map<SootField, soot.PointsToSet>> localFieldCache =
            Collections.synchronizedMap(new IdentityHashMap<>());
    private final Map<soot.PointsToSet, Map<SootField, soot.PointsToSet>>
            setFieldCache =
            Collections.synchronizedMap(new IdentityHashMap<>());
    private final Map<soot.PointsToSet, soot.PointsToSet> arrayElementCache =
            Collections.synchronizedMap(new IdentityHashMap<>());

    public QilinSootPointsToAnalysis(PTA pta) {
        this.pta = pta;
    }

    @Override
    public soot.PointsToSet reachingObjects(Local local) {
        synchronized (localCache) {
            return localCache.computeIfAbsent(
                    local,
                    ignored -> reachingObjectsForLocals(
                            local, pta::reachingObjects));
        }
    }

    @Override
    public soot.PointsToSet reachingObjects(Context context, Local local) {
        return reachingObjectsForLocals(
                local, variant -> pta.reachingObjects(context, variant));
    }

    @Override
    public soot.PointsToSet reachingObjects(SootField field) {
        synchronized (fieldCache) {
            return fieldCache.computeIfAbsent(
                    field,
                    ignored -> reachingObjectsForFields(
                            field, pta::reachingObjects));
        }
    }

    @Override
    public soot.PointsToSet reachingObjects(
            soot.PointsToSet baseSet, SootField field) {
        if (baseSet instanceof QilinSootPointsToSet qpts) {
            synchronized (setFieldCache) {
                Map<SootField, soot.PointsToSet> byField =
                        setFieldCache.computeIfAbsent(
                                baseSet,
                                ignored -> Collections.synchronizedMap(
                                        new IdentityHashMap<>()));
                return byField.computeIfAbsent(field, ignored -> {
                    List<qilin.core.sets.PointsToSet> results =
                            new ArrayList<>();
                    for (qilin.core.sets.PointsToSet base : qpts.delegates()) {
                        for (SootField variant : fieldVariants(field)) {
                            results.add(pta.reachingObjects(base, variant));
                        }
                    }
                    return wrap(results);
                });
            }
        }
        return empty();
    }

    @Override
    public soot.PointsToSet reachingObjects(
            Local local, SootField field) {
        synchronized (localFieldCache) {
            Map<SootField, soot.PointsToSet> byField =
                    localFieldCache.computeIfAbsent(
                            local,
                            ignored -> Collections.synchronizedMap(
                                    new IdentityHashMap<>()));
            return byField.computeIfAbsent(field, ignored -> {
                List<qilin.core.sets.PointsToSet> results = new ArrayList<>();
                for (Local localVariant : localVariants(local)) {
                    for (SootField fieldVariant : fieldVariants(field)) {
                        results.add(
                                pta.reachingObjects(
                                        localVariant, fieldVariant));
                    }
                }
                return wrap(results);
            });
        }
    }

    @Override
    public soot.PointsToSet reachingObjects(
            Context context, Local local, SootField field) {
        List<qilin.core.sets.PointsToSet> results = new ArrayList<>();
        for (Local localVariant : localVariants(local)) {
            for (SootField fieldVariant : fieldVariants(field)) {
                results.add(
                        pta.reachingObjects(
                                context, localVariant, fieldVariant));
            }
        }
        return wrap(results);
    }

    @Override
    public soot.PointsToSet reachingObjectsOfArrayElement(
            soot.PointsToSet baseSet) {
        if (baseSet instanceof QilinSootPointsToSet qpts) {
            synchronized (arrayElementCache) {
                return arrayElementCache.computeIfAbsent(baseSet, ignored -> {
                    List<qilin.core.sets.PointsToSet> results =
                            new ArrayList<>();
                    for (qilin.core.sets.PointsToSet base : qpts.delegates()) {
                        results.add(pta.reachingObjectsOfArrayElement(base));
                    }
                    return wrap(results);
                });
            }
        }
        return empty();
    }

    private soot.PointsToSet wrap(qilin.core.sets.PointsToSet pointsToSet) {
        return new QilinSootPointsToSet(pta, pointsToSet);
    }

    private soot.PointsToSet wrap(
            List<qilin.core.sets.PointsToSet> pointsToSets) {
        return new QilinSootPointsToSet(pta, pointsToSets);
    }

    private soot.PointsToSet empty() {
        return new QilinSootPointsToSet(pta, List.of());
    }

    private soot.PointsToSet reachingObjectsForLocals(
            Local queriedLocal,
            Function<Local, qilin.core.sets.PointsToSet> query) {
        return wrap(localVariants(queriedLocal).stream().map(query).toList());
    }

    private soot.PointsToSet reachingObjectsForFields(
            SootField queriedField,
            Function<SootField, qilin.core.sets.PointsToSet> query) {
        return wrap(fieldVariants(queriedField).stream().map(query).toList());
    }

    private static List<Local> localVariants(Local queriedLocal) {
        if (GenericTagUtil.isSpecializedLocal(queriedLocal)) {
            return List.of(queriedLocal);
        }
        List<Local> variants = new ArrayList<>();
        variants.add(queriedLocal);
        variants.addAll(
                GenericTagUtil.getSpecializedLocals(queriedLocal));
        return variants;
    }

    private static List<SootField> fieldVariants(SootField queriedField) {
        if (!GenericTagUtil.getOriginField(queriedField)
                .equals(queriedField)) {
            return List.of(queriedField);
        }
        List<SootField> variants = new ArrayList<>();
        variants.add(queriedField);
        variants.addAll(
                GenericTagUtil.getSpecializedFields(queriedField));
        return variants;
    }
}
