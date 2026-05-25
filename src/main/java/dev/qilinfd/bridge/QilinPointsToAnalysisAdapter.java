package dev.qilinfd.bridge;

import qilin.core.PTA;
import soot.Context;
import soot.Local;
import soot.SootField;

final class QilinPointsToAnalysisAdapter implements soot.PointsToAnalysis {
    private final PTA pta;

    QilinPointsToAnalysisAdapter(PTA pta) {
        this.pta = pta;
    }

    @Override
    public soot.PointsToSet reachingObjects(Local local) {
        return wrap(pta.reachingObjects(local));
    }

    @Override
    public soot.PointsToSet reachingObjects(Context context, Local local) {
        return wrap(pta.reachingObjects(context, local));
    }

    @Override
    public soot.PointsToSet reachingObjects(SootField field) {
        return wrap(pta.reachingObjects(field));
    }

    @Override
    public soot.PointsToSet reachingObjects(soot.PointsToSet base, SootField field) {
        return base instanceof QilinPointsToSetAdapter adapter
                ? wrap(pta.reachingObjects(adapter.delegate(), field))
                : QilinPointsToSetAdapter.empty();
    }

    @Override
    public soot.PointsToSet reachingObjects(Local local, SootField field) {
        return wrap(pta.reachingObjects(local, field));
    }

    @Override
    public soot.PointsToSet reachingObjects(Context context, Local local, SootField field) {
        return wrap(pta.reachingObjects(context, local, field));
    }

    @Override
    public soot.PointsToSet reachingObjectsOfArrayElement(soot.PointsToSet base) {
        return base instanceof QilinPointsToSetAdapter adapter
                ? wrap(pta.reachingObjectsOfArrayElement(adapter.delegate()))
                : QilinPointsToSetAdapter.empty();
    }

    private static QilinPointsToSetAdapter wrap(qilin.core.sets.PointsToSet pointsToSet) {
        return new QilinPointsToSetAdapter(pointsToSet);
    }
}
