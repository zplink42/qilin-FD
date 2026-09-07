package dev.qilinfd.bridge.flowdroid;

import soot.Body;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

/**
 * Supplies stable statement owners when FlowDroid consumes a call graph that
 * was built before the FlowDroid phase.
 */
public final class QilinJimpleBasedICFG
        extends JimpleBasedInterproceduralCFG {
    private final Map<Unit, Body> fallbackOwners = new IdentityHashMap<>();

    public QilinJimpleBasedICFG(
            boolean enableExceptions, boolean includeReflectiveCalls) {
        super(enableExceptions, includeReflectiveCalls);
    }

    public void registerBody(Body body) {
        if (body == null) {
            return;
        }
        initializeUnitToOwner(body);
        for (Unit unit : body.getUnits()) {
            fallbackOwners.put(unit, body);
        }
    }

    @Override
    public Body getBodyOf(Unit unit) {
        Body body = super.getBodyOf(unit);
        return body != null ? body : fallbackOwners.get(unit);
    }

    @Override
    public SootMethod getMethodOf(Unit unit) {
        SootMethod method = super.getMethodOf(unit);
        if (method != null) {
            return method;
        }
        Body body = fallbackOwners.get(unit);
        return body == null ? null : body.getMethod();
    }

    @Override
    public boolean isExitStmt(Unit unit) {
        return getMethodOf(unit) != null && super.isExitStmt(unit);
    }

    @Override
    public boolean isStartPoint(Unit unit) {
        return getMethodOf(unit) != null && super.isStartPoint(unit);
    }

    @Override
    public List<Unit> getSuccsOf(Unit unit) {
        return getMethodOf(unit) == null
                ? Collections.emptyList()
                : super.getSuccsOf(unit);
    }

    @Override
    public List<Unit> getPredsOf(Unit unit) {
        return getMethodOf(unit) == null
                ? Collections.emptyList()
                : super.getPredsOf(unit);
    }

    @Override
    public List<Unit> getPredsOfCallAt(Unit unit) {
        return getMethodOf(unit) == null
                ? Collections.emptyList()
                : super.getPredsOfCallAt(unit);
    }

    @Override
    public List<Value> getParameterRefs(SootMethod method) {
        return method == null
                ? Collections.emptyList()
                : super.getParameterRefs(method);
    }
}
