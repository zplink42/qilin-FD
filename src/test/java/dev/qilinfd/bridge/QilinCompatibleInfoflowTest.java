package dev.qilinfd.bridge;

import org.junit.jupiter.api.Test;
import soot.Local;
import soot.RefType;
import soot.jimple.Jimple;
import soot.jimple.JimpleBody;
import soot.jimple.NullConstant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QilinCompatibleInfoflowTest {
    @Test
    void declaresLocalsReferencedByStatementsBeforeFlowDroidSplitsTheBody() {
        JimpleBody body = Jimple.v().newBody();
        Local missingLocal = Jimple.v().newLocal("missing", RefType.v("java.lang.Object"));
        body.getUnits().add(Jimple.v().newAssignStmt(missingLocal, NullConstant.v()));

        assertEquals(0, body.getLocals().size());
        assertEquals(1, QilinCompatibleInfoflow.declareMissingLocals(body));
        assertTrue(body.getLocals().contains(missingLocal));
        assertEquals(0, QilinCompatibleInfoflow.declareMissingLocals(body));
    }
}
