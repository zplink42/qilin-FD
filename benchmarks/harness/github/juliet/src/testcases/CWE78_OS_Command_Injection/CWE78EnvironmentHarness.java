package testcases.CWE78_OS_Command_Injection;

public final class CWE78EnvironmentHarness {
    private CWE78EnvironmentHarness() {
    }

    public static void main(String[] args) throws Throwable {
        new CWE78_OS_Command_Injection__Environment_01().bad();
    }
}
