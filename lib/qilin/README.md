# Qilin Analysis JARs

This directory holds classic-Soot Qilin JARs that may be selected as the
pointer-analysis provider for `qilin-FD`.

The default JAR is `Qilin-0.10.10.3-SNAPSHOT.jar`, built from
`D:\gitdesk\qilin-generics` with classic Soot 4.6.0. To evaluate another
compatible Qilin build, place its JAR here and run Gradle with, for example:

```powershell
.\gradlew.bat verifySmokeQilin -PqilinJar=lib/qilin/Qilin-my-optimization.jar
```

The replacement JAR must retain the `qilin.core.PTA` query boundary and the
`driver.Main.run(String[])` launch hook used by the bridge, and must expose
classic `soot.*` types compatible with FlowDroid.
