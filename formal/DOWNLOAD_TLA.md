# Running the TLA+ model

The TLC model checker (`tla2tools.jar`, ~2.3 MB) is **not bundled** here to avoid
redistributing a third-party binary. Download it once from the official TLA+ tools
releases:

```bash
# https://github.com/tlaplus/tlaplus/releases  (file: tla2tools.jar)
curl -L -o tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
```

Requires a Java runtime (JRE 11+). Then, from this `formal/` directory:

```bash
java -jar tla2tools.jar -config MA_content.cfg      MemAuthority.tla   # T1 content  -> VIOLATED (witness trace)
java -jar tla2tools.jar -config MA_lineage.cfg      MemAuthority.tla   # T1 lineage  -> VIOLATED
java -jar tla2tools.jar -config MA_nonmalleable.cfg MemAuthority.tla   # T3 non-malleable -> HOLDS (no error)
java -jar tla2tools.jar -config MA_ind.cfg          MemAuthority.tla   # inductive invariant -> inductive (no error)

java -jar tla2tools.jar -config MemoryInvariants.cfg           MemoryInvariants.tla  # proof (Binding=TRUE)
java -jar tla2tools.jar -config MemoryInvariants_necessity.cfg MemoryInvariants.tla  # necessity (Binding=FALSE) -> VIOLATED
```
