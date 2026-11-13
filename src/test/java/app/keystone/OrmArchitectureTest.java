package app.keystone;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;

/** 保证业务仓储统一使用 ORM，不重新引入直接 JDBC 访问。 */
class OrmArchitectureTest {
    @Test
    void mainSourcesDoNotUseDirectJdbc() throws Exception {
        try (var files = Files.walk(Path.of("src/main/java"))) {
            files.filter(path -> path.toString().endsWith(".java")).forEach(path -> {
                try {
                    String source = Files.readString(path);
                    assertFalse(source.contains("DataSource"), path + " must not inject DataSource");
                    assertFalse(source.contains("PreparedStatement"), path + " must not use PreparedStatement");
                    assertFalse(source.contains("prepareStatement"), path + " must not call prepareStatement");
                    assertFalse(source.contains("java.sql.Connection"), path + " must not depend on JDBC Connection");
                } catch (java.io.IOException e) {
                    throw new IllegalStateException("Could not inspect " + path, e);
                }
            });
        }
    }
}
