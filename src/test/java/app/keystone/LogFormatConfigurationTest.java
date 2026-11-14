package app.keystone;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

class LogFormatConfigurationTest {
    /** 验证生产控制台日志包含完整日期和时间，便于跨天检索和事件排序。 */
    @Test
    void consoleLogFormatIncludesDate() throws Exception {
        String properties = Files.readString(Path.of("src/main/resources/application.properties"));
        assertTrue(properties.contains("quarkus.log.console.format=%d{yyyy-MM-dd HH:mm:ss}"));
    }
}
