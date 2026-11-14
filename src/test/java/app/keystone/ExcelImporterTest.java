package app.keystone;

import app.keystone.user.UserExcelImporter;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 验证用户导入只接受 XLSX，并在解析阶段完成表头和字段类型校验。 */
class ExcelImporterTest {
    @Test
    void readsUserRecordsFromOpenXmlWorkbook() throws Exception {
        Path path = Files.createTempFile("keystone-user-import-", ".xlsx");
        try {
            Files.write(path, ExcelExporter.export(
                    List.of("部门ID", "用户名", "昵称", "密码", "状态", "性别"),
                    List.of(List.of("", "imported", "导入用户", "password", true, 1))));
            var records = UserExcelImporter.read(path, "users.xlsx");
            assertEquals(1, records.size());
            assertEquals("imported", records.get(0).username());
            assertEquals(true, records.get(0).enabled());
            assertEquals(1, records.get(0).sex());
        } finally {
            Files.deleteIfExists(path);
        }
    }

    @Test
    void rejectsNonXlsxAndIncompleteHeaders() throws Exception {
        Path path = Files.createTempFile("keystone-user-import-", ".xlsx");
        try {
            Files.write(path, ExcelExporter.export(List.of("用户名"), List.of(List.of("only-name"))));
            assertThrows(IllegalArgumentException.class, () -> UserExcelImporter.read(path, "users.csv"));
            assertThrows(IllegalArgumentException.class, () -> UserExcelImporter.read(path, "users.xls"));
            assertThrows(IllegalArgumentException.class, () -> UserExcelImporter.read(path, "users.xlsx"));
        } finally {
            Files.deleteIfExists(path);
        }
    }
}
