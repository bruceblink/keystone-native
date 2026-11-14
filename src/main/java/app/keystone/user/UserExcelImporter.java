package app.keystone.user;

import app.keystone.ExcelImporter;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** 将用户导入工作表转换为已校验的业务记录，不接触数据库和权限状态。 */
public final class UserExcelImporter {
    private static final List<String> HEADERS = List.of(
            "部门ID", "用户名", "昵称", "邮件", "电话号码", "性别", "头像", "密码", "状态", "角色ID", "职位ID", "备注");

    private UserExcelImporter() {
    }

    public static List<Record> read(Path path, String filename) {
        List<List<String>> rows = ExcelImporter.read(path, filename);
        if (rows.isEmpty()) throw new IllegalArgumentException("Excel worksheet is empty");
        Map<String, Integer> indexes = headers(rows.get(0));
        List<Record> records = new ArrayList<>();
        for (int row = 1; row < rows.size(); row++) {
            List<String> values = rows.get(row);
            if (values.stream().allMatch(value -> value == null || value.isBlank())) continue;
            records.add(new Record(row + 1, value(values, indexes, "用户名"), value(values, indexes, "密码"),
                    value(values, indexes, "昵称"), value(values, indexes, "部门ID"), value(values, indexes, "职位ID"),
                    value(values, indexes, "邮件"), value(values, indexes, "电话号码"), integer(values, indexes, "性别"),
                    value(values, indexes, "头像"), enabled(values, indexes), roleIds(values, indexes), value(values, indexes, "备注")));
        }
        return records;
    }

    private static Map<String, Integer> headers(List<String> values) {
        Map<String, Integer> indexes = new LinkedHashMap<>();
        for (int index = 0; index < values.size(); index++) {
            String header = values.get(index) == null ? "" : values.get(index).trim();
            if (!HEADERS.contains(header) || indexes.put(header, index) != null) throw new IllegalArgumentException("Excel headers are invalid");
        }
        if (!indexes.keySet().containsAll(List.of("用户名", "昵称", "密码"))) throw new IllegalArgumentException("Excel headers are incomplete");
        return indexes;
    }

    private static String value(List<String> row, Map<String, Integer> indexes, String header) {
        Integer index = indexes.get(header);
        return index == null || index >= row.size() ? null : blankToNull(row.get(index));
    }

    private static Integer integer(List<String> row, Map<String, Integer> indexes, String header) {
        String value = value(row, indexes, header);
        if (value == null) return null;
        try { return Integer.valueOf(value); }
        catch (NumberFormatException e) { throw new IllegalArgumentException(header + " must be an integer", e); }
    }

    private static Boolean enabled(List<String> row, Map<String, Integer> indexes) {
        String value = value(row, indexes, "状态");
        if (value == null) return true;
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "1", "true", "启用" -> true;
            case "0", "false", "禁用" -> false;
            default -> throw new IllegalArgumentException("状态 must be true, false, 1 or 0");
        };
    }

    private static List<String> roleIds(List<String> row, Map<String, Integer> indexes) {
        String value = value(row, indexes, "角色ID");
        if (value == null) return List.of();
        List<String> result = new ArrayList<>();
        for (String item : value.split("[,;|\\s]+")) result.add(item);
        return List.copyOf(result);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    public record Record(int row, String username, String password, String displayName, String deptId, String postId,
                         String email, String phoneNumber, Integer sex, String avatar, Boolean enabled,
                         List<String> roleIds, String remark) {
    }
}
