package app.keystone.role;

import app.keystone.ExcelExporter;
import java.util.List;

/** 将角色基础信息编码为 Excel；不导出任何凭据或秘密。 */
public final class RoleExcelExporter {
    private static final List<String> HEADERS = List.of("角色ID", "角色标识", "角色名称", "启用", "数据范围", "部门范围", "权限");

    private RoleExcelExporter() {
    }

    public static byte[] export(List<Role> roles) {
        return ExcelExporter.export(HEADERS, (roles == null ? List.<Role>of() : roles).stream()
                .map(role -> java.util.Arrays.asList(role.id(), role.code(), role.name(), role.enabled(), role.dataScope(), role.deptScope(),
                        role.permissions() == null ? null : String.join("|", role.permissions())))
                .toList());
    }
}
