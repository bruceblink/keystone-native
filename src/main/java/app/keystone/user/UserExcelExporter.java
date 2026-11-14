package app.keystone.user;

import app.keystone.ExcelExporter;
import java.util.List;

/** 将已经通过数据范围查询的用户记录编码为 Excel 工作簿。 */
public final class UserExcelExporter {
    private static final List<String> HEADERS = List.of(
            "用户ID", "用户名", "显示名称", "部门ID", "岗位ID", "启用", "邮箱", "手机号", "性别", "最后登录时间", "备注", "角色");

    private UserExcelExporter() {
    }

    /** 输出用户业务字段；密码、令牌和认证哈希不属于导出内容。 */
    public static byte[] export(List<User> users) {
        return ExcelExporter.export(HEADERS, (users == null ? List.<User>of() : users).stream()
                .map(user -> java.util.Arrays.asList(user.id(), user.username(), user.displayName(), user.deptId(), user.postId(),
                        user.enabled(), user.email(), user.phoneNumber(), user.sex(), user.loginAt(), user.remark(),
                        user.roles() == null ? null : String.join("|", user.roles())))
                .toList());
    }
}
