package app.keystone.user;

import java.time.Instant;
import java.util.List;
import java.util.StringJoiner;

/** 将已经通过数据范围查询的用户记录编码为 UTF-8 CSV。 */
public final class UserCsvExporter {
    private static final String HEADER = "用户ID,用户名,显示名称,部门ID,岗位ID,启用,邮箱,手机号,性别,最后登录时间,备注,角色";

    private UserCsvExporter() {
    }

    /** 输出带 BOM 的 CSV，便于常见表格工具正确识别中文；输入记录不包含密码或令牌。 */
    public static String export(List<User> users) {
        var csv = new StringBuilder("\uFEFF").append(HEADER).append('\n');
        for (User user : users == null ? List.<User>of() : users) {
            var row = new StringJoiner(",");
            row.add(value(user.id())).add(value(user.username())).add(value(user.displayName()))
                    .add(value(user.deptId())).add(value(user.postId())).add(value(user.enabled()))
                    .add(value(user.email())).add(value(user.phoneNumber())).add(value(user.sex()))
                    .add(value(user.loginAt())).add(value(user.remark()))
                    .add(value(user.roles() == null ? null : String.join("|", user.roles())));
            csv.append(row).append('\n');
        }
        return csv.toString();
    }

    private static String value(Object value) {
        if (value == null) return "";
        if (value instanceof Instant instant) return csv(instant.toString());
        return csv(String.valueOf(value));
    }

    private static String csv(String value) {
        if (value.indexOf(',') >= 0 || value.indexOf('"') >= 0 || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            return '"' + value.replace("\"", "\"\"") + '"';
        }
        return value;
    }
}
