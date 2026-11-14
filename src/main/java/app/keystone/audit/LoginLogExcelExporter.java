package app.keystone.audit;

import app.keystone.ExcelExporter;
import java.util.List;

/** 将登录日志的审计字段编码为 Excel；消息正文不进入导出文件。 */
public final class LoginLogExcelExporter {
    private static final List<String> HEADERS = List.of("日志ID", "用户名", "状态", "IP地址", "用户代理", "登录时间");

    private LoginLogExcelExporter() {
    }

    public static byte[] export(List<LoginLog> logs) {
        return ExcelExporter.export(HEADERS, (logs == null ? List.<LoginLog>of() : logs).stream()
                .map(log -> java.util.Arrays.asList(log.id(), log.username(), log.status(), log.ipAddress(), log.userAgent(), log.loginAt()))
                .toList());
    }
}
