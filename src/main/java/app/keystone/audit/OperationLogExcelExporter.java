package app.keystone.audit;

import app.keystone.ExcelExporter;
import java.util.List;

/** 将操作审计的非敏感索引字段编码为 Excel；详细载荷不进入导出文件。 */
public final class OperationLogExcelExporter {
    private static final List<String> HEADERS = List.of("日志ID", "操作主体", "动作", "资源", "资源ID", "创建时间");

    private OperationLogExcelExporter() {
    }

    public static byte[] export(List<OperationLog> logs) {
        return ExcelExporter.export(HEADERS, (logs == null ? List.<OperationLog>of() : logs).stream()
                .map(log -> java.util.Arrays.asList(log.id(), log.actorUsername(), log.action(), log.resource(), log.resourceId(), log.createdAt()))
                .toList());
    }
}
