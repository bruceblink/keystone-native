package app.keystone.post;

import app.keystone.ExcelExporter;
import java.util.List;

/** 将岗位基础信息编码为 Excel；不导出认证秘密。 */
public final class PostExcelExporter {
    private static final List<String> HEADERS = List.of("岗位ID", "岗位标识", "岗位名称", "排序", "启用");

    private PostExcelExporter() {
    }

    public static byte[] export(List<Post> posts) {
        return ExcelExporter.export(HEADERS, (posts == null ? List.<Post>of() : posts).stream()
                .map(post -> List.of(post.id(), post.code(), post.name(), post.sortOrder(), post.enabled()))
                .toList());
    }
}
