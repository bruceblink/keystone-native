package app.keystone.compat;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.util.List;

public final class CsvExport {
    private CsvExport() {}
    public static Response response(String fileName, List<String[]> rows) {
        StringBuilder csv = new StringBuilder("\uFEFF");
        for (String[] row : rows) { for (int i = 0; i < row.length; i++) { if (i > 0) csv.append(','); csv.append(escape(row[i])); } csv.append('\n'); }
        return Response.ok(csv.toString().getBytes(StandardCharsets.UTF_8), "text/csv; charset=UTF-8").header("Content-Disposition", "attachment; filename=\"" + fileName + "\"").build();
    }
    private static String escape(String value) { if (value == null) return ""; String text = value.replace("\"", "\"\""); return text.indexOf(',') >= 0 || text.indexOf('\n') >= 0 || text.indexOf('\"') >= 0 ? "\"" + text + "\"" : text; }
}
