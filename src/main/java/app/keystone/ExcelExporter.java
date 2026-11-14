package app.keystone;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** 生成最小的 Open XML 工作簿；调用方必须先完成权限和数据范围查询。 */
public final class ExcelExporter {
    public static final String CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

    private ExcelExporter() {
    }

    /** 输出包含一个工作表的真实 XLSX 文件，不引入额外运行时依赖。 */
    public static byte[] export(List<String> headers, List<? extends List<?>> rows) {
        try {
            var output = new ByteArrayOutputStream();
            try (var zip = new ZipOutputStream(output, StandardCharsets.UTF_8)) {
                entry(zip, "[Content_Types].xml", contentTypes());
                entry(zip, "_rels/.rels", rootRelationships());
                entry(zip, "xl/workbook.xml", workbook());
                entry(zip, "xl/_rels/workbook.xml.rels", workbookRelationships());
                entry(zip, "xl/worksheets/sheet1.xml", worksheet(headers, rows));
            }
            return output.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Could not create Excel workbook", e);
        }
    }

    private static void entry(ZipOutputStream zip, String name, String content) throws IOException {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(content.getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
    }

    private static String worksheet(List<String> headers, List<? extends List<?>> rows) {
        var safeHeaders = headers == null ? List.<String>of() : headers;
        var safeRows = rows == null ? List.<List<?>>of() : rows;
        int columnCount = safeHeaders.size();
        for (List<?> row : safeRows) columnCount = Math.max(columnCount, row == null ? 0 : row.size());
        int rowCount = safeRows.size() + 1;
        String lastColumn = columnCount == 0 ? "A" : columnName(columnCount);
        var xml = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>")
                .append("<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">")
                .append("<dimension ref=\"A1:").append(lastColumn).append(rowCount).append("\"/><sheetData>");
        appendRow(xml, 1, safeHeaders);
        for (int index = 0; index < safeRows.size(); index++) appendRow(xml, index + 2, safeRows.get(index));
        return xml.append("</sheetData></worksheet>").toString();
    }

    private static void appendRow(StringBuilder xml, int rowNumber, List<?> values) {
        xml.append("<row r=\"").append(rowNumber).append("\">");
        List<?> safeValues = values == null ? List.of() : values;
        for (int index = 0; index < safeValues.size(); index++) {
            String reference = columnName(index + 1) + rowNumber;
            Object value = safeValues.get(index);
            if (value instanceof Number number && !(value instanceof Float) && !(value instanceof Double)) {
                xml.append("<c r=\"").append(reference).append("\"><v>")
                        .append(number).append("</v></c>");
            } else if (value instanceof Boolean bool) {
                xml.append("<c r=\"").append(reference).append("\" t=\"b\"><v>")
                        .append(bool ? '1' : '0').append("</v></c>");
            } else {
                String text = value == null ? "" : value instanceof Instant instant ? instant.toString() : String.valueOf(value);
                xml.append("<c r=\"").append(reference).append("\" t=\"inlineStr\"><is><t xml:space=\"preserve\">")
                        .append(xml(text)).append("</t></is></c>");
            }
        }
        xml.append("</row>");
    }

    private static String columnName(int number) {
        var result = new StringBuilder();
        for (int value = number; value > 0; value = (value - 1) / 26) {
            result.append((char) ('A' + (value - 1) % 26));
        }
        return result.reverse().toString();
    }

    private static String xml(String value) {
        var result = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == '&') result.append("&amp;");
            else if (character == '<') result.append("&lt;");
            else if (character == '>') result.append("&gt;");
            else if (character == '"') result.append("&quot;");
            else if (character == '\'') result.append("&apos;");
            else if (character == '\t' || character == '\n' || character == '\r' || character >= 0x20) result.append(character);
        }
        return result.toString();
    }

    private static String contentTypes() {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
                + "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
                + "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
                + "<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>"
                + "<Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>"
                + "</Types>";
    }

    private static String rootRelationships() {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
                + "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>";
    }

    private static String workbook() {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets><sheet name=\"数据\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>";
    }

    private static String workbookRelationships() {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/></Relationships>";
    }
}
