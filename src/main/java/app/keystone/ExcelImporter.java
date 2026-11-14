package app.keystone;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** 读取第一个工作表的 XLSX 内容；调用方负责表头和业务字段校验。 */
public final class ExcelImporter {
    private static final long MAX_FILE_SIZE = 50L * 1024 * 1024;

    private ExcelImporter() {
    }

    /** 校验客户端文件名和大小，再读取 Open XML 工作簿的第一张工作表。 */
    public static List<List<String>> read(Path path, String filename) {
        if (path == null || filename == null || !filename.toLowerCase(Locale.ROOT).endsWith(".xlsx")) {
            throw new IllegalArgumentException("Excel file must use the .xlsx extension");
        }
        try {
            if (!Files.isRegularFile(path) || Files.size(path) == 0 || Files.size(path) > MAX_FILE_SIZE) {
                throw new IllegalArgumentException("Excel file is missing or too large");
            }
            try (var zip = new ZipFile(path.toFile())) {
                ZipEntry sheet = zip.getEntry("xl/worksheets/sheet1.xml");
                if (sheet == null) throw new IllegalArgumentException("Excel worksheet is missing");
                List<String> sharedStrings = readSharedStrings(zip.getEntry("xl/sharedStrings.xml"), zip);
                return readRows(zip.getInputStream(sheet), sharedStrings);
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Excel workbook is invalid", e);
        }
    }

    private static List<String> readSharedStrings(ZipEntry entry, ZipFile zip) throws Exception {
        if (entry == null) return List.of();
        Document document = parse(zip.getInputStream(entry));
        NodeList values = document.getElementsByTagNameNS("*", "si");
        List<String> result = new ArrayList<>(values.getLength());
        for (int index = 0; index < values.getLength(); index++) result.add(text(values.item(index)));
        return result;
    }

    private static List<List<String>> readRows(InputStream stream, List<String> sharedStrings) throws Exception {
        Document document = parse(stream);
        NodeList rowNodes = document.getElementsByTagNameNS("*", "row");
        List<List<String>> rows = new ArrayList<>(rowNodes.getLength());
        for (int rowIndex = 0; rowIndex < rowNodes.getLength(); rowIndex++) {
            NodeList cells = ((Element) rowNodes.item(rowIndex)).getElementsByTagNameNS("*", "c");
            List<String> row = new ArrayList<>();
            for (int cellIndex = 0; cellIndex < cells.getLength(); cellIndex++) {
                Element cell = (Element) cells.item(cellIndex);
                int column = columnIndex(cell.getAttribute("r"), cellIndex);
                while (row.size() < column) row.add("");
                String value = value(cell, sharedStrings);
                if (row.size() == column) row.add(value); else row.set(column, value);
            }
            rows.add(row);
        }
        return rows;
    }

    private static String value(Element cell, List<String> sharedStrings) {
        String type = cell.getAttribute("t");
        String raw = text(first(cell, "v"));
        if ("s".equals(type)) {
            try { return sharedStrings.get(Integer.parseInt(raw)); }
            catch (RuntimeException e) { throw new IllegalArgumentException("Excel shared string is invalid", e); }
        }
        if ("inlineStr".equals(type)) return text(first(cell, "is"));
        if ("b".equals(type)) return "1".equals(raw) ? "true" : "false";
        return raw;
    }

    private static Element first(Element parent, String name) {
        NodeList nodes = parent.getElementsByTagNameNS("*", name);
        return nodes.getLength() == 0 ? null : (Element) nodes.item(0);
    }

    private static String text(Node node) {
        return node == null ? "" : node.getTextContent();
    }

    private static int columnIndex(String reference, int fallback) {
        if (reference == null || reference.isBlank()) return fallback;
        int index = 0;
        for (int cursor = 0; cursor < reference.length() && Character.isLetter(reference.charAt(cursor)); cursor++) {
            index = index * 26 + Character.toUpperCase(reference.charAt(cursor)) - 'A' + 1;
        }
        return Math.max(0, index - 1);
    }

    private static Document parse(InputStream stream) throws Exception {
        try (stream) {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            return factory.newDocumentBuilder().parse(stream);
        }
    }
}
