package app.keystone.dict;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

@ApplicationScoped
public class DictionaryRepository {
    @Inject DataSource dataSource;

    public List<DictionaryType> types() {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("SELECT id, code, name, enabled FROM sys_dict_type ORDER BY code"); var rs = p.executeQuery()) {
            var result = new ArrayList<DictionaryType>(); while (rs.next()) result.add(new DictionaryType(rs.getLong("id"), rs.getString("code"), rs.getString("name"), rs.getBoolean("enabled"))); return result;
        } catch (Exception e) { throw new IllegalStateException("Could not list dictionary types", e); }
    }

    public List<DictionaryItem> items(String typeCode) {
        String sql = "SELECT i.id, t.code type_code, i.item_value, i.item_label, i.sort_order, i.enabled FROM sys_dict_item i JOIN sys_dict_type t ON t.id = i.type_id WHERE t.code = ? AND t.enabled = true ORDER BY i.sort_order, i.id";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) { p.setString(1, typeCode); try (var rs = p.executeQuery()) { var result = new ArrayList<DictionaryItem>(); while (rs.next()) result.add(item(rs)); return result; } }
        catch (Exception e) { throw new IllegalStateException("Could not list dictionary items", e); }
    }

    public DictionaryType createType(String code, String name) {
        require(code, "code"); require(name, "name");
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("INSERT INTO sys_dict_type(code, name) VALUES (?, ?)", java.sql.Statement.RETURN_GENERATED_KEYS)) { p.setString(1, code.trim()); p.setString(2, name.trim()); p.executeUpdate(); try (var keys = p.getGeneratedKeys()) { keys.next(); return findType(c, keys.getLong(1)); } }
        catch (java.sql.SQLIntegrityConstraintViolationException e) { throw new IllegalArgumentException("dictionary type code already exists", e); }
        catch (Exception e) { throw new IllegalStateException("Could not create dictionary type", e); }
    }

    public DictionaryItem createItem(String typeCode, String value, String label, Integer sortOrder) {
        require(typeCode, "typeCode"); require(value, "value"); require(label, "label");
        try (var c = dataSource.getConnection()) {
            long typeId = typeId(c, typeCode);
            try (var p = c.prepareStatement("INSERT INTO sys_dict_item(type_id, item_value, item_label, sort_order) VALUES (?, ?, ?, ?)", java.sql.Statement.RETURN_GENERATED_KEYS)) { p.setLong(1, typeId); p.setString(2, value.trim()); p.setString(3, label.trim()); p.setInt(4, sortOrder == null ? 0 : sortOrder); p.executeUpdate(); try (var keys = p.getGeneratedKeys()) { keys.next(); return findItem(c, keys.getLong(1)); } }
        } catch (java.sql.SQLIntegrityConstraintViolationException e) { throw new IllegalArgumentException("dictionary item value already exists", e); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not create dictionary item", e); }
    }

    public void deleteItem(long id) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_dict_item WHERE id = ?")) { p.setLong(1, id); if (p.executeUpdate() == 0) throw new java.util.NoSuchElementException("dictionary item not found"); }
        catch (java.util.NoSuchElementException e) { throw e; }
        catch (Exception e) { throw new IllegalStateException("Could not delete dictionary item", e); }
    }

    private static void require(String value, String field) { if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " is required"); }
    private static long typeId(java.sql.Connection c, String code) throws Exception { try (var p = c.prepareStatement("SELECT id FROM sys_dict_type WHERE code = ? AND enabled = true")) { p.setString(1, code); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("dictionary type not found"); return rs.getLong(1); } } }
    private static DictionaryType findType(java.sql.Connection c, long id) throws Exception { try (var p = c.prepareStatement("SELECT id, code, name, enabled FROM sys_dict_type WHERE id = ?")) { p.setLong(1, id); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("dictionary type not found"); return new DictionaryType(rs.getLong("id"), rs.getString("code"), rs.getString("name"), rs.getBoolean("enabled")); } } }
    private static DictionaryItem findItem(java.sql.Connection c, long id) throws Exception { try (var p = c.prepareStatement("SELECT i.id, t.code type_code, i.item_value, i.item_label, i.sort_order, i.enabled FROM sys_dict_item i JOIN sys_dict_type t ON t.id = i.type_id WHERE i.id = ?")) { p.setLong(1, id); try (var rs = p.executeQuery()) { if (!rs.next()) throw new java.util.NoSuchElementException("dictionary item not found"); return item(rs); } } }
    private static DictionaryItem item(ResultSet rs) throws Exception { return new DictionaryItem(rs.getLong("id"), rs.getString("type_code"), rs.getString("item_value"), rs.getString("item_label"), rs.getInt("sort_order"), rs.getBoolean("enabled")); }
}
