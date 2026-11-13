package app.keystone.dict;

public record DictionaryItem(String id, String typeCode, String value, String label, int sortOrder, boolean enabled) {}
