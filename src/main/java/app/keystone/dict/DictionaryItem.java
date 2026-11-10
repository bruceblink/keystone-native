package app.keystone.dict;

public record DictionaryItem(long id, String typeCode, String value, String label, int sortOrder, boolean enabled) {}
