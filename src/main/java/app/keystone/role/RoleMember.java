package app.keystone.role;

/** 角色成员查询的最小身份字段，不包含联系方式或账号状态。 */
public record RoleMember(String id, String username, String displayName) {}
