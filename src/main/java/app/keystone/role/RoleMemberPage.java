package app.keystone.role;

import java.util.List;

/** 角色成员分页响应，保留 Native 管理列表使用的分页字段。 */
public record RoleMemberPage<T>(List<T> items, int page, int size, long total) {}
