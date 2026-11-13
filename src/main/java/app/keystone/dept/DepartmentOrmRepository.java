package app.keystone.dept;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.List;
import java.util.Set;

/** 使用 Panache 读取部门树的子节点，避免数据范围服务直接访问 JDBC。 */
@ApplicationScoped
public class DepartmentOrmRepository implements PanacheRepositoryBase<DepartmentEntity, Long> {
    public List<Long> findChildIds(Set<Long> parentIds) {
        if (parentIds == null || parentIds.isEmpty()) return List.of();
        return find("parentId in ?1", parentIds).list().stream().map(DepartmentEntity::id).toList();
    }
}
