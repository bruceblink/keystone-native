package app.keystone.dept;

import app.keystone.auth.DataScopeService;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import java.util.List;
import java.util.Set;

/** 使用 Panache 读取部门树的子节点，避免数据范围服务直接访问 JDBC。 */
@ApplicationScoped
public class DepartmentOrmRepository implements PanacheRepositoryBase<DepartmentEntity, java.util.UUID> {
    @Transactional
    public List<Department> listDepartments(DataScopeService.Scope scope) {
        return find("order by parentId, sortOrder, id").list().stream()
                .filter(department -> scope.allowsDepartment(department.id()))
                .map(DepartmentEntity::toModel).toList();
    }

    @Transactional
    public Department createDepartment(String code, String name, String parentId, int sortOrder) {
        var department = new DepartmentEntity(code.trim(), name.trim(), parentId, sortOrder);
        persistAndFlush(department);
        return department.toModel();
    }

    @Transactional
    public Department updateDepartment(String id, String name, String parentId, Integer sortOrder, Boolean enabled) {
        DepartmentEntity department = find("id", app.keystone.identity.UuidValues.parse(id)).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (department == null) throw new java.util.NoSuchElementException("department not found");
        department.update(name, parentId, sortOrder, enabled);
        return department.toModel();
    }

    @Transactional
    public void deleteDepartment(String id) {
        DepartmentEntity department = find("id", app.keystone.identity.UuidValues.parse(id)).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (department == null) throw new java.util.NoSuchElementException("department not found");
        delete(department);
    }

    @Transactional
    public Department findDepartment(String id) {
        DepartmentEntity department = findById(app.keystone.identity.UuidValues.parse(id));
        if (department == null) throw new java.util.NoSuchElementException("department not found");
        return department.toModel();
    }

    public List<String> findChildIds(Set<String> parentIds) {
        if (parentIds == null || parentIds.isEmpty()) return List.of();
        return find("parentId in ?1", parentIds.stream().map(app.keystone.identity.UuidValues::parse).toList()).list().stream().map(DepartmentEntity::id).toList();
    }
}
