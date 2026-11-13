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
public class DepartmentOrmRepository implements PanacheRepositoryBase<DepartmentEntity, Long> {
    @Transactional
    public List<Department> listDepartments(DataScopeService.Scope scope) {
        return find("order by parentId, sortOrder, id").list().stream()
                .filter(department -> scope.allowsDepartment(department.id()))
                .map(DepartmentEntity::toModel).toList();
    }

    @Transactional
    public Department createDepartment(String code, String name, Long parentId, int sortOrder) {
        var department = new DepartmentEntity(code.trim(), name.trim(), parentId, sortOrder);
        persistAndFlush(department);
        return department.toModel();
    }

    @Transactional
    public Department updateDepartment(long id, String name, Long parentId, Integer sortOrder, Boolean enabled) {
        DepartmentEntity department = find("id", id).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (department == null) throw new java.util.NoSuchElementException("department not found");
        department.update(name, parentId, sortOrder, enabled);
        return department.toModel();
    }

    @Transactional
    public void deleteDepartment(long id) {
        DepartmentEntity department = find("id", id).withLock(LockModeType.PESSIMISTIC_WRITE).firstResult();
        if (department == null) throw new java.util.NoSuchElementException("department not found");
        delete(department);
    }

    @Transactional
    public Department findDepartment(long id) {
        DepartmentEntity department = findById(id);
        if (department == null) throw new java.util.NoSuchElementException("department not found");
        return department.toModel();
    }

    public List<Long> findChildIds(Set<Long> parentIds) {
        if (parentIds == null || parentIds.isEmpty()) return List.of();
        return find("parentId in ?1", parentIds).list().stream().map(DepartmentEntity::id).toList();
    }
}
