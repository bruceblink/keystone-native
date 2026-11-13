package app.keystone.dept;

import app.keystone.auth.DataScopeService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;

/** 部门管理入口；具体持久化由 ORM 仓储负责。 */
@ApplicationScoped
public class DepartmentRepository {
    @Inject DepartmentOrmRepository ormDepartments;

    public List<Department> list() {
        return list(DataScopeService.Scope.unrestricted());
    }

    public List<Department> list(DataScopeService.Scope scope) {
        return ormDepartments.listDepartments(scope);
    }

    public Department create(String code, String name, Long parentId, Integer sortOrder) {
        if (code == null || code.isBlank() || name == null || name.isBlank()) {
            throw new IllegalArgumentException("code and name are required");
        }
        try {
            return ormDepartments.createDepartment(code, name, parentId, sortOrder == null ? 0 : sortOrder);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            if (isConstraint(e)) throw new IllegalArgumentException("department code already exists or parent does not exist", e);
            throw new IllegalStateException("Could not create department", e);
        }
    }

    public Department update(long id, String name, Long parentId, Integer sortOrder, Boolean enabled) {
        if (parentId != null && parentId == id) throw new IllegalArgumentException("department cannot be its own parent");
        try {
            return ormDepartments.updateDepartment(id, name, parentId, sortOrder, enabled);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            if (isConstraint(e)) throw new IllegalArgumentException("parent department does not exist", e);
            throw new IllegalStateException("Could not update department", e);
        }
    }

    public void delete(long id) {
        try {
            ormDepartments.deleteDepartment(id);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            if (isConstraint(e)) throw new IllegalArgumentException("department has child departments", e);
            throw new IllegalStateException("Could not delete department", e);
        }
    }

    private static boolean isConstraint(Throwable error) {
        for (Throwable current = error; current != null; current = current.getCause()) {
            String name = current.getClass().getSimpleName().toLowerCase(java.util.Locale.ROOT);
            String message = String.valueOf(current.getMessage()).toLowerCase(java.util.Locale.ROOT);
            if (name.contains("constraint") || message.contains("duplicate") || message.contains("foreign key")) return true;
        }
        return false;
    }
}
