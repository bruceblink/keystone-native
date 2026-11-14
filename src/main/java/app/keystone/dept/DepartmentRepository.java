package app.keystone.dept;

import app.keystone.auth.DataScopeService;
import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;

/** 部门管理入口；具体持久化由 ORM 仓储负责。 */
@ApplicationScoped
public class DepartmentRepository {
    @Inject DepartmentOrmRepository ormDepartments;
    @Inject AuthorizationService authorization;

    /** 部门查询和写入统一在应用命令边界执行权限与范围检查。 */
    public List<Department> list(AuthorizationContext context) {
        authorization.require(context, "department:read", "department");
        return ormDepartments.listDepartments(context.scope());
    }

    private List<Department> list() {
        return list(DataScopeService.Scope.unrestricted());
    }

    private List<Department> list(DataScopeService.Scope scope) {
        return ormDepartments.listDepartments(scope);
    }

    private Department create(String code, String name, String parentId, Integer sortOrder) {
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

    public Department create(AuthorizationContext context, String code, String name, String parentId, Integer sortOrder) {
        authorization.require(context, "department:create", "department");
        if (!context.scope().allowsDepartmentCreation(parentId)) throw denied();
        return create(code, name, parentId, sortOrder);
    }

    private Department update(String id, String name, String parentId, Integer sortOrder, Boolean enabled) {
        if (parentId != null && parentId.equals(id)) throw new IllegalArgumentException("department cannot be its own parent");
        try {
            return ormDepartments.updateDepartment(id, name, parentId, sortOrder, enabled);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            if (isConstraint(e)) throw new IllegalArgumentException("parent department does not exist", e);
            throw new IllegalStateException("Could not update department", e);
        }
    }

    public Department update(AuthorizationContext context, String id, String name, String parentId, Integer sortOrder, Boolean enabled) {
        authorization.require(context, "department:update", "department");
        if (!context.scope().allowsDepartmentUpdate(id, parentId)) throw denied();
        return update(id, name, parentId, sortOrder, enabled);
    }

    private void delete(String id) {
        try {
            ormDepartments.deleteDepartment(id);
        } catch (java.util.NoSuchElementException | IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            if (isConstraint(e)) throw new IllegalArgumentException("department has child departments", e);
            throw new IllegalStateException("Could not delete department", e);
        }
    }

    public void delete(AuthorizationContext context, String id) {
        authorization.require(context, "department:delete", "department");
        if (!context.scope().allowsDepartment(id)) throw denied();
        delete(id);
    }

    private static app.keystone.auth.AuthorizationDeniedException denied() {
        return new app.keystone.auth.AuthorizationDeniedException("data_scope_denied", 403, "data scope does not allow this department");
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
