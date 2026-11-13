package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;

/** 使用 Panache 管理服务主体查询和创建。 */
@ApplicationScoped
public class ServiceSubjectRepository implements PanacheRepositoryBase<ServiceSubjectEntity, String> {

    ServiceSubjectEntity findByCode(String code) {
        return find("code", code).firstResult();
    }
}
