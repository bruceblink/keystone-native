package app.keystone.auth;

import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.UUID;

/** 使用 Panache 管理服务主体查询和创建。 */
@ApplicationScoped
public class ServiceSubjectRepository implements PanacheRepositoryBase<ServiceSubjectEntity, UUID> {

    ServiceSubjectEntity findByCode(String code) {
        return find("code", code).firstResult();
    }
}
