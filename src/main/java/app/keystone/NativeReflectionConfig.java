package app.keystone;

import app.keystone.audit.LoginLog;
import app.keystone.audit.LoginLogRepository;
import app.keystone.audit.OperationLog;
import app.keystone.audit.OperationLogRepository;
import app.keystone.auth.AuthResource;
import app.keystone.auth.ApiKeyRepository;
import app.keystone.auth.ApiKeyResource;
import app.keystone.auth.ApiKeyAuthenticationRequest;
import app.keystone.auth.SessionRepository;
import app.keystone.config.SystemConfig;
import app.keystone.config.SystemConfigResource;
import app.keystone.dept.Department;
import app.keystone.dept.DepartmentResource;
import app.keystone.dict.DictionaryItem;
import app.keystone.dict.DictionaryResource;
import app.keystone.dict.DictionaryType;
import app.keystone.job.Job;
import app.keystone.job.JobInvocationService;
import app.keystone.job.JobLog;
import app.keystone.job.JobLogRepository;
import app.keystone.job.JobResource;
import app.keystone.menu.Menu;
import app.keystone.menu.MenuNode;
import app.keystone.menu.MenuRepository;
import app.keystone.notice.Notice;
import app.keystone.notice.NoticeResource;
import app.keystone.post.Post;
import app.keystone.post.PostResource;
import app.keystone.profile.ProfileResource;
import app.keystone.role.Role;
import app.keystone.role.RoleResource;
import app.keystone.user.User;
import app.keystone.user.UserRepository;
import app.keystone.user.UserResource;
import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection(targets = {
        ApiResponse.class, HealthResource.Health.class,
        AuthResource.LoginRequest.class, AuthResource.RefreshRequest.class, AuthResource.InitialPasswordRequest.class, AuthResource.TokenResponse.class,
        ApiKeyRepository.IssuedApiKey.class, ApiKeyResource.Request.class,
        ApiKeyRepository.ApiKeyMetadata.class, ApiKeyAuthenticationRequest.class,
        User.class, UserRepository.AuthUser.class, UserRepository.Page.class,
        UserResource.UserRequest.class, UserResource.PasswordRequest.class, UserResource.StatusRequest.class,
        Role.class, RoleResource.RoleRequest.class, RoleResource.PermissionRequest.class,
        Menu.class, MenuNode.class, MenuRepository.MenuRequest.class,
        Department.class, DepartmentResource.DepartmentRequest.class,
        DictionaryType.class, DictionaryItem.class, DictionaryResource.TypeRequest.class, DictionaryResource.ItemRequest.class,
        SystemConfig.class, SystemConfigResource.ConfigRequest.class,
        Notice.class, NoticeResource.NoticeRequest.class, NoticeResource.PublishRequest.class,
        Post.class, PostResource.PostRequest.class,
        Job.class, JobLog.class, JobLogRepository.Page.class, JobInvocationService.JobTarget.class, JobResource.JobRequest.class, JobResource.StatusRequest.class,
        SessionRepository.OnlineSession.class, OperationLog.class, OperationLogRepository.Page.class, LoginLog.class, LoginLogRepository.Page.class,
        ProfileResource.ProfileRequest.class, ProfileResource.PasswordRequest.class, ProfileResource.AvatarRequest.class
})
public final class NativeReflectionConfig {
    private NativeReflectionConfig() {}
}
