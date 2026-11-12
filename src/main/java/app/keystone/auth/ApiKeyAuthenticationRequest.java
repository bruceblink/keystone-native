package app.keystone.auth;

import io.quarkus.security.identity.request.BaseAuthenticationRequest;

/** 保存一次请求中的 API Key。原始值只在认证流程内存中使用。 */
public final class ApiKeyAuthenticationRequest extends BaseAuthenticationRequest {
    private final String value;

    public ApiKeyAuthenticationRequest(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
