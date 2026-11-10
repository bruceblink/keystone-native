package app.keystone.user;

import java.util.List;

public record User(long id, String username, String displayName, Long deptId, Long postId, boolean enabled,
                   String email, String phoneNumber, Integer sex, String avatar, String loginIp,
                   java.time.Instant loginAt, String remark, List<String> roles) {}
