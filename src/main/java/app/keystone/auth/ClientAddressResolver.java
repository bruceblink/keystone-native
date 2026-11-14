package app.keystone.auth;

import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * 解析用于限流和审计的客户端地址。
 *
 * <p>默认使用 TCP 连接的远端地址。只有远端地址属于显式配置的受信代理网段时，
 * 才解析 X-Forwarded-For。反向代理必须在转发前删除外部请求携带的同名请求头。</p>
 */
@ApplicationScoped
public class ClientAddressResolver {
    private static final int MAX_FORWARDED_HOPS = 10;
    private static final int MAX_HEADER_LENGTH = 512;
    private final List<Cidr> trustedProxyCidrs;

    @Inject
    public ClientAddressResolver(
            @ConfigProperty(name = "keystone.security.network.trusted-proxy-cidrs", defaultValue = "") String trustedProxyCidrs) {
        this.trustedProxyCidrs = parseCidrs(trustedProxyCidrs);
    }

    /** 从当前 HTTP 请求读取 TCP 远端地址，再按受信代理配置处理转发头。 */
    public String resolve(RoutingContext context, String forwardedFor) {
        String remote = null;
        if (context != null && context.request() != null && context.request().remoteAddress() != null) {
            remote = context.request().remoteAddress().host();
        }
        return resolve(remote, forwardedFor);
    }

    /** 解析地址的纯函数入口，便于在没有 HTTP 容器时验证边界。 */
    public String resolve(String remoteAddress, String forwardedFor) {
        String remote = normalizeLiteral(remoteAddress);
        if (remote == null) return "unknown";
        InetAddress remoteIp;
        try { remoteIp = parseLiteral(remote); }
        catch (IllegalArgumentException e) { return "unknown"; }
        if (forwardedFor == null || forwardedFor.isBlank() || !isTrusted(remoteIp)) return remote;
        if (forwardedFor.length() > MAX_HEADER_LENGTH) return remote;

        String[] values = forwardedFor.split(",", -1);
        if (values.length == 0 || values.length > MAX_FORWARDED_HOPS) return remote;
        List<InetAddress> chain = new ArrayList<>(values.length);
        for (String value : values) {
            String candidate = normalizeLiteral(value);
            if (candidate == null) return remote;
            try { chain.add(parseLiteral(candidate)); }
            catch (IllegalArgumentException e) { return remote; }
        }

        // 从最近代理向外检查。链中只能有一个非受信地址，额外的非受信地址表示头部未被代理清理。
        int clientIndex = -1;
        for (int i = chain.size() - 1; i >= 0; i--) {
            if (!isTrusted(chain.get(i))) {
                if (clientIndex >= 0) return remote;
                clientIndex = i;
            }
        }
        if (clientIndex >= 0) return format(chain.get(clientIndex));
        // 链上的地址全部属于受信代理时，取最左侧地址作为原始客户端地址。
        return format(chain.get(0));
    }

    /** 判断 HTTP 连接的远端地址是否属于明确配置的受信代理网段。 */
    public boolean isTrustedProxy(String remoteAddress) {
        String normalized = normalizeLiteral(remoteAddress);
        if (normalized == null) return false;
        try {
            return isTrusted(parseLiteral(normalized));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private boolean isTrusted(InetAddress address) {
        return trustedProxyCidrs.stream().anyMatch(cidr -> cidr.contains(address));
    }

    private static List<Cidr> parseCidrs(String value) {
        if (value == null || value.isBlank()) return List.of();
        List<Cidr> result = new ArrayList<>();
        for (String item : value.split(",", -1)) {
            String normalized = item.trim();
            if (normalized.isBlank()) throw new IllegalArgumentException("trusted proxy CIDR is blank");
            int slash = normalized.indexOf('/');
            if (slash <= 0 || slash != normalized.lastIndexOf('/')) throw new IllegalArgumentException("invalid trusted proxy CIDR");
            String address = normalizeLiteral(normalized.substring(0, slash));
            if (address == null) throw new IllegalArgumentException("trusted proxy CIDR must use a literal address");
            int prefix;
            try { prefix = Integer.parseInt(normalized.substring(slash + 1).trim()); }
            catch (NumberFormatException e) { throw new IllegalArgumentException("invalid trusted proxy CIDR prefix", e); }
            InetAddress ip = parseLiteral(address);
            int max = ip.getAddress().length * 8;
            if (prefix < 0 || prefix > max) throw new IllegalArgumentException("trusted proxy CIDR prefix is out of range");
            result.add(new Cidr(ip.getAddress(), prefix));
        }
        return List.copyOf(result);
    }

    private static String normalizeLiteral(String value) {
        if (value == null) return null;
        String normalized = value.trim();
        if (normalized.startsWith("[") && normalized.endsWith("]")) normalized = normalized.substring(1, normalized.length() - 1);
        if (normalized.isBlank() || normalized.length() > 64 || normalized.indexOf('%') >= 0) return null;
        if (!normalized.matches("[0-9A-Fa-f:.]+")) return null;
        return normalized;
    }

    private static InetAddress parseLiteral(String value) {
        try {
            InetAddress address = InetAddress.getByName(value);
            if (value.indexOf(':') >= 0 && address.getAddress().length != 16) throw new IllegalArgumentException("invalid IPv6 address");
            if (value.indexOf(':') < 0 && address.getAddress().length != 4) throw new IllegalArgumentException("invalid IPv4 address");
            return address;
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("invalid IP address", e);
        }
    }

    private static String format(InetAddress address) {
        return address.getHostAddress().toLowerCase(Locale.ROOT);
    }

    private record Cidr(byte[] network, int prefixLength) {
        private Cidr { network = Arrays.copyOf(network, network.length); }

        private boolean contains(InetAddress address) {
            byte[] candidate = address.getAddress();
            if (candidate.length != network.length) return false;
            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;
            for (int i = 0; i < fullBytes; i++) if (candidate[i] != network[i]) return false;
            if (remainingBits == 0) return true;
            int mask = 0xff << (8 - remainingBits);
            return (candidate[fullBytes] & mask) == (network[fullBytes] & mask);
        }
    }
}
