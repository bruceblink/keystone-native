package app.keystone.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 验证直连地址、受信代理链和异常转发头的处理边界。 */
class ClientAddressResolverTest {
    @Test
    void ignoresForwardedHeaderWhenNoTrustedProxyIsConfigured() {
        var resolver = new ClientAddressResolver("");
        assertEquals("192.0.2.10", resolver.resolve("192.0.2.10", "198.51.100.5"));
    }

    @Test
    void usesFirstUntrustedAddressBehindTrustedProxy() {
        var resolver = new ClientAddressResolver("192.0.2.0/24");
        assertEquals("198.51.100.5", resolver.resolve("192.0.2.10", "198.51.100.5, 192.0.2.11"));
    }

    @Test
    void rejectsUntrustedRemoteAndMalformedChains() {
        var resolver = new ClientAddressResolver("192.0.2.0/24");
        assertEquals("198.51.100.10", resolver.resolve("198.51.100.10", "203.0.113.4"));
        assertEquals("192.0.2.10", resolver.resolve("192.0.2.10", "not-an-ip"));
        assertEquals("192.0.2.10", resolver.resolve("192.0.2.10", "1.1.1.1,"));
        assertEquals("192.0.2.10", resolver.resolve("192.0.2.10", "198.51.100.5,203.0.113.4"));
        assertEquals("192.0.2.10", resolver.resolve("192.0.2.10", "1.1.1.1,".repeat(11)));
    }

    @Test
    void supportsIpv6TrustedProxyCidr() {
        var resolver = new ClientAddressResolver("2001:db8:1::/48");
        assertEquals("2001:db8:2:0:0:0:0:5", resolver.resolve("2001:db8:1::10", "2001:db8:2::5"));
    }

    @Test
    void rejectsInvalidTrustedProxyConfiguration() {
        assertThrows(IllegalArgumentException.class, () -> new ClientAddressResolver("proxy.example/24"));
        assertThrows(IllegalArgumentException.class, () -> new ClientAddressResolver("192.0.2.0/33"));
    }
}
