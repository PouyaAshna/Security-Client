package ir.core.lib.security.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;

@Getter
@Setter
@ConfigurationProperties(prefix = "authentication")
public class AuthenticationProperties {
    private AuthenticationType type;
    private TokenStoreType tokenStore;
    private Resource resource;
    private Server server;

    private JWT jwt;

    @Getter
    @Setter
    public static class JWT {
        private String signingKey;
    }

    @Getter
    @Setter
    public static class Resource {
        private String clientId;
        private String clientSecret;
        private String authorizationServerUrl;
        private DefaultAuthorizedRequestType defaultAuthorizedRequestType;
        private String[] permitAllUrls;
        private String[] authenticatedUrls;
    }

    @Getter
    @Setter
    public static class Server {
        private int accessTokenValidity;
        private int refreshTokenValidity;
        private Map<String, Client> clients;

        @Getter
        @Setter
        public static class Client {
            private String clientId;
            private String clientSecret;
        }
    }
}
