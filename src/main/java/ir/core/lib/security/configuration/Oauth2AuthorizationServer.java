package ir.core.lib.security.configuration;

import ir.core.lib.security.properties.AuthenticationProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;

import java.util.Map;

@Configuration
@ConditionalOnProperty(
        value = "authentication.type",
        havingValue = "SERVER"
)
@EnableAuthorizationServer
@Import(Oauth2SecurityConfiguration.class)
public class Oauth2AuthorizationServer extends AuthorizationServerConfigurerAdapter {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final TokenStore tokenStore;
    private final AuthenticationProperties authenticationProperties;
    private final PasswordEncoder passwordEncoder;
    private final AccessTokenConverter accessTokenConverter;

    public Oauth2AuthorizationServer(AuthenticationManager authenticationManager,
                                     UserDetailsService userDetailsService,
                                     TokenStore tokenStore,
                                     AuthenticationProperties authenticationProperties,
                                     PasswordEncoder passwordEncoder,
                                     AccessTokenConverter accessTokenConverter) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.tokenStore = tokenStore;
        this.authenticationProperties = authenticationProperties;
        this.passwordEncoder = passwordEncoder;
        this.accessTokenConverter = accessTokenConverter;
    }

    @Bean
    public OAuth2AccessDeniedHandler oauthAccessDeniedHandler() {
        return new OAuth2AccessDeniedHandler();
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
        oauthServer
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        super.configure(clients);
        InMemoryClientDetailsServiceBuilder inMemoryClientDetailsServiceBuilder = clients.inMemory();
        Map<String, AuthenticationProperties.Server.Client> clientsMap = authenticationProperties.getServer().getClients();
        for (String clientId : clientsMap.keySet()) {
            AuthenticationProperties.Server.Client loadedClient = clientsMap.get(clientId);
            inMemoryClientDetailsServiceBuilder
                    .withClient(loadedClient.getClientId())
                    .secret(passwordEncoder.encode(loadedClient.getClientSecret()))
                    .authorizedGrantTypes("password", "refresh_token")
                    .scopes("read", "write")
                    .accessTokenValiditySeconds(authenticationProperties.getServer().getAccessTokenValidity())
                    .refreshTokenValiditySeconds(authenticationProperties.getServer().getRefreshTokenValidity());
        }
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        super.configure(endpoints);
        endpoints
                .tokenStore(tokenStore)
                .userDetailsService(userDetailsService)
                .authenticationManager(authenticationManager)
                .accessTokenConverter(accessTokenConverter);
    }
}
