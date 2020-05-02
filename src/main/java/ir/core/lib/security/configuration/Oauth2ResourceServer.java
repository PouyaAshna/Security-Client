package ir.core.lib.security.configuration;

import ir.core.lib.security.properties.AuthenticationProperties;
import ir.core.lib.security.properties.DefaultAuthorizedRequestType;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;

@Configuration
@EnableResourceServer
@ConditionalOnProperty(
        value = "authentication.type",
        havingValue = "RESOURCE"
)
public class Oauth2ResourceServer extends ResourceServerConfigurerAdapter {

    private final AuthenticationProperties authenticationProperties;

    public Oauth2ResourceServer(AuthenticationProperties authenticationProperties) {
        this.authenticationProperties = authenticationProperties;
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer config) {
        config.tokenServices(tokenServices());
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        SessionManagementConfigurer<HttpSecurity> httpSecuritySessionManagementConfigurer = http
                .cors()
                .and()
                .csrf()
                .disable()
                .headers()
                .frameOptions()
                .disable()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry expressionInterceptUrlRegistry =
                httpSecuritySessionManagementConfigurer.and().authorizeRequests();
        if (authenticationProperties.getResource().getDefaultAuthorizedRequestType().equals(DefaultAuthorizedRequestType.AUTHENTICATED)) {
            if (authenticationProperties.getResource().getPermitAllUrls() != null) {
                expressionInterceptUrlRegistry
                        .antMatchers(authenticationProperties.getResource().getPermitAllUrls())
                        .permitAll();
            }
            expressionInterceptUrlRegistry
                    .anyRequest()
                    .authenticated();
        } else if (authenticationProperties.getResource().getDefaultAuthorizedRequestType().equals(DefaultAuthorizedRequestType.PERMIT_ALL)) {
            if (authenticationProperties.getResource().getAuthenticatedUrls() != null) {
                expressionInterceptUrlRegistry
                        .antMatchers(authenticationProperties.getResource().getAuthenticatedUrls())
                        .authenticated();
            }
            expressionInterceptUrlRegistry
                    .anyRequest()
                    .permitAll();
        } else {
            expressionInterceptUrlRegistry
                    .anyRequest()
                    .authenticated();
        }
    }

    @Bean
    @Primary
    public RemoteTokenServices tokenServices() {
        RemoteTokenServices tokenService = new RemoteTokenServices();
        tokenService.setCheckTokenEndpointUrl(
                authenticationProperties.getResource().getAuthorizationServerUrl() + "/oauth/check_token");
        tokenService.setClientId(authenticationProperties.getResource().getClientId());
        tokenService.setClientSecret(authenticationProperties.getResource().getClientSecret());
        return tokenService;
    }

}
