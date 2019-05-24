package com.yanmouxie.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Value("#{ @environment['my.oauth2.resource.resourceId'] }")
	private String serverResourceID;

	@Autowired
	@Qualifier("authenticationManagerBean")
	private AuthenticationManager authenticationManager;

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints)
			throws Exception {
		endpoints.authenticationManager(authenticationManager);
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients)
			throws Exception {
		// It can save in DB as well
		clients.inMemory()
				.withClient("myclient")
				.secret("{noop}mysecret")
				.authorizedGrantTypes("client_credentials")
				.scopes("resource-server-read", "resource-server-write")
				.accessTokenValiditySeconds(300)
				.resourceIds(serverResourceID)

				.and()
				.withClient("ResourceServer")
				.secret("{noop}ResourceServerSecret")
				.authorizedGrantTypes("authorization_code", "implicit",
						"password", "client_credentials", "refresh_token")
				.authorities("ROLE_TRUSTED_CLIENT")
				.resourceIds(serverResourceID);
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer)
			throws Exception {
		oauthServer.tokenKeyAccess(
				"isAnonymous() || hasAuthority('ROLE_TRUSTED_CLIENT')")
				.checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");
	}
}