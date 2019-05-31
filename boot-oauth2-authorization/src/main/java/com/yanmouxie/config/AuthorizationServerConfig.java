package com.yanmouxie.config;

import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	//private static final String SERVER_RESOURCE_ID = "oauth2-server";
	
	@Autowired
	DataSource dataSource;

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
		clients.withClientDetails(clientDetailsService());
		/*
		clients.inMemory()
				.withClient("myclient")
				.secret("$2a$10$tEFtDKpFh6eAr07inuDYVOtVAArj1NK3ulnj8KuUp7rHjrjYPzzD.") // mysecret:$2a$10$tEFtDKpFh6eAr07inuDYVOtVAArj1NK3ulnj8KuUp7rHjrjYPzzD.
				.authorizedGrantTypes("client_credentials")
				.scopes("resource-server-read", "resource-server-write")
				.accessTokenValiditySeconds(300)
				.resourceIds(SERVER_RESOURCE_ID)

				.and()
				.withClient("ResourceServer")
				.secret("{noop}ResourceServerSecret")
				.authorizedGrantTypes("authorization_code", "implicit",
						"password", "client_credentials", "refresh_token")
				.authorities("ROLE_TRUSTED_CLIENT")
				.resourceIds(SERVER_RESOURCE_ID);
		*/
	}
	
	@Bean
	public ClientDetailsService clientDetailsService(){
		ClientDetailsService clientDetailsService = new JdbcClientDetailsService(dataSource);
		return clientDetailsService;
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer)
			throws Exception {

		oauthServer.passwordEncoder(new BCryptPasswordEncoder());
		//oauthServer.checkTokenAccess("permitAll()");
		oauthServer.tokenKeyAccess(
				"isAnonymous() || hasAuthority('ROLE_TRUSTED_CLIENT')")
				.checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");
	}
}