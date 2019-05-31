package com.yanmouxie.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

	private static final String SERVER_RESOURCE_ID = "oauth2-server";
	private static final String URL = "http://localhost:8080/oauth/check_token";

	@Override
	public void configure(ResourceServerSecurityConfigurer resources)
			throws Exception {
		resources.resourceId(SERVER_RESOURCE_ID);
		RemoteTokenServices tokenService = new RemoteTokenServices();
		tokenService.setCheckTokenEndpointUrl(URL);
		tokenService.setClientId("ResourceServer");
		tokenService.setClientSecret("ResourceServerSecret");
		resources.tokenServices(tokenService);
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.requestMatchers().antMatchers("/api/**", "/test")
		.and()
		.authorizeRequests().antMatchers("/test").access("#oauth2.hasScope('resource-server-read')");
		
		//http.requestMatchers().antMatchers("/api/**").and().authorizeRequests().antMatchers("/api/**").access("#oauth2.hasScope('resource-server-read')");
		//http.requestMatchers().antMatchers("/test").and().authorizeRequests().antMatchers("/test").access("#oauth2.hasScope('resource-server-read')");
		//http.authorizeRequests().antMatchers("/test").authenticated();
	}
}
