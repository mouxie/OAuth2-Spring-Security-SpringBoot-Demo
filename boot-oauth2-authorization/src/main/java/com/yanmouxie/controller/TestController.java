package com.yanmouxie.controller;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

	@Autowired
	private AuthorizationServerEndpointsConfiguration endpoints;

	@RequestMapping("/getAccessTokenByClientId")
	public Collection<OAuth2AccessToken> getAccessTokenByClientId(String client_id) {
		InMemoryTokenStore tokenStore = (InMemoryTokenStore) endpoints.getEndpointsConfigurer().getTokenStore();
		
		Collection<OAuth2AccessToken> tokens = tokenStore.findTokensByClientId(client_id);
		
		if (tokens != null && tokens.size() > 0) {
			for (OAuth2AccessToken accessToken : tokens) {
				System.out.println("accessToken:" + accessToken.getValue());
			}
		}

		return tokens;
	}
}
