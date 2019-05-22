package com.yanmouxie.controller;

import java.io.IOException;
import java.util.Arrays;
import org.apache.commons.codec.binary.Base64;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Controller
public class ClientController {

	@RequestMapping(value = "/client-test", method = RequestMethod.GET, produces = "application/json")
	@ResponseBody
	public String test() throws JsonProcessingException, IOException {

		ResponseEntity<String> response = null;

		RestTemplate restTemplate = new RestTemplate();

		String credentials = "myclient:mysecret";
		String encodedCredentials = new String(Base64.encodeBase64(credentials
				.getBytes()));

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.add("Authorization", "Basic " + encodedCredentials); // key=Authorization；value=Basic+space+Base64(username:password)

		HttpEntity<String> request = new HttpEntity<String>(headers);

		String access_token_url = "http://localhost:8080/oauth/token";
		access_token_url += "?grant_type=client_credentials";

		response = restTemplate.exchange(access_token_url, HttpMethod.POST,
				request, String.class);

		System.out.println("Access Token Response ---------"
				+ response.getBody());

		// Get the Access Token From the recieved JSON response
		ObjectMapper mapper = new ObjectMapper();
		JsonNode node = mapper.readTree(response.getBody());
		String token = node.path("access_token").asText();

		String url = "http://localhost:9090/test";

		// Use the access token for authentication
		HttpHeaders headers1 = new HttpHeaders();
		headers1.add("Authorization", "Bearer " + token);
		HttpEntity<String> entity = new HttpEntity<>(headers1);

		ResponseEntity<String> response2 = restTemplate.exchange(url,
				HttpMethod.GET, entity, String.class);

		System.out.println("Resource Server Response ---------"
				+ response2.getBody());

		return "{\"Authorization Server Access Token Response\":"
				+ response.getBody() + ",\"Resource Server Response\":\""
				+ response2.getBody() + "\"" + "}";
	}
}