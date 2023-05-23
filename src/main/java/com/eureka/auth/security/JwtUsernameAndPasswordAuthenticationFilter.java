package com.eureka.auth.security;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.sql.Date;
import java.util.Collections;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter   {
	
	// We use auth manager to validate the user credentials
	private AuthenticationManager authManager;

	
	private final JwtConfig jwtConfig;
	
	private KeyStoreUtils keyStoreUtils;
    
	public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authManager, JwtConfig jwtConfig) {
		this.authManager = authManager;
		this.jwtConfig = jwtConfig;
		
		// By default, UsernamePasswordAuthenticationFilter listens to "/login" path. 
		// In our case, we use "/auth". So, we need to override the defaults.
		this.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(jwtConfig.getUri(), "POST"));
	}
	
	public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authManager, JwtConfig jwtConfig, KeyStoreUtils keyStoreUtils) {
		this.authManager = authManager;
		this.jwtConfig = jwtConfig;
		// By default, UsernamePasswordAuthenticationFilter listens to "/login" path. 
		// In our case, we use "/auth". So, we need to override the defaults.
		this.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(jwtConfig.getUri(), "POST"));
	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
		try {
			
			// 1. Get credentials from request
			//Reading JSON data from in coming request
			//{ 
			   // "username" : "nagendra",
			  //  "password" : "test"
		    //}
			UserCredentials creds = new ObjectMapper().
					readValue(request.getInputStream(), UserCredentials.class);
			
			// 2. Create auth object (contains credentials) which will be used by auth manager
			UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
					creds.getUsername(), creds.getPassword(), Collections.emptyList());
			
			// 3. Authentication manager authenticate the user, 
			//and use UserDetialsServiceImpl::loadUserByUsername() method to load the user.
			return authManager.authenticate(authToken);
			
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	//onAuthenticationFailure
	// Upon successful authentication, generate a token.
	// The 'auth' passed to successfulAuthentication() is the current authenticated user.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication auth) throws IOException, ServletException {
		Long now = System.currentTimeMillis();
		
		//When we will come to this
		//once my username and password are correct!!
		//This code JWT Token library code - >>
		String token="";
		try {
			token = Jwts.builder()
				.setSubject(auth.getName())	
				// Convert to list of strings. 
				// This is important because it affects the way we get them back in the Gateway.
				.claim("fruit", "Banana")
				.claim("title", "Mr.")
				.claim("email", "jamesbond@gmail.com")
				.claim("authorities", auth.getAuthorities().stream()
					.map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
				.setIssuedAt(new Date(now))
				.setExpiration(new Date(now + jwtConfig.getExpiration() * 1000))  // in milliseconds
				//.signWith(SignatureAlgorithm.RS256, keyStoreUtils.readPrivateKey())
				.signWith(SignatureAlgorithm.HS512, jwtConfig.getSecret().getBytes())
				.compact();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		
		// Add token to header
		JwtTokenResponse jwtTokenResponse=new JwtTokenResponse();
		jwtTokenResponse.setAuthorization(token);
		jwtTokenResponse.setEmail("technohunk444@gmail.com");
		jwtTokenResponse.setName(auth.getName());
		
		String jsonStringData=new ObjectMapper().writeValueAsString(jwtTokenResponse);
		
		response.setContentType("application/json");
		response.getWriter().println(jsonStringData);
		
		//response.addHeader(jwtConfig.getHeader(), jwtConfig.getPrefix() + token);
	}
	
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request,
			HttpServletResponse response, AuthenticationException failed)
			throws IOException, ServletException {
		SecurityContextHolder.clearContext();

		if (logger.isDebugEnabled()) {
			logger.debug("Authentication request failed: " + failed.toString(), failed);
			logger.debug("Updated SecurityContextHolder to contain null Authentication");
		}
		JwtTokenResponse jwtTokenResponse=new JwtTokenResponse();
		jwtTokenResponse.setEmail("technohunk444@gmail.com");
		jwtTokenResponse.setMessage("Sorry , your token is not valid any more!");
		String jsonStringData=new ObjectMapper().writeValueAsString(jwtTokenResponse);
		response.setContentType("application/json");
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.getWriter().println(jsonStringData);

	}
	
	class JwtTokenResponse{
		private String name;
		private String email;
		private String message;
		private String Authorization;
		private String companyName="TechnoHunk Info Solutions PVT. LTD.";
		
		
		public String getMessage() {
			return message;
		}
		public void setMessage(String message) {
			this.message = message;
		}
		public String getCompanyName() {
			return companyName;
		}
		public void setCompanyName(String companyName) {
			this.companyName = companyName;
		}
		public String getName() {
			return name;
		}
		public void setName(String name) {
			this.name = name;
		}
		public String getEmail() {
			return email;
		}
		public void setEmail(String email) {
			this.email = email;
		}
		public String getAuthorization() {
			return Authorization;
		}
		public void setAuthorization(String authtorization) {
			Authorization = authtorization;
		}
		
	}
	
	// A (temporary) class just to represent the user credentials
	private static class UserCredentials {
	    private String username, password;
	    
	    public String getUsername() {
			return username;
		}
	    
	    public void setUsername(String username) {
			this.username = username;
		}
	    public String getPassword() {
			return password;
		}
	    public void setPassword(String password) {
			this.password = password;
		}
	}
	
	
}