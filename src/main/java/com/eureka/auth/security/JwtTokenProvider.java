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
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;

import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenProvider {
	
   @Value("${keystore.location}")
   private Resource resourceFile;

  /**
   * THIS IS NOT A SECURE PRACTICE! For simplicity, we are storing a static key here. Ideally, in a
   * microservices environment, this key would be kept on a config-server.
   */
  @Value("${security.jwt.token.secret-key:secret-key}")
  private String secretKey;

  @Value("${security.jwt.token.expire-length:3600000}")
  private long validityInMilliseconds = 3600000; // 1h

  @PostConstruct
  protected void init() {
    secretKey = java.util.Base64.getEncoder().encodeToString(secretKey.getBytes());
  }
  
  
  public String createToken(String username, Collection<? extends GrantedAuthority> roles) {
	    Claims claims = Jwts.claims().setSubject(username);
	    //List<SimpleGrantedAuthority>
	    //List<SimpleGrantedAuthority> <<<<<- List<String>
	    claims.put("auth", roles);

	    Date now = new Date();
	    Date validity = new Date(now.getTime() + validityInMilliseconds);

	    return Jwts.builder()//
	        .setClaims(claims)//
	        .setIssuedAt(now)//
	        .setExpiration(validity)//
	        .signWith(SignatureAlgorithm.HS512, secretKey)//
	        .compact();
	  }

  public String createToken(String username, List<String> roles) {

    Claims claims = Jwts.claims().setSubject(username);
    //List<SimpleGrantedAuthority>
    //List<SimpleGrantedAuthority> <<<<<- List<String>
    claims.put("auth", roles.stream().map(s -> new SimpleGrantedAuthority(s))
    		.filter(Objects::nonNull).collect(Collectors.toList()));

    Date now = new Date();
    Date validity = new Date(now.getTime() + validityInMilliseconds);

    return Jwts.builder()//
        .setClaims(claims)//
        .setIssuedAt(now)//
        .setExpiration(validity)//
        .signWith(SignatureAlgorithm.HS512, secretKey)//
        .compact();
  }
  
  public String createRefreshToken(String username) {
      LocalDateTime currentTime = LocalDateTime.now();
      Claims claims = Jwts.claims().setSubject(username);
      String token = Jwts.builder()
              .setClaims(claims)
              .setIssuer("Bank Tech")
              .setId(UUID.randomUUID().toString())
              .setIssuedAt(Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant()))
              .setExpiration(Date.from(currentTime
                      .plusMinutes(60)
                      .atZone(ZoneId.systemDefault()).toInstant()))
              .signWith(SignatureAlgorithm.HS512, secretKey)
              .compact();

      return token;

	   
	  }

		/*
		 * public Authentication getAuthentication(String token) { UserDetails
		 * userDetails =
		 * springSecurityUserDetails.loadUserByUsername(getUsername(token)); return new
		 * UsernamePasswordAuthenticationToken(userDetails, "",
		 * userDetails.getAuthorities()); }
		 */

  /**
   * if u know the token then we can fetch username from the token
   * 
   * @param token
   * @return
   */
  public String getUsername(String token) {
    return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
  }

  /**
   * Extracting -> Bearer token from in coming header
   * and return  it
   * 
   * @param req
   * @return
   */
  public String resolveToken(HttpServletRequest req) {
    String bearerToken = req.getHeader("Authorization");
    if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
      return bearerToken.substring(7);
    }
    return null;
  }

  //check token is expired or not
  public boolean validateToken(String token) {
    try {
      Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
      return true;
    } catch (JwtException | IllegalArgumentException e) {
      throw new CustomException("Expired or invalid JWT token", HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
  
  @PostConstruct
  public  void readPublicKey() throws IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, KeyStoreException {
	  InputStream is = resourceFile.getInputStream();
      KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
      String password = "test@123";
      char[] passwd = password.toCharArray();
      keystore.load(is, passwd);
      String alias = "keubiko";
      Key key = keystore.getKey(alias, passwd);
      if (key instanceof PublicKey) {
        // Get certificate of public key
        Certificate cert = keystore.getCertificate(alias);
        // Get public key
        PublicKey publicKey = cert.getPublicKey();
        String publicKeyString = Base64.encodeBase64String(publicKey
                  .getEncoded());
        System.out.println("--> "+publicKeyString);
      }
      if (key instanceof PrivateKey) {
          // Get certificate of public key
          Certificate cert = keystore.getCertificate(alias);
          
          // Get public key
          PublicKey publicKey = cert.getPublicKey();
          String publicKeyString = Base64.encodeBase64String(publicKey
                    .getEncoded());
          
          KeyPair keyPair= new KeyPair(publicKey, (PrivateKey) key);
          
          String privateKeyString = Base64.encodeBase64String(((PrivateKey) key
                  ).getEncoded());
          
          System.out.println("publicKeyString--> "+publicKeyString);
          System.out.println("privateKeyString--> "+privateKeyString);
        }
  }

}
