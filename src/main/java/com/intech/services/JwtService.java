package com.intech.services;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

import com.google.common.reflect.ClassPath;

import java.util.Date;

import static java.util.Collections.emptyList;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;


@Service
public class JwtService {
  @Value("${security.jwt.expiration}")
  private int EXPIRATIONTIME;
  @Value("${security.jwt.secret}")
  private String SECRET;
  @Value("${security.jwt.token.prefix}")
  private String TOKEN_PREFIX;
  @Value("${security.jwt.header.string}")
  private String HEADER_STRING;

  private ClassPathResource resource = new ClassPathResource("myapp.jks");
  private KeyStore keyStore;
  
  public String generateJwt(String username){
    
    try {
      keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(resource.getInputStream(), "keystorepassword".toCharArray());
      PrivateKey key = (PrivateKey)keyStore.getKey("myalias", "myaliaspassword".toCharArray());      

      return Jwts.builder()
        .setSubject(username)
        .setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
        .signWith(SignatureAlgorithm.RS256, key)
        .compact();
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
 }

  public Authentication getAuthentication(HttpServletRequest request) {
    String token = request.getHeader(HEADER_STRING);
    if (token != null) {
      // parse the token.
      try {
        keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(resource.getInputStream(), "keystorepassword".toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate("myalias");
        PublicKey pubKey = certificate.getPublicKey();
        String user = Jwts.parser()
            .setSigningKey(pubKey)
            .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
            .getBody()
            .getSubject();
            return user != null ?   new UsernamePasswordAuthenticationToken(user, null, emptyList()) :  null;
      } catch (Exception e) {
        //TODO: handle exception
        e.printStackTrace();
        return null;
      }
    }
    return null;
  }

}
