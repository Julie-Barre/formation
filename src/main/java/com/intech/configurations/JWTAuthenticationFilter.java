package com.intech.configurations;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.security.core.Authentication;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import com.intech.services.JwtService;

import java.io.IOException;

public class JWTAuthenticationFilter extends GenericFilterBean {
  private JwtService jwtService;
  public JWTAuthenticationFilter(JwtService jwtService ){
    this.jwtService = jwtService;
  }
  @Override
  public void doFilter(ServletRequest request,
             ServletResponse response,
             FilterChain filterChain)
      throws IOException, ServletException {
    Authentication authentication = this.jwtService.getAuthentication((HttpServletRequest)request);
    SecurityContextHolder.getContext().setAuthentication(authentication);
    filterChain.doFilter(request,response);
  }
}