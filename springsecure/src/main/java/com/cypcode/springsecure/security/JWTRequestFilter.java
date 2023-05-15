package com.cypcode.springsecure.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;


@Component
public class JWTRequestFilter extends OncePerRequestFilter {

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private JWTTokenUtil jwtTokenUtil;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		final String requestTokenHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

		if (requestTokenHeader == null || requestTokenHeader == "" || !requestTokenHeader.startsWith("Bearer ")) {
			chain.doFilter(request, response);
			return;
		}

		String jwtToken = requestTokenHeader.split(" ")[1].trim();
		String username = jwtTokenUtil.getUsernameFromToken(jwtToken);
		UserDetails userValueObject = userDetailsService.loadUserByUsername(username);

		if (jwtTokenUtil.validateToken(jwtToken, userValueObject)) {

			UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
					userValueObject, null, userValueObject.getAuthorities());
			usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
		}

		chain.doFilter(request, response);
	}
}
