package com.cypcode.springsecure.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.cypcode.springsecure.entity.SpringUser;
import com.cypcode.springsecure.security.JWTTokenUtil;
import java.util.*;

@RestController("/")
public class HomeController {
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private JWTTokenUtil jwtTokenUtil;
	
	@Autowired
	private UserDetailsService userDetailsService;


	@GetMapping
	public String getHome() {
		return "Welcome to Cypcode Spring Secure API.";
	}
	@GetMapping("login")
	public Map<String, String> getLogin(@RequestBody SpringUser request) {
		try {
			authenticate(request.getUsername(), request.getPassword());
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		final UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());

		final String token = jwtTokenUtil.generateToken(userDetails);
		
		Map<String, String> response = new HashMap<>();
		response.put("token", token);
		
		return response;
	}
	@GetMapping("sign-up")
	public String getRegistration() {
		return "Register new user.";
	}
	private void authenticate(String username, String password) throws Exception {
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		} catch (DisabledException e) {
			throw new Exception("USER_DISABLED", e);
		} catch (BadCredentialsException e) {
			throw new Exception("INVALID_CREDENTIALS", e);
		}
	}
}
