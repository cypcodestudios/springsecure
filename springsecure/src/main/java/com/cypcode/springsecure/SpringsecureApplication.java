package com.cypcode.springsecure;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@SpringBootApplication
@ComponentScan({ "com.cypcode.springsecure.controller", "com.cypcode.springsecure.security"})
public class SpringsecureApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringsecureApplication.class, args);
	}
	
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	  public UserDetailsService userDetailsService() {
	    var userDetailsService =
	        new InMemoryUserDetailsManager();

	    var user = User.withUsername("user")
	            .password("password")
	            .authorities("USER_ROLE")
	            .build();

	    userDetailsService.createUser(user); 

	    return userDetailsService;
	  }

}
