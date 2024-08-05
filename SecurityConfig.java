package com.cnh.ess.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	
	@Bean
	public InMemoryUserDetailsManager userDetailsService() {
	    UserDetails user1 = User.builder().username("user")
	            .password(passwordEncoder().encode("123"))
	            .roles("USER")
	            .authorities("view_user")
	            .build();
	    UserDetails user2 = User.builder().username("admin")
	            .password(passwordEncoder().encode("123"))
	            .roles("ADMIN")
	            .authorities("view_admin","read_admin")
	            .build();
	    return new InMemoryUserDetailsManager(user1, user2);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
	    return new BCryptPasswordEncoder();
	}
	

	
	
	/*
	 * protected void configure(HttpSecurity http) throws Exception { http
	 * .csrf(csrf -> csrf.disable()) //.cors(cors -> cors.disable()) //.cors(cors ->
	 * cors.configurationSource(corsConfigurationSource()))
	 * .authorizeRequests(requests -> requests.antMatchers("/").permitAll()
	 * .anyRequest().authenticated()) .formLogin(withDefaults())
	 * .httpBasic(withDefaults()); }
	 */

	
	 protected void configure(HttpSecurity http) throws Exception {
         http
                 .authorizeRequests(requests -> requests
                         .antMatchers("/").permitAll()
                         .anyRequest().authenticated())
                 .csrf(csrf -> csrf.disable())
                 .formLogin(formLogin ->
                         formLogin
                                 .loginProcessingUrl("/esLogin")
                                 .usernameParameter("es_iusername")
                                 .passwordParameter("es_ipassword")
                                 .defaultSuccessUrl("/essLogin", false)
                 )
                 .httpBasic(withDefaults());  
     }
	
	


	
	

}
