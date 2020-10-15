package com.bezkoder.springjwt.security;

import com.bezkoder.springjwt.security.jwt.AuthTokenFilter;
import com.bezkoder.springjwt.security.jwt.AuthenticationEntryPointJWT;
import com.bezkoder.springjwt.security.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity //allows Spring to find and automatically apply the class to the global Web Security
@EnableGlobalMethodSecurity(prePostEnabled = true)//It enables @PreAuthorize, @PostAuthorize
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	UserDetailsServiceImpl userDetailsServiceImpl;

	@Autowired
	private AuthenticationEntryPointJWT authenticationEntryPointJWT;

	@Bean
	public AuthTokenFilter authTokenFilter() {
		return new AuthTokenFilter();
	}

	//AuthenticationManager is used for .authenticate()
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	//PasswordEncoder when configuring DaoAuthenticationProvider
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	//configuring DaoAuthenticationProvider by AuthenticationManagerBuilder.userDetailsService()
	@Override
	public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
		authenticationManagerBuilder.userDetailsService(userDetailsServiceImpl).passwordEncoder(passwordEncoder());
	}

	//Tells Spring Security how we configure CORS and CSRF
	//when we want to require all users to be authenticated or not
	//which filter (AuthTokenFilter) and when we want it to work(filter before UsernamePasswordAuthenticationFilter)
	//which Exception Handler is chosen (AuthEntryPointJwt)
	@Override
	protected void configure(HttpSecurity http) throws Exception {


		http.headers().frameOptions().disable();//TODO for using H2, delete in production

		http.cors().and().csrf().disable()
				//use AuthEntryPointJwt to handle exception
			.exceptionHandling().authenticationEntryPoint(authenticationEntryPointJWT).and()
				//Config session
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
				// authorizeRequests that match the following patterns
			.authorizeRequests()
				.antMatchers("/api/auth/**").permitAll() //allow all request from /api/auth/**,
				.antMatchers("/api/test/**").permitAll() //allow all request from /api/test/**, but these api are blocked again in controller by e.g. @PreAuthorize("hasRole('ADMIN')")
				.antMatchers("/h2-console/**").permitAll() //TODO for using H2, delete in production
				.anyRequest().authenticated().and()//allow all authenticated request
				//Tell Spring security to use AuthTokenFilter to filter before using UsernamePasswordAuthenticationFilter
			.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);

		}
}
