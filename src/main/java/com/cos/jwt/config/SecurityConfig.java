package com.cos.jwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.filter.MyFilter3;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	private final CorsFilter corsFilter;
	
	public SecurityConfig(CorsFilter corsFilter) {
		this.corsFilter = corsFilter;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class);
		
		http.csrf().disable();
		
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용하지 않겠다
			.and()
			.addFilter(corsFilter) // @CrossOrigin: 인증 필요 X, 시큐리티 필터에 인증 등록
			.formLogin().disable() // form 로그인 사용 X
			.httpBasic().disable()
			.authorizeRequests()
			.antMatchers("/api/v1/user/**")
			.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
			.antMatchers("/api/v1/manager/**")
			.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
			.antMatchers("/api/v1/admin/**")
			.access(" hasRole('ROLE_ADMIN')")
			.anyRequest().permitAll();
	}
}