package com.cos.jwt.config.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// Spring Security에서 UsernamePasswordAuthenticationFilter 존재
// /login 요청해서 username, password 전송(POST)
// UsernamePasswordAuthenticationFilter 작동
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private final AuthenticationManager authenticationManager;
	
	public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}
	
	// /login 요청 시 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter: 로그인 시도");
		
		// 1. username, password
		
		// 2. authenticationManager로 정상인지 로그인 시도 -> PrincipalDetailsService 호출 -> loadUserByUsername() 실행
		
		// 3. PrincipalDetails를 세션에 저장(권한 관리 목적)
		
		// 4. JWT 토큰 만들어서 응답
		
		return super.attemptAuthentication(request, response);
	}
}