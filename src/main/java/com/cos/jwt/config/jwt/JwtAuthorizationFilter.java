package com.cos.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

// 시큐리티 filter 중 BasicAuthenticationFilter 존재
// 인증 혹은 권한이 필요한 특정 주소 요청할 경우 위 필터를 반드시 통과
// 인증 혹은 권한이 필요없는 주소라면 필터 통과 X
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
	
	private UserRepository userRepository;

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}
	
	// 인증 혹은 권한이 필요한 주소 요청일 경우 필터를 통과
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//super.doFilterInternal(request, response, chain);
		System.out.println("인증 혹은 권한 필요한 주소 요청");

		String jwtHeader = request.getHeader("Authorization");
		System.out.println("jwtHeader:" + jwtHeader); 

		// header 존재 여부 확인
		if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
			chain.doFilter(request, response);
			return;
		}
		
		// JWT 토큰으로 정상적인 사용자 확인
		String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
		String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();
		
		// 서명이 정상적으로 완료
		if(username != null) {
			User entity =userRepository.findByUsername(username);
			PrincipalDetails principalDetails = new PrincipalDetails(entity);

			// JWT 토큰 서명이 정상일 경우 Authentication 객체 생성
			Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
			
			
			// 강제로 시큐리티 세션에 접근하여 Authentication 객체 저장
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}
		chain.doFilter(request, response);
	}
}