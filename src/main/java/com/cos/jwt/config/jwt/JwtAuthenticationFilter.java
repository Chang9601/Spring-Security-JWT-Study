package com.cos.jwt.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

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
		try {
			/*
			 * BufferedReader br = request.getReader(); String input = null;
			 * 
			 * while((input = br.readLine()) != null) { System.out.println(input); }
			 */
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);
			System.out.println(user);
			
			UsernamePasswordAuthenticationToken authenticationToken = 
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			// PrincipalDetailsService의 loadUserByUsername() 함수 실행 후 정상이면 authentication 반환
			// DB의 username과 password가 일치
			Authentication authentication = authenticationManager.authenticate(authenticationToken);

			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			System.out.println("로그인 완료: " + principalDetails.getUser().getUsername()); // 로그인 완료 의미	
			
			// authentication 객체가 세션 영역에 저장되고 반환
			// 반환 이유: 권한 관리를 Spring Security가 대신 처리
			// JWT 토큰의 경우 세션이 필요없지만 권한 처리 때문에 세션에 삽입
			return authentication;
			
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}
		
		// 2. authenticationManager로 정상인지 로그인 시도 -> PrincipalDetailsService 호출 -> loadUserByUsername() 실행
		
		// 3. PrincipalDetails를 세션에 저장(권한 관리 목적)
		
		// 4. JWT 토큰 만들어서 응답
		
		return null;
	}
	
	
	// attemptAuthentication 실행 후 인증이 정상적으로 완료되면 successfulAuthentication 실행
	// JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthenticaiton 실행: 인증 완료");
		
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		
		// RSA x, Hash 암호화
		String jwtToken = JWT.create()
				.withSubject("cos 토큰")
				.withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512("cos"));
		
		response.addHeader("Authorization", "Bear " + jwtToken);
	}
	
	
}