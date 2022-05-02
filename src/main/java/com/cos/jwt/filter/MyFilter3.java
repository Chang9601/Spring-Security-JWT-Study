package com.cos.jwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter3 implements Filter {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		
		// 토큰: cos -> ID/PW가 정상적으로 들어와서 로그인 완료 시 토큰 생성해서 응답으로 전달
		// 요청 시 header의 Authorization의 value 값으로 토큰을 가져온다.
		// 가져온 토큰이 자신이 만든 토큰인지 검증만 하면 된다.(RSA, HS256)
		if(req.getMethod().equals("POST")) {
			String headerAuth = req.getHeader("Authorization");
			System.out.println(headerAuth);	
			System.out.println("필터3");
			
			if(headerAuth.equals("cos")) {
				chain.doFilter(req, res);
			} else {
				PrintWriter out = res.getWriter();
				out.println("인증 X");
			}
		}
	}

}
