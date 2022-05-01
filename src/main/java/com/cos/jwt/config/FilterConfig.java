package com.cos.jwt.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;

@Configuration
public class FilterConfig {

	@Bean
	public FilterRegistrationBean<MyFilter1> filter1() {
		FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<MyFilter1>(new MyFilter1());
		bean.addUrlPatterns("/*"); // 모든 요청에 필터 적용
		bean.setOrder(1); // 낮은 번호가 필터 중에서 가장 먼저 실행
		
		return bean;
	}
	
	@Bean
	public FilterRegistrationBean<MyFilter2> filter2() {
		FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<MyFilter2>(new MyFilter2());
		bean.addUrlPatterns("/*"); // 모든 요청에 필터 적용
		bean.setOrder(0); // 낮은 번호가 필터 중에서 가장 먼저 실행
		
		return bean;
	}
}
