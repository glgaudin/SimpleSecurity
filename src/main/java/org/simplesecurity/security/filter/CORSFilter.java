package org.simplesecurity.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

public class CORSFilter implements Filter{

	@Override
	public void destroy() {
		
		
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		((HttpServletResponse)response).setHeader( "Access-Control-Allow-Origin", "*" ); 
		((HttpServletResponse)response).setHeader( "Access-Control-Allow-Headers", "X-Token" ); 
		((HttpServletResponse)response).setHeader( "Access-Control-Expose-Headers", "X-Token" ); 
		((HttpServletResponse)response).setHeader( "Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE" ); 
		((HttpServletResponse)response).setHeader( "Cache-Control", "no-cache"); 
		chain.doFilter( request, response );
		
	}

	@Override
	public void init(FilterConfig arg0) throws ServletException {
		
		
	}

}
