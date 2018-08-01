package org.simplesecurity.security.aspect;

import static org.simplesecurity.security.SecurityConstants.HEADER_SECURITY_TOKEN;

import javax.servlet.http.HttpServletResponse;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.simplesecurity.security.reponse.TokenValidationResponse;
import org.simplesecurity.security.service.SecurityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
@Aspect
public class SecurityAspect {
	@Autowired
	private SecurityService securityService;

	@Before(value = "@annotation(org.simplesecurity.security.annotation.Secure) && execution(* *(..))")
	public void before(JoinPoint joinPoint) throws Throwable {
		HttpServletResponse httpResponse = (HttpServletResponse) joinPoint.getArgs()[0];
		String token = (String) joinPoint.getArgs()[1];

		// validate and add new token to response
		TokenValidationResponse validationResponse = securityService.validate(token);
		httpResponse.addHeader(HEADER_SECURITY_TOKEN, validationResponse.getToken());

	}

}
