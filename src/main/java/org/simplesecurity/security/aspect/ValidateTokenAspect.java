/*
 * Copyright (C) 2018 Gregg Gaudin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */
package org.simplesecurity.security.aspect;

import java.lang.reflect.Method;

import javax.servlet.http.HttpServletResponse;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.simplesecurity.security.annotation.ValidateToken;
import org.simplesecurity.security.context.SecurityContext;
import org.simplesecurity.security.service.SecurityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
/**
 * Aspect that works in conjunction with the Secure annotation to validate a user's token
 * before invoking a method
 * 
 * @author glgau
 *
 */
@Component
@Aspect
@Order(2)
public class ValidateTokenAspect {
	@Autowired
	private SecurityService securityService;

	@Before(value = "@annotation(org.simplesecurity.security.annotation.ValidateToken) && execution(* *(..))")
	public void before(JoinPoint joinPoint) throws Throwable {
		HttpServletResponse httpResponse = (HttpServletResponse) joinPoint.getArgs()[0];
		String token = (String) joinPoint.getArgs()[1];

		// validate and add new token to response
		securityService.isValidUser(httpResponse, token);
		
		// permissions are optional, only check if they exist
		MethodSignature signature = (MethodSignature) joinPoint.getSignature();
	    Method method = signature.getMethod();

	    ValidateToken annotation = method.getAnnotation(ValidateToken.class);

	    if (annotation.permissions() != null && annotation.permissions().length > 0) {
	    	SecurityContext.getUserContext().hasPermissions(annotation.permissions());
	    }
		
	}

}
