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

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.simplesecurity.security.annotation.HasPermission;
import org.simplesecurity.security.context.SecurityContext;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
/**
 * Aspect that works in conjunction with the HasPermission annotation
 * to check a user's permission
 * 
 * @author glgau
 *
 */
@Component
@Aspect
@Order(3)
public class HasPermissionAspect {
	
	@Before(value = "@annotation(org.simplesecurity.security.annotation.HasPermission) && execution(* *(..))")
	public void before(JoinPoint joinPoint) throws Throwable {
		MethodSignature signature = (MethodSignature) joinPoint.getSignature();
	    Method method = signature.getMethod();

	    HasPermission annotation = method.getAnnotation(HasPermission.class);
	    
	    SecurityContext.getUserContext().hasPermissions(annotation.permissions());
	}

}
