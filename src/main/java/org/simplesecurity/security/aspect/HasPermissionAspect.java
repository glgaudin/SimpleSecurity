package org.simplesecurity.security.aspect;

import java.lang.reflect.Method;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.simplesecurity.security.annotation.HasPermission;
import org.simplesecurity.security.context.SecurityContext;
import org.springframework.stereotype.Component;

@Component
@Aspect
public class HasPermissionAspect {
	
	@Before(value = "@annotation(org.simplesecurity.security.annotation.HasPermission) && execution(* *(..))")
	public void before(JoinPoint joinPoint) throws Throwable {
		
		MethodSignature signature = (MethodSignature) joinPoint.getSignature();
	    Method method = signature.getMethod();

	    HasPermission annotation = method.getAnnotation(HasPermission.class);
	    
	    SecurityContext.getUserContext().hasPermission(annotation.permission());
	}

}
