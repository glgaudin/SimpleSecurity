package org.simplesecurity.security.spring.config;

import org.simplesecurity.security.aspect.HasPermissionAspect;
import org.simplesecurity.security.aspect.SecurityAspect;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

@Configuration
@ComponentScan({ "org.simplesecurity" })
@EnableAspectJAutoProxy
public class SimpleSecurityConfig {
	
	@Bean
	public HasPermissionAspect permissionAspect() {
		return new HasPermissionAspect();
	}
 	@Bean
	public SecurityAspect securityAspect() {
		return new SecurityAspect();
	}
}
