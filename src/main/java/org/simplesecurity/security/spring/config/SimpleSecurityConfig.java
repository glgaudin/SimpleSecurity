package org.simplesecurity.security.spring.config;

import org.simplesecurity.security.aspect.HasPermissionAspect;
import org.simplesecurity.security.aspect.ValidateTokenAspect;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
/**
 * Spring configuration class for the aspect portion of the security implementation
 * @author glgau
 *
 */
@Configuration
@ComponentScan({ "org.simplesecurity" })
@EnableAspectJAutoProxy
public class SimpleSecurityConfig {
	
	/**
	 * The aspect which handles permissions
	 * @return
	 */
	@Bean
	public HasPermissionAspect permissionAspect() {
		return new HasPermissionAspect();
	}
	
	/**
	 * The aspect which handles the token validation
	 * @return
	 */
 	@Bean
	public ValidateTokenAspect securityAspect() {
		return new ValidateTokenAspect();
	}
}
