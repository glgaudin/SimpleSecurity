package org.simplesecurity.security.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.stereotype.Component;

/**
 * Annotation designed to check the user permissions before a method is invoked.
 *  
 * @author glgau
 *
 */
@Component
@Target(value = {ElementType.METHOD, ElementType.TYPE})
@Retention(value = RetentionPolicy.RUNTIME)
public @interface HasPermission {

	String permission();
}
