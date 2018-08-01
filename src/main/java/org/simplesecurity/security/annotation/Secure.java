package org.simplesecurity.security.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.stereotype.Component;

/**
 * Annotation to be used to secure a method.  Designed to be used at the REST level but it should work 
 * the service level as well.
 * 
 * @author glgau
 *
 */
@Component
@Target(value = {ElementType.METHOD, ElementType.TYPE})
@Retention(value = RetentionPolicy.RUNTIME)
public @interface Secure {

}
