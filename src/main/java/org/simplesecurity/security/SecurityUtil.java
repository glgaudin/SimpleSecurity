package org.simplesecurity.security;

import static org.simplesecurity.security.SecurityConstants.KEY_ALGORITHM;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

@Component("securityManager")
public class SecurityUtil {

	public static Key getRandonKey() {
		SecureRandom random = new SecureRandom();		
		byte[] keyBytes = new byte[16];
		random.nextBytes(keyBytes);
		return new SecretKeySpec(keyBytes, KEY_ALGORITHM.toString());
	}
	
}
