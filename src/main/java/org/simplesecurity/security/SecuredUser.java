package org.simplesecurity.security;

import java.util.Set;

public interface SecuredUser {

	Integer getId();

	void setId(Integer id);
	
	String getFirstName();

	void setFirstName(String firstName);

	String getLastName();

	void setLastName(String lastName);

	String getEmail();

	void setEmail(String email);

	String getUsername();

	void setUsername(String username);

	String getPassword();

	void setPassword(String password);

	Set<SecuredUserPermission> getUserPermissions();

	void setUserAuthorities(Set<SecuredUserPermission> userAuthorities);

}