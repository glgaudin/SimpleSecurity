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
package org.simplesecurity.security;

import java.util.Set;
/**
 * Interface representing a secured user in a system.  Can be implemented by any model including 
 * an entity class.
 * 
 * @author glgau
 *
 */
public interface SecuredUser {

	/**
	 * return the id
	 * 
	 * @return
	 */
	Integer getId();

	/**
	 * set the id
	 * 
	 * @param id
	 */
	void setId(Integer id);
	
	/**
	 * return the username
	 * 
	 * @return
	 */
	String getUsername();

	/**
	 * set the username
	 * 
	 * @param username
	 */
	void setUsername(String username);

	/**
	 * return the password
	 * 
	 * @return
	 */
	String getPassword();

	/** 
	 * set the password
	 *  
	 * @param password
	 */
	void setPassword(String password);

	/**
	 * return the set of permissions for the user
	 * 
	 * @return
	 */
	Set<? extends SecuredUserPermission> getUserPermissions();

	/**
	 * set the set of permissions for the user
	 * 
	 * @param userPermissions
	 */
	void setUserPermissions(Set<? extends SecuredUserPermission> userPermissions);

}