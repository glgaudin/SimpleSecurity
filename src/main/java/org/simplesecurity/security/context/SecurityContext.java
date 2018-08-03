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
package org.simplesecurity.security.context;
/**
 * Static thread-safe security context class
 *   
 * @author glgau
 *
 */
public class SecurityContext {

	private static final ThreadLocal<UserContext> contextContainer = new InheritableThreadLocal<>();

	/**
	 * return the user context
	 * 
	 * @return
	 */
	public static UserContext getUserContext() {
		return contextContainer.get();
	}

	/**
	 * set the user context
	 * 
	 * @param context
	 */
	public static void setUserContext(UserContext context) {
		// only set if non-null
		if (context != null) {
			contextContainer.set(context);
		}
	}
}