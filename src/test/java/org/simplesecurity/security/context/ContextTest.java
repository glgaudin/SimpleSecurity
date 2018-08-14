package org.simplesecurity.security.context;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.junit.Before;
import org.junit.Test;
import org.simplesecurity.security.SecuredUser;
import org.simplesecurity.security.SecuredUserPermission;

public class ContextTest {

	private UserContext u1 = new UserContext();
	private UserContext u2 = new UserContext();
	
	private static final String USER1 = "user1";
	private static final String USER2 = "user2";

	@Test
	public void testContext() throws InterruptedException {
		
		final ExecutorService pool = Executors.newFixedThreadPool(2);
		
		Runnable t1 = new Runnable() {
			public void run() {
				
				SecurityContext.setUserContext(u1);
				
				try {
					System.err.println("starting thread one");
					Thread.sleep(2000);
					assertThat(USER1, is(SecurityContext.getUserContext().getUser().getUsername()));
					System.err.println("thread 1 " + SecurityContext.getUserContext().getUser().getUsername());
					Thread.sleep(8000);
					assertThat(USER1, is(SecurityContext.getUserContext().getUser().getUsername()));
					System.err.println("thread 1 " + SecurityContext.getUserContext().getUser().getUsername());
					
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
			}
		};

		Runnable t2 = new Runnable() {
			public void run() {
				
				SecurityContext.setUserContext(u2);
				
				try {
					
					System.err.println("starting thread two");
					assertThat(USER2, is(SecurityContext.getUserContext().getUser().getUsername()));
					System.err.println("thread 2 " + SecurityContext.getUserContext().getUser().getUsername());
					Thread.sleep(3000);
					assertThat(USER2, is(SecurityContext.getUserContext().getUser().getUsername()));
					System.err.println("thread 2 " + SecurityContext.getUserContext().getUser().getUsername());
					
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
			}
		};

		pool.submit(t1);
		pool.submit(t2);
		
		while (! pool.isShutdown()) {
			// hang in there!
        }		
	}

	@Before
	public void doBefore() {

		User user1 = new User();
		User user2 = new User();

		user1.setUsername(USER1);
		user2.setUsername(USER2);

		u1.setUser(user1);
		u2.setUser(user2);
	}

	private class User implements SecuredUser {
		
		private String username;

		private String password;
		

		public String getUsername() {
			return username;
		}

		public void setUsername(String username) {
			this.username = username;
		}

		public String getPassword() {
			return password;
		}

		public void setPassword(String password) {
			this.password = password;
		}

		@Override
		public Integer getId() {
			return null;
		}

		@Override
		public void setId(Integer id) {
		}

		@Override
		public Set<SecuredUserPermission> getUserPermissions() {
			return null;
		}

		@Override
		public void setUserPermissions(Set<? extends SecuredUserPermission> userPermissions) {
			
		}
	}
}
