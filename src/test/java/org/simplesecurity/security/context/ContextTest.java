package org.simplesecurity.security.context;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.junit.Before;
import org.junit.Test;
import org.simplesecurity.security.SecuredUser;
import org.simplesecurity.security.SecuredUserAuthority;

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
					assertThat(USER1, is(SecurityContext.getUserContext().getUser().getFirstName()));
					System.err.println("thread 1 " + SecurityContext.getUserContext().getUser().getFirstName());
					Thread.sleep(8000);
					assertThat(USER1, is(SecurityContext.getUserContext().getUser().getFirstName()));
					System.err.println("thread 1 " + SecurityContext.getUserContext().getUser().getFirstName());
					
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
					assertThat(USER2, is(SecurityContext.getUserContext().getUser().getFirstName()));
					System.err.println("thread 2 " + SecurityContext.getUserContext().getUser().getFirstName());
					Thread.sleep(3000);
					assertThat(USER2, is(SecurityContext.getUserContext().getUser().getFirstName()));
					System.err.println("thread 2 " + SecurityContext.getUserContext().getUser().getFirstName());
					
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

		user1.setFirstName(USER1);
		user2.setFirstName(USER2);

		u1.setUser(user1);
		u2.setUser(user2);
	}

	private class User implements SecuredUser {
		
		private String firstName;

		private String lastName;

		private String email;

		private String username;

		private String password;
		
		public String getFirstName() {
			return firstName;
		}

		public void setFirstName(String firstName) {
			this.firstName = firstName;
		}

		public String getLastName() {
			return lastName;
		}

		public void setLastName(String lastName) {
			this.lastName = lastName;
		}

		public String getEmail() {
			return email;
		}

		public void setEmail(String email) {
			this.email = email;
		}

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
		public Set<SecuredUserAuthority> getUserAuthorities() {
			return null;
		}

		@Override
		public void setUserAuthorities(Set<SecuredUserAuthority> userAuthorities) {
			
		}

	}
}
