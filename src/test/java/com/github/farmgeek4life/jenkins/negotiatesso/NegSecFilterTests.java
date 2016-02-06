package com.github.farmgeek4life.jenkins.negotiatesso;

import javax.servlet.http.HttpServletRequest;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Rule;

import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.mockito.Mockito;

public class NegSecFilterTests {
    /**
     * Time limit in seconds for timed tests.
     */
    public static final int TIME_LIMIT = 10;
    
    /**
     * Jenkins rule instance.
     */
    // CS IGNORE VisibilityModifier FOR NEXT 3 LINES. REASON: Mocks tests.
    @Rule
    public JenkinsRule rule = new JenkinsRule();
    
	@Test
    public void test_cleanRequest() {
        assertTrue(NegSecFilter.cleanRequest("http://host:8080/whoAmI").equals("/whoAmI"));
        assertTrue(NegSecFilter.cleanRequest("http://host/whoAmI").equals("/whoAmI"));
        assertTrue(NegSecFilter.cleanRequest("http://host/securityRealm").equals("/securityRealm"));
        assertTrue(NegSecFilter.cleanRequest("https://host:8080/job/jobName").equals("/job/jobName"));
        assertTrue(NegSecFilter.cleanRequest("http://host:8080/git/notifyCommit?url=http://gitserver/gitrepo.git").equals("/git/notifyCommit"));
        assertTrue(NegSecFilter.cleanRequest("/whoAmI").equals("/whoAmI"));
        assertTrue(NegSecFilter.cleanRequest("/git/notifyCommit?url=http://gitserver/gitrepo.git").equals("/git/notifyCommit"));
    }
	
	@Test
	public void test_shouldAttemptAuthentication() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        
		assertTrue(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/job/SomeJob"));
		assertTrue(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/job/notifyCommit"));
		assertTrue(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/"));
        
        //computer slava-agent jnlp
		assertTrue(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/computer/someHostname/slave-agent.jnlp"));
	}
	
	@Test
	public void test_shouldNotAttemptAuthentication() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getParameter("encrypt")).thenReturn("true");
        
        // ALWAYS_READABLE_PATHS
		assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/login"));
		assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/tcpSlaveAgentListener"));
		assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/userContent"));
        
        //computer slava-agent jnlp
		assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/computer/someHostname/slave-agent.jnlp"));
        
        // Unprotected root actions, built in
		assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/cli"));
		assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/jnlpJars"));
		assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/whoAmI"));
        
        // Unprotected root actions, bundled plugins
		assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/subversion/notifyCommit"));
        
        // Unprotected root actions, separate plugins - must be installed in the testing jenkins instance to work
		//assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/git/notifyCommit"));
		//assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/mercurial/notifyCommit"));
	}
}
