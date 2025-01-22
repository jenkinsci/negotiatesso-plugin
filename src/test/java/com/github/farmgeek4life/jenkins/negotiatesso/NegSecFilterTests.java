package com.github.farmgeek4life.jenkins.negotiatesso;

import jakarta.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.mockito.Mockito;

@WithJenkins
class NegSecFilterTests {

    @Test
    void test_cleanRequest(JenkinsRule rule) {
        assertEquals("/whoAmI", NegSecFilter.cleanRequest("http://host:8080/whoAmI"));
        assertEquals("/whoAmI", NegSecFilter.cleanRequest("http://host/whoAmI"));
        assertEquals("/securityRealm", NegSecFilter.cleanRequest("http://host/securityRealm"));
        assertEquals("/job/jobName", NegSecFilter.cleanRequest("https://host:8080/job/jobName"));
        assertEquals("/git/notifyCommit", NegSecFilter.cleanRequest("http://host:8080/git/notifyCommit?url=http://gitserver/gitrepo.git"));
        assertEquals("/whoAmI", NegSecFilter.cleanRequest("/whoAmI"));
        assertEquals("/git/notifyCommit", NegSecFilter.cleanRequest("/git/notifyCommit?url=http://gitserver/gitrepo.git"));
    }

    @Test
    void test_shouldAttemptAuthentication(JenkinsRule rule) {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

        assertTrue(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/job/SomeJob"));
        assertTrue(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/job/notifyCommit"));
        assertTrue(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/"));

        // In the 'cloned' implementation, /userContent was part of ALWAYS_READABLE_PATHS; that is actually not correct
        assertTrue(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/userContent"));

        //computer slave-agent jnlp - should require authentication here.
        // Disabled: exception being thrown in call to Jenkins.isSubjectToMandatoryReadPermissionCheck(rest)
        //assertTrue(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/computer/someHostname/slave-agent.jnlp"));
    }

    @Test
    void test_shouldNotAttemptAuthentication(JenkinsRule rule) {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getParameter("encrypt")).thenReturn("true");

        // ALWAYS_READABLE_PATHS
        assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/login"));
        assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/tcpSlaveAgentListener"));
        assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/securityRealm"));

        //computer slave-agent jnlp
        // Disabled: exception being thrown in call to Jenkins.isSubjectToMandatoryReadPermissionCheck(rest)
        //assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/computer/someHostname/slave-agent.jnlp"));

        // Unprotected root actions, built in
        assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/cli"));
        assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/jnlpJars"));
        assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/whoAmI"));
        // Disabled: This was changed into a plugin, so it fails in the test harness because the plugin is not installed
        //assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/instance-identity"));
        // others include 'assetManager', 'wsagents' (when supported/enabled), 'static-files'

        // Unprotected root actions, separate plugins - must be installed in the testing jenkins instance to work
        //assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/subversion/notifyCommit"));
        //assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/git/notifyCommit"));
        //assertFalse(NegSecFilter.shouldAttemptAuthentication(rule.jenkins, request, "/mercurial/notifyCommit"));
    }
}
