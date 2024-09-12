/*
 *  The MIT License
 *
 *  Copyright (c) 2015 Bryson Gibbons. All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 * 
 *  This class extends a Waffle class. See https://github.com/dblock/waffle for 
 *  appropriate licenses for Waffle, which are not included here (as I do not 
 *  include any source code from Waffle).
 * 
 *  Portions of this code are based on the KerberosSSO plugin, also licensed 
 *  under the MIT License. See https://github.com/jenkinsci/kerberos-sso-plugin 
 *  for license details.
 */

package com.github.farmgeek4life.jenkins.negotiatesso;

/**
 *
 * @author Bryson Gibbons
 */
import hudson.Functions;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.IOException;
import java.net.URL;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import com.google.common.annotations.VisibleForTesting;
import jenkins.model.Jenkins;

import waffle.servlet.NegotiateSecurityFilter;
//import waffle.servlet.spi.SecurityFilterProviderCollection;
//import waffle.servlet.spi.BasicSecurityFilterProvider;
//import waffle.servlet.spi.NegotiateSecurityFilterProvider;

/**
 * Take a NegotiateSecurityFilter, and add a couple of items needed for Jenkins.
 * Also, add an ability to configure the FilterProviders to use, outside of init(FilterConfig)
 */
public final class NegSecFilter extends NegotiateSecurityFilter {
    private static final Logger LOGGER = Logger.getLogger(NegotiateSSO.class.getName());
    public static final String BYPASS_HEADER = "Bypass_Kerberos";
    private boolean redirectEnabled = false;
    private String redirect = "yourdomain.com";
    private boolean allowLocalhost = true;

    /**
     * Add call to advertise Jenkins headers, as appropriate.
     * @param request The request - used to check for not authorized paths, check for localhost, redirect, and chain filters
     * @param response The response - used to redirect, advertise headers, or chain filters
     * @param chain The filter chain
     * @throws java.io.IOException pass-through from request/response/chain
     * @throws javax.servlet.ServletException pass-through from request/response/chain
     */
    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {
        if ((!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) || containsBypassHeader(request)) {
            chain.doFilter(request, response);
            return;
        }
        
        HttpServletRequest httpRequest = (HttpServletRequest)request;
        String requestUri = httpRequest.getRequestURI();
        // After Jenkins 1.590:
        //Jenkins jenkins = Jenkins.getActiveInstance();
        if (!shouldAttemptAuthentication(Jenkins.get(), httpRequest, requestUri)) {
            LOGGER.log(Level.FINEST, "Bypassing authentication for {0}", requestUri);
            chain.doFilter(request, response);
            return;
        }
        
        if (this.allowLocalhost && httpRequest.getLocalAddr().equals(httpRequest.getRemoteAddr())) {
            // User is localhost, and we want to skip authenticating localhost
            LOGGER.log(Level.FINEST, "Bypassing authentication for localhost to {0}", requestUri);
            chain.doFilter(request, response);
            return;
        }
        
        if (this.redirectEnabled && !httpRequest.getLocalAddr().equals(httpRequest.getRemoteAddr())) {
            // If local and remote addresses are identical, user is localhost and shouldn't be redirected
            try {
                String requestedURL = httpRequest.getRequestURL().toString();
                String requestedDomain = new URL(requestedURL).getHost();
                if (!requestedDomain.toLowerCase().contains(this.redirect.toLowerCase())) {
                    String redirectURL = requestedURL.replaceFirst(requestedDomain, requestedDomain + "." + this.redirect);
                    HttpServletResponse httpResponse = (HttpServletResponse)response;
                    LOGGER.log(Level.FINEST, "Sending redirect for access to {0}", requestUri);
                    httpResponse.sendRedirect(redirectURL);
                    return;
                }
            }
            catch (java.net.MalformedURLException e) {
                HttpServletResponse httpResponse = (HttpServletResponse)response;
                httpResponse.sendError(404, "ERROR: Requested URL \"" + httpRequest.getRequestURL().toString() + "\" does not exist on this server.");
                LOGGER.log(Level.FINE, "Received malformed request \"{0}\" from host {1} (IP {2})", new Object[]{httpRequest.getRequestURL().toString(), httpRequest.getRemoteHost(), httpRequest.getRemoteAddr()});
                return;
            }
        }
        
        // A user is "always" authenticated by Jenkins as anonymous when not authenticated in any other way.
        if (SecurityContextHolder.getContext().getAuthentication() == null
                || !SecurityContextHolder.getContext().getAuthentication().isAuthenticated()
                || Functions.isAnonymous()) {
            Functions.advertiseHeaders((HttpServletResponse)response); //Adds headers for CLI
            LOGGER.log(Level.FINER, "Filtering request: " + requestUri);
            super.doFilter(request, response, chain); // Calls the authentication filter, which chains
        }
        else
        {
            LOGGER.log(Level.FINEST, "Bypassing filter - already authenticated: " + requestUri);
            chain.doFilter(request, response); // just continue down the filter chain
        }
        
        //super.doFilter(request, response, chain); // This will also call the filter chaining
    }
    
    /**
     * Remove the hostname and the query string from a requested URI
     * @param requestURI the requested URI
     * @return the cleaned portion of the URI
     */
    @VisibleForTesting
    static String cleanRequest(String requestURI) {
        // if the request URI starts with http, delete everything up to the first '/' following the hostname
        // if the request URI has a query string, delete it.
        return requestURI.replaceAll("^https?://[^/]+/", "/").replaceAll("\\?.*$", "");
    }
    
    /**
     * Check a request URI to see if authentication should be attempted
     * 
     * If a path is unprotected or always readable, don't attempt to authenticate.
     * Attempting to authenticate causes problems with things like the cli and notifyCommit URIs
     * @param jenkins jenkins instance; accessible for testing purposes (for getUnprotectedRootActions())
     * @param request servlet request, used to get the parameter "encrypt"
     * @param requestURI the requested URI
     * @return true if authenticated should be attempted.
     */
    @VisibleForTesting
    static boolean shouldAttemptAuthentication(Jenkins jenkins, ServletRequest request, String requestURI) {
        // NOTES:
        // Jenkins has private set ALWAYS_READABLE_PATHS, getUnprotectedRootAction(), and another
        // test that are exceptions to the permissions check. jenkins.getTarget() runs all of these,
        // but we only care about the exceptions to the permissions check.
        // Trying to use jenkins.getTarget() always seemed to test against anonymous or everyone permissions,
        // so the user was never automatically authenticated.
        
        // Code copied from Jenkins.getTarget(); need the rest, but not the permission check.
        String rest = cleanRequest(requestURI); //Stapler.getCurrentRequest().getRestOfPath() in Jenkins.getTarget()

        // isSubjectToMandatoryReadPermissionCheck() uses Stapler.getCurrentRequest().getParameter("encrypt")
        // However, this filter runs before Stapler captures the current request, which will usually lead to a NullPointerException
        // To avoid this, we manually check the slave-agent/jenkins-agent requests, and handle them in a similar fashion.
        if (isAgentJnlpPath(rest, "jenkins") || isAgentJnlpPath(rest, "slave")) {
            if ("true".equals(request.getParameter("encrypt"))) {
                LOGGER.log(Level.FINEST, "NoAuthRequired: Jenkins agent jnlp: " + rest);
                return false;
            }
            else {
                LOGGER.log(Level.FINEST, "AuthRequired: Jenkins agent jnlp: " + rest);
                return true;
            }
        }

        // Use the Jenkins core method to determine what other paths are readable without permission checks
        // First available in Jenkins version 2.37
        return Jenkins.get().isSubjectToMandatoryReadPermissionCheck(rest);
    }

    /**
     * This is copied from https://github.com/jenkinsci/jenkins/blob/master/core/src/main/java/jenkins/model/Jenkins.java
     */
    private static boolean isAgentJnlpPath(String restOfPath, String prefix) {
        return restOfPath.matches("(/manage)?/computer/[^/]+/" + prefix + "-agent[.]jnlp");
    }
    
    private static boolean containsBypassHeader(ServletRequest request) {
        if (!(request instanceof HttpServletRequest)) {
            return false;
        }
        return ((HttpServletRequest)request).getHeader(BYPASS_HEADER) != null;
    }
    
    /**
     * @param doEnable if redirect should be enabled
     * @param redirectTo the site to redirect to
     */
    public void setRedirect(boolean doEnable, String redirectTo) {
        this.redirectEnabled = doEnable;
        this.redirect = redirectTo;
    }
    
    /**
     * @param allow if localhost should bypass the SSO authentication
     */
    public void setAllowLocalhost(boolean allow) {
        this.allowLocalhost = allow;
    }
}
