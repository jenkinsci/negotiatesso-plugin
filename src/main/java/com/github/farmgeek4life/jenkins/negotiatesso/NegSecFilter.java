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
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.acegisecurity.context.SecurityContextHolder;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableSet;
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
        LOGGER.log(Level.FINEST, "Request URI: " + requestUri);
        if (!shouldAttemptAuthentication(Jenkins.getInstance(), httpRequest, requestUri)) {
			LOGGER.log(Level.FINER, "Bypassing authentication for " + requestUri);
            chain.doFilter(request, response);
            return;
        }
        
        if (this.allowLocalhost && httpRequest.getLocalAddr().equals(httpRequest.getRemoteAddr())) {
            // User is localhost, and we want to skip authenticating localhost
            chain.doFilter(request, response);
            return;
        }
        
        if (this.redirectEnabled && !httpRequest.getLocalAddr().equals(httpRequest.getRemoteAddr())) {
            // If local and remote addresses are identical, user is localhost and shouldn't be redirected
            String requestedURL = httpRequest.getRequestURL().toString();
            String requestedDomain = new URL(requestedURL).getHost();
            if (!requestedDomain.toLowerCase().contains(this.redirect.toLowerCase())) {
                String redirectURL = requestedURL.replaceFirst(requestedDomain, requestedDomain + "." + this.redirect);
                HttpServletResponse httpResponse = (HttpServletResponse)response;
                httpResponse.sendRedirect(redirectURL);
                return;
            }
        }
        
        // A user is "always" authenticated by Jenkins as anonymous when not authenticated in any other way.
        if (SecurityContextHolder.getContext().getAuthentication() == null
                || !SecurityContextHolder.getContext().getAuthentication().isAuthenticated()
                || Functions.isAnonymous()) {
            Functions.advertiseHeaders((HttpServletResponse)response); //Adds headers for CLI
        //    logger.log(Level.FINE, "Filtering request");
        //    super.doFilter(request, response, chain);
        }
        //else
        //{
        //    logger.log(Level.FINE, "Bypassing filter - already authenticated");
        //    chain.doFilter(request, response);
        //}
        
        super.doFilter(request, response, chain); // This will also call the filter chaining
    }
    
    /**
     * Copied from Jenkins.ALWAYS_READABLE_PATHS. Should request a public access to it, or a split function.
     * Urls that are always visible without READ permission.
     *
     * <p>See also:{@link #getUnprotectedRootActions}.
     */
    private static final ImmutableSet<String> ALWAYS_READABLE_PATHS = ImmutableSet.of(
        "/login",
        "/logout",
        "/accessDenied",
        "/adjuncts/",
        "/error",
        "/oops",
        "/signup",
        "/tcpSlaveAgentListener",
        "/federatedLoginService/",
        "/securityRealm",
        "/userContent" // not added in Jenkins.java, but obviously needed in this case...
    );
    
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
        for (String name : ALWAYS_READABLE_PATHS) {
            if (rest.startsWith(name)) {
                LOGGER.log(Level.FINER, "NoAuthRequired: Always readable path: " + rest);
                return false;
            }
        }
        
        // uses Stapler.getCurrentRequest().getParameter("encrypt") in Jenkins.getTarget()
        if (rest.matches("/computer/[^/]+/slave-agent[.]jnlp") 
                && "true".equals(request.getParameter("encrypt"))) {
                LOGGER.log(Level.FINER, "NoAuthRequired: Slave agent jnlp: " + rest);
            return false;
        }
        
        // remaining checks require access to jenkins 
        // if no access to jenkins, assume authentication should be attempted
        if (jenkins == null) {
            return true;
        }
        
        for (String name : jenkins.getUnprotectedRootActions()) {
            if (rest.startsWith("/" + name + "/") || rest.equals("/" + name)) {
                LOGGER.log(Level.FINER, "NoAuthRequired: Unprotected root action: " + rest);
                return false;
            }
        }

    	return true;
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
