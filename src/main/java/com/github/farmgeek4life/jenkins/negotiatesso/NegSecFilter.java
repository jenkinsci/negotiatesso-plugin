/**
 * Waffle (https://github.com/dblock/waffle)
 * 
* Copyright (c) 2010 - 2014 Application Security, Inc.
 * 
* All rights reserved. This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License v1.0 which
 * accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * 
* Contributors: Application Security, Inc. Modified by Bryson Gibbons for use
 * with Jenkins
 */
package com.github.farmgeek4life.jenkins.negotiatesso;

/**
 *
 * @author brysoncg
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
     * @param request
     * @param response
     * @param chain
     * @throws java.io.IOException
     * @throws javax.servlet.ServletException
     */
    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {
        
        if ((!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) || containsBypassHeader(request)) {
            chain.doFilter(request, response);
            return;
        }
        
        HttpServletRequest httpRequest = (HttpServletRequest)request;
        String userContentPath = httpRequest.getContextPath() + "/userContent";
        
        if (httpRequest.getRequestURI().startsWith(userContentPath)) {
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
    public void setRedirect(boolean doEnable, String redirectTo)
    {
        this.redirectEnabled = doEnable;
        this.redirect = redirectTo;
    }
    
    /**
     * @param allow if localhost should bypass the SSO authentication
     */
    public void setAllowLocalhost(boolean allow)
    {
        this.allowLocalhost = allow;
    }
}
