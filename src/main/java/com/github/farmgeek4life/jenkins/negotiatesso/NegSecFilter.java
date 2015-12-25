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
import java.util.StringTokenizer;
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
    private final String pathsNotAuthenticated = "userContent;cli;git;jnlpJars;subversion;whoAmI;bitbucket-hook;";
    
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
        String contextPath = httpRequest.getContextPath();
        String requestURI = httpRequest.getRequestURI();
        
        StringTokenizer notAuthPathsTokenizer = new StringTokenizer(pathsNotAuthenticated, ";");
        while (notAuthPathsTokenizer.hasMoreTokens()) {
            String token = notAuthPathsTokenizer.nextToken();
            if (token.length() < 1) {
                continue;
            }
            
            String matchString = contextPath + "/" + token;
            if (requestURI.equals(matchString) || requestURI.startsWith(matchString + "/")) {
                chain.doFilter(request, response);
                return;
            }
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
