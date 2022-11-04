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
 *  Portions of this code are based on the KerberosSSO plugin, also licensed 
 *  under the MIT License. See https://github.com/jenkinsci/kerberos-sso-plugin 
 *  for license details.
 */

package com.github.farmgeek4life.jenkins.negotiatesso;

import hudson.model.User;
import hudson.security.ACL;
import hudson.security.SecurityRealm;
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import waffle.servlet.NegotiateRequestWrapper;
import waffle.servlet.WindowsPrincipal;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import jenkins.security.seed.UserSeedProperty;
import org.acegisecurity.Authentication;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.kohsuke.accmod.restrictions.suppressions.SuppressRestrictedWarnings;

/**
 * A post-NegotiateAuthentication filter that will properly populate the UserSeed information for the session
 * @author Bryson Gibbons;
 */
public class NegSecUserSeedFilter implements Filter {

    @Override
    public void init(FilterConfig fc) throws ServletException {
        // Nothing to do.
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request instanceof NegotiateRequestWrapper) {
            NegotiateRequestWrapper nrw = (NegotiateRequestWrapper) request;
            WindowsPrincipal principal = (WindowsPrincipal) nrw.getUserPrincipal();
            authenticateJenkins(principal, (HttpServletRequest) request);
        }
        
        chain.doFilter(request, response);
    }
    
    /**
     * Perform the authentication methods for Jenkins
     */
    private void authenticateJenkins(WindowsPrincipal principal, HttpServletRequest httpRequest) {
        String principalName = principal.getName();
        if (principalName.contains("@")) {
            principalName = principalName.substring(0, principalName.indexOf("@"));
        }
        if (principalName.contains("\\")) {
            principalName = principalName.substring(principalName.indexOf("\\") + 1);
        }
        Jenkins jenkins = Jenkins.get();
        SecurityRealm realm = jenkins.getSecurityRealm();
        UserDetails userDetails = realm.loadUserByUsername(principalName);
        Authentication authToken = new UsernamePasswordAuthenticationToken(
                        userDetails.getUsername(),
                        userDetails.getPassword(),
                        userDetails.getAuthorities());
        ACL.as(authToken);
        populateUserSeed(httpRequest, userDetails.getUsername());              
        SecurityListener.fireLoggedIn(userDetails.getUsername());
    }
    
    /**
     * This request is in a filter before the Stapler for pre-authentication for that reason we need to keep the code
     * that applies the same logic as UserSeedSecurityListener.
     * Copied from Kerberos-SSO plugin.
     * @param httpRequest Current request.
     * @param username Authenticated username.
     */
    @SuppressRestrictedWarnings(UserSeedProperty.class)
    private void populateUserSeed(HttpServletRequest httpRequest, String username) {
        // Adapted from hudson.security.AuthenticationProcessingFilter2
        if (!UserSeedProperty.DISABLE_USER_SEED) {
            User user = User.getById(username, true);

            HttpSession newSession = httpRequest.getSession();
            UserSeedProperty userSeed = user.getProperty(UserSeedProperty.class);
            String sessionSeed = userSeed.getSeed();
            newSession.setAttribute(UserSeedProperty.USER_SESSION_SEED, sessionSeed);
        }
    }

    @Override
    public void destroy() {
        // Nothing to do.
    }
    
}
