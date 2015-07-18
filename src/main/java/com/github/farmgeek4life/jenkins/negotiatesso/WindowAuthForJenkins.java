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

import hudson.security.ACL;
import hudson.security.SecurityRealm;
import hudson.util.VersionNumber;
import java.lang.reflect.Method;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.acegisecurity.Authentication;
import org.acegisecurity.context.SecurityContext;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import waffle.windows.auth.IWindowsIdentity;
import waffle.windows.auth.IWindowsSecurityContext;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;

/**
 *
 * @author Bryson Gibbons
 */
public class WindowAuthForJenkins extends WindowsAuthProviderImpl {
    
    private static final Logger LOGGER = Logger.getLogger(NegotiateSSO.class.getName());
    
    /**
     * Called by BasicSecurityFilterProvider
     */
    @Override
    public IWindowsIdentity logonUser(final String username, final String password)
    {
       IWindowsIdentity id = super.logonUser(username, password);
       authenticateJenkins(id);
       return id;
    }
    
    /**
     * Called by NegotiateSecurityFilterProvider
     */
    @Override
    public IWindowsSecurityContext acceptSecurityToken(final String connectionId, final byte[] token, final String securityPackage) {
        IWindowsSecurityContext context = super.acceptSecurityToken(connectionId, token, securityPackage);
        authenticateJenkins(context.getIdentity());
        return context;
    }
    
    /**
     * Perform the authentication methods for Jenkins
     */
    private void authenticateJenkins(IWindowsIdentity windowsIdentity) {
        String principalName = windowsIdentity.getFqn();
        if (principalName.contains("@")) {
            principalName = principalName.substring(0, principalName.indexOf("@"));
        }
        if (principalName.contains("\\")) {
            principalName = principalName.substring(principalName.indexOf("\\") + 1);
        }
        SecurityRealm realm = Jenkins.getInstance().getSecurityRealm();
        UserDetails userDetails = realm.loadUserByUsername(principalName);
        Authentication authToken = new UsernamePasswordAuthenticationToken(
                        userDetails.getUsername(),
                        userDetails.getPassword(),
                        userDetails.getAuthorities());
        SecurityContext context = ACL.impersonate(authToken);
        if (Jenkins.getVersion().isNewerThan(new VersionNumber("1.568"))) {
            try {
                Method fireLoggedIn = SecurityListener.class.getMethod("fireLoggedIn", String.class);
                fireLoggedIn.invoke(null, userDetails.getUsername());
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Failed to invoke fireLoggedIn method {0}", e);
            }
        }
    }
}
