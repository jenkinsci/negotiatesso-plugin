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
 */

package com.github.farmgeek4life.jenkins.negotiatesso;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletContext;

/**
 * The Hackabout way to try to control provider settings for NegotiateSecurityFilter, without writing a new security provider collection class...
 * @author Bryson Gibbons
 */
public class SecurityFilterConfig implements FilterConfig {
    private final HashMap<String, String> params = new HashMap<String, String>();
    public static final Map<String, Boolean> ALLOWED_PARAMS;
    
    static {
        HashMap<String, Boolean> allowedParams = new HashMap<String, Boolean>();
        allowedParams.put("principalFormat", Boolean.TRUE);
        allowedParams.put("roleFormat", Boolean.TRUE);
        allowedParams.put("allowGuestLogin", Boolean.TRUE);
        allowedParams.put("impersonate", Boolean.TRUE);
        allowedParams.put("securityFilterProviders", Boolean.TRUE);
        //allowedParams.put("allowLocalhost", Boolean.TRUE);
        //allowedParams.put("redirectEnabled", Boolean.TRUE);
        //allowedParams.put("redirect", Boolean.TRUE);
        // waffle.servlet.spi.BasicSecurityFilterProvider/realm
        //allowedParams.put("realm", Boolean.TRUE); // BasicSecurityFilterProvider
        allowedParams.put("waffle.servlet.spi.BasicSecurityFilterProvider/realm", Boolean.TRUE); // BasicSecurityFilterProvider
        // waffle.servlet.spi.NegotiateSecurityFilterProvider/protocols
        //allowedParams.put("PROTOCOLS", Boolean.TRUE); // NegotiateSecurityFilterProvider, valid values Negotiate, NTLM (string tokenized)
        allowedParams.put("waffle.servlet.spi.NegotiateSecurityFilterProvider/protocols", Boolean.TRUE); // NegotiateSecurityFilterProvider, valid values Negotiate, NTLM (string tokenized)
        ALLOWED_PARAMS = Collections.unmodifiableMap(allowedParams);
    }
    
    public Boolean setParameter(String name, String value) {
        if (ALLOWED_PARAMS.containsKey(name)) {
            params.put(name, value);
            return true;
        }
        return false;
    }
    
    /**
     * Filter name
     * @return The name of the filter
     */
    @Override
    public String getFilterName() {
        return "NegSecFilter";
    }
    
    /**
     * Servlet context
     * @return servlet context
     */
    @Override
    public ServletContext getServletContext() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    /**
     * Get the value for a parameter
     * @param string parameter name
     * @return parameter value
     */
    @Override
    public String getInitParameter(String string) {
        return params.get(string);
    }

    /**
     * Get an enumeration of parameter names
     * @return Enumeration of parameter names
     */
    @Override
    public Enumeration<String> getInitParameterNames() {
        return Collections.enumeration(params.keySet());
    }    
}
