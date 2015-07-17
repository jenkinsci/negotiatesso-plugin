/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.farmgeek4life.jenkins.negotiatesso;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;

/**
 * The Hackabout way to try to control provider settings for NegotiateSecurityFilter, without writing a new security provider collection class...
 * @author Bryson
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
        allowedParams.put("authProvider", Boolean.TRUE);
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
        if (ALLOWED_PARAMS.containsKey(name))
        {
            if (params.containsKey(name))
            {
                params.replace(name, value);
            }
            else
            {
                params.put(name, value);
            }
            return true;
        }
        return false;
    }
    
    @Override
    public String getFilterName() {
        return "NegSecFilter";
    }
    
    @Override
    public ServletContext getServletContext() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String getInitParameter(String string) {
        return params.get(string);
    }

    @Override
    public Enumeration getInitParameterNames() {
        String tokenizer = new String();
        for (String param : params.keySet())
        {
            tokenizer += param + ";";
        }
        return new StringTokenizer(tokenizer, ";");
    }
    
}
