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
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
//import javax.servlet.http.HttpServletRequest;
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
}
