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

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.ListBoxModel;
import hudson.util.PluginServletFilter;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest2;

import jakarta.servlet.ServletException;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.GlobalConfiguration;
import jenkins.model.GlobalConfigurationCategory;
import waffle.servlet.spi.BasicSecurityFilterProvider;
import waffle.servlet.spi.NegotiateSecurityFilterProvider;
import waffle.util.cache.CacheSupplier;

/**
 * The core of this Plugin. Handles the configuration of the Waffle
 * NegotiateSecurityFilter It also starts / stops the filter at the user's
 * request and data-binds to config.groovy.
 *
 * @author Bryson Gibbons;
 */
@Extension
public final class NegotiateSSO extends GlobalConfiguration {
    private static final Logger LOGGER = Logger.getLogger(NegotiateSSO.class.getName());

    private boolean enabled = false;

    private boolean redirectEnabled = false;
    private String redirect = "yourdomain.com";
    private boolean allowLocalhost = true;

    private boolean allowImpersonate = false;
    private String principalFormat = "fqn";
    private String roleFormat = "fqn";
    private String protocols = "Negotiate NTLM";
    private String providers = NegotiateSecurityFilterProvider.class.getName() + " " + BasicSecurityFilterProvider.class.getName();

    private transient NegSecFilter filter;
    private transient NegSecUserSeedFilter userSeedFilter;

    /**
     * Fetches the singleton instance of this plugin.
     *
     * @return the instance.
     */
    public static NegotiateSSO getInstance() {
        Jenkins jenkins = Jenkins.get();
        return jenkins.getDescriptorByType(NegotiateSSO.class);
    }

    /**
     * Get the proper category for the settings location
     * @return GlobalConfigurationCategory.Security
     */
    @Override
    public GlobalConfigurationCategory getCategory() {
        return GlobalConfigurationCategory.get(GlobalConfigurationCategory.Security.class);
    }

    /**
     * The Plugin Display name
     * @return Display name
     */
    @Override
    public String getDisplayName() {
        return "NegotiateSSO";
    }

    /**
     * Initializes and starts the filter, if enabled.
     */
    public NegotiateSSO() {
        super();
        //load(); // start() calls load().
        try {
            start();
        }
        catch (ServletException e) {
            NegotiateSSO.LOGGER.log(Level.SEVERE, "Failed initialize plugin due to faulty config.", e);
            this.enabled = false;
        }
    }

    /**
     * Starts the plugin. Loads previous configuration if such exists.
     *
     * @throws ServletException if the Waffle NTLM/Kerberos filter cannot be added to
     * Jenkins.
     */
    public void start() throws ServletException {
        load();
        try {
            if (this.enabled) {
                startFilter();
            }
        } catch (ServletException e) {
            NegotiateSSO.LOGGER.log(Level.SEVERE, "Failed initialize plugin due to faulty config.", e);
            this.enabled = false;
            removeFilter();
        }
    }

    /**
     * Initializes the filter and inserts it into the chain
     * @throws ServletException
     */
    private void startFilter() throws ServletException {
        if (!System.getProperty("os.name").toLowerCase().contains("win")) {
            NegotiateSSO.LOGGER.log(Level.SEVERE, "Not a Windows OS. NegotiateSSO will not work. Plugin Disabled.");
            this.enabled = false;
            return;
        }

        NegotiateSSO.LOGGER.log(Level.INFO, "Starting Security Filter");
        this.filter = new NegSecFilter();
        this.filter.setImpersonate(this.allowImpersonate);
        this.filter.setPrincipalFormat(this.principalFormat); // default "fqn", options "fqn", "sid", "both"
        this.filter.setRoleFormat(this.roleFormat); // default "fqn", options "fqn", "sid", "both", "none"
        this.filter.setAllowLocalhost(this.allowLocalhost);
        this.filter.setRedirect(this.redirectEnabled, this.redirect);
        SecurityFilterConfig config = new SecurityFilterConfig();
        config.setParameter("roleFormat", this.roleFormat);
        config.setParameter("principalFormat", this.principalFormat);
        config.setParameter("impersonate", String.valueOf(this.allowImpersonate));
        config.setParameter("allowGuestLogin", String.valueOf(Boolean.FALSE));
        config.setParameter("securityFilterProviders", this.providers); // split around any whitespace: \t\n\x0B\f\r
        //config.setParameter("securityFilterProviders", NegotiateSecurityFilterProvider.class.getName()); // split around any whitespace: \t\n\x0B\f\r
        //config.setParameter("securityFilterProviders", BasicSecurityFilterProvider.class.getName()); // split around any whitespace: \t\n\x0B\f\r

        //config.setParameter("allowLocalhost", String.valueOf(this.allowLocalhost));
        //config.setParameter("redirectEnabled", String.valueOf(this.redirectEnabled));
        //config.setParameter("redirect", this.redirect);
        if (this.providers.contains("NegotiateSecurityFilterProvider")) {
            //config.setParameter("waffle.servlet.spi.BasicSecurityFilterProvider/realm", "");
            //config.setParameter("waffle.servlet.spi.NegotiateSecurityFilterProvider/protocols", "Negotiate NTLM"); // split around any whitespace: \t\n\x0B\f\r
            config.setParameter("waffle.servlet.spi.NegotiateSecurityFilterProvider/protocols", protocols); // split around any whitespace: \t\n\x0B\f\r
        }

        // Modify the thread's ClassLoader context so that the ServiceLoader call in waffle-jna-jakarta can succeed
        NegotiateSSO.LOGGER.log(Level.FINEST, "adapt TCCL for waffle-jna-jakarta ServiceLoader call");
        Thread thread = Thread.currentThread();
        ClassLoader loader = thread.getContextClassLoader();
        thread.setContextClassLoader(CacheSupplier.class.getClassLoader());

        try {
            this.filter.init(config);
        } finally {
            // Reset the thread's ClassLoader context to the previous value
            NegotiateSSO.LOGGER.log(Level.FINEST, "reset TCCL");
            thread.setContextClassLoader(loader);
        }

        this.userSeedFilter = new NegSecUserSeedFilter();
        this.userSeedFilter.init(null);

        // https://github.com/dblock/waffle/blob/master/Docs/tomcat/TomcatSingleSignOnValve.md
        //    fqn: Fully qualified names, such as domain\\username. When unavailable, a SID is used. This is the default.
        //    sid: SID in the S- format.
        //    both: Both a fully qualified name and a SID in the S- format. The fully qualified name is placed in the list first. Tomcat assumes that the first entry of this list is a username.
        //    none Do not include a principal name. Permitted only for roleFormat.
        PluginServletFilter.addFilter(this.filter);
        PluginServletFilter.addFilter(this.userSeedFilter);
    }

    /**
     * Safe and complete removal of the filter from the system.
     *
     * @throws ServletException if PluginServletFilter does
     */
    private void removeFilter() throws ServletException {
        if (this.filter != null) {
            PluginServletFilter.removeFilter(this.filter);
            this.filter.destroy();
            this.filter = null;
        }

        if (this.userSeedFilter != null) {
            PluginServletFilter.removeFilter(this.userSeedFilter);
            this.userSeedFilter.destroy();
            this.userSeedFilter = null;
        }
    }

    /**
     * When submit is pressed on the global config page and any settings for
     * this plugin are changed, this method is called. It updates all the
     * fields, restarts or stops the filter depending on configuration and saves
     * the configuration to disk.
     *
     * @param req the Stapler Request to serve.
     * @param formData the JSON data containing the new configuration.
     * @return true if configuration successful; false otherwise
     * @throws Descriptor.FormException if any data in the form is wrong.
     */
    @Override
    public boolean configure(StaplerRequest2 req, JSONObject formData)
            throws Descriptor.FormException {
        try {
            if (!System.getProperty("os.name").toLowerCase().contains("win")) {
                NegotiateSSO.LOGGER.log(Level.SEVERE, "Not a Windows OS. NegotiateSSO will not work. Plugin Disabled.");
                removeFilter();
                this.enabled = false;
            }
            else if (formData.has("enabled")) {
                JSONObject data = formData.getJSONObject("enabled");

                //NegotiateSSO.LOGGER.log(Level.SEVERE, "data: " + data.toString());
                if (!data.has("allowImpersonate") || !data.has("roleFormat")
                        || !data.has("principalFormat") || !data.has("protocols")
                        || !data.has("providers") || !data.has("allowLocalhost")) {
                    throw new Descriptor.FormException("Malformed form recieved. Try again.", "enabled");
                }

                if (data.has("redirectEnabled")) {
                    JSONObject rData = data.getJSONObject("redirectEnabled");
                    //NegotiateSSO.LOGGER.log(Level.SEVERE, "rData: " + rData.toString());
                    if (rData.has("redirect")) {
                        String domain = rData.getString("redirect");
                        if (!domain.isEmpty()) {
                            this.redirectEnabled = true;
                            this.redirect = rData.getString("redirect");
                        }
                        else {
                            throw new Descriptor.FormException("Cannot specify empty domain. Try again.", "redirect");
                        }
                    }
                    else {
                        throw new Descriptor.FormException("Malformed form recieved. Try again.", "redirect");
                    }
                }
                else {
                    this.redirectEnabled = false;
                }

                //Then processing data that it's up to the user to get correct.
                this.enabled = true;

                this.allowImpersonate = data.getBoolean("allowImpersonate");
                this.roleFormat = data.getString("roleFormat");
                this.principalFormat = data.getString("principalFormat");
                this.protocols = data.getString("protocols");
                this.providers = data.getString("providers");
                this.allowLocalhost = data.getBoolean("allowLocalhost");

                removeFilter();
                startFilter();
            } else {
                removeFilter();
                this.enabled = false;
            }

            save();
        }
        catch (ServletException e) {
            NegotiateSSO.LOGGER.log(Level.SEVERE, "Failed to initialize plugin due to faulty config.", e);
            try {
                removeFilter();
            }
            catch (ServletException x) {
                // Nothing.
            }
            this.enabled = false;
            return false;
        }
        return true;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @return whether the Filter is currently enabled or not.
     */
    public boolean getEnabled() {
        return this.enabled;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @return the current role format
     */
    public String getRoleFormat() {
        return this.roleFormat;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @param format set the role format
     */
    public void setRoleFormat(String format) {
        this.roleFormat = format;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @return the current principal format
     */
    public String getPrincipalFormat() {
        return this.principalFormat;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @param format set the principal format
     */
    public void setPrincipalFormat(String format) {
        this.principalFormat = format;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @return the current protocols
     */
    public String getProtocols() {
        return protocols;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @param protocol set the principal format
     */
    public void setProtocols(String protocol) {
        this.protocols = protocol;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @return the current providers
     */
    public String getProviders() {
        return providers;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @param provider set the principal format
     */
    public void setProviders(String provider) {
        this.providers = provider;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @return whether servlet delegation should be used.
     */
    public boolean isAllowImpersonate() {
        return this.allowImpersonate;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @return whether localhost is allowed without authentication.
     */
    public boolean isAllowLocalhost() {
        return this.allowLocalhost;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @return whether unauthenticated requests should be redirected
     */
    public boolean isRedirectEnabled() {
        return this.redirectEnabled;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @return the site to redirect to
     */
    public String getRedirect() {
        return this.redirect;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @param redirect the site to redirect to
     */
    public void setRedirect(String redirect) {
        this.redirect = redirect;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @return the allowed role format strings
     */
    public ListBoxModel doFillRoleFormatItems() {
        ListBoxModel items = new ListBoxModel();
        items.add("Fully Qualified Name, fallback on SID", "fqn");
        items.add("SID", "sid");
        items.add("Both FQN and SID", "both");
        items.add("No Principal Name", "none");
        return items;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @return the allowed principal format strings
     */
    public ListBoxModel doFillPrincipalFormatItems() {
        ListBoxModel items = new ListBoxModel();
        items.add("Fully Qualified Name, fallback on SID", "fqn");
        items.add("SID", "sid");
        items.add("Both FQN and SID", "both");
        return items;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @return the allowed protocol strings
     */
    public ListBoxModel doFillProtocolsItems() {
        ListBoxModel items = new ListBoxModel();
        items.add("Negotiate, fallback on NTLM", "Negotiate NTLM");
        items.add("NTLM, fallback on Negotiate", "NTLM Negotiate");
        items.add("Negotiate only", "Negotiate");
        items.add("NTLM only", "NTLM");
        return items;
    }

    /**
     * Used by groovy for data-binding: provides a name and java classpath for an HTML 'select' element
     *
     * Suppressed warnings (for security scans):
     * * permission check: the configuration page is restricted to 'ADMINISTER' permissions, but this function is only providing the potential choices, not changing settings
     * * csrf: We do not provide routable URLs, only a text name (with spaces) and a java classpath reference for internal use
     *
     * @return the allowed provider strings
     */
    @SuppressWarnings({"lgtm[jenkins/no-permission-check]", "lgtm[jenkins/csrf]"})
    public ListBoxModel doFillProvidersItems() {
        ListBoxModel items = new ListBoxModel();
        items.add("Negotiate, then Basic", NegotiateSecurityFilterProvider.class.getName() + " " + BasicSecurityFilterProvider.class.getName());
        items.add("Negotiate only", NegotiateSecurityFilterProvider.class.getName());
        items.add("Basic (pop-up login) only", BasicSecurityFilterProvider.class.getName());
        return items;
    }
}
