package com.github.farmgeek4life.jenkins.negotiatesso;

//import waffle.servlet.NegotiateSecurityFilter;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.ListBoxModel;
import hudson.util.PluginServletFilter;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.GlobalConfiguration;
import jenkins.model.GlobalConfigurationCategory;
import waffle.servlet.spi.BasicSecurityFilterProvider;
import waffle.servlet.spi.NegotiateSecurityFilterProvider;
import waffle.windows.auth.IWindowsAuthProvider;

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

    private boolean allowImpersonate = true;
    private String principalFormat = "fqn";
    private String roleFormat = "fqn";
    private String protocols = "Negotiate NTLM";
    private String providers = NegotiateSecurityFilterProvider.class.getName() + " " + BasicSecurityFilterProvider.class.getName();
    private transient final IWindowsAuthProvider authProvider = new WindowAuthForJenkins();

    private transient NegSecFilter filter;

    /**
     * Fetches the singleton instance of this plugin.
     *
     * @return the instance.
     */
    /*public static NegotiateSSO getInstance() {
        Jenkins jenkins = Jenkins.getInstance();
        if (jenkins != null) {
            return jenkins.getPluginManager().getPlugin(NegotiateSSO.class);
            //return jenkins.getPlugin(NegotiateSSO.class);
        } else {
            return null;
        }
    }*/
    
    /**
     *
     * @return
     */
    @Override
    public GlobalConfigurationCategory getCategory() {
        return GlobalConfigurationCategory.get(GlobalConfigurationCategory.Security.class);
    }
    
    /**
     *
     * @return
     */
    @Override
    public String getDisplayName() {
        return "NegotiateSSO";
    }
    
    public NegotiateSSO()
    {
        super();
        //load(); // start() calls load().
        try {
            start();
        }
        catch (ServletException e)
        {
            LOGGER.log(Level.SEVERE, "Failed initialize plugin due to faulty config.", e);
            enabled = false;
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
            if (enabled) {
                startFilter();
            }
        } catch (ServletException e) {
            LOGGER.log(Level.SEVERE, "Failed initialize plugin due to faulty config.", e);
            enabled = false;
            removeFilter();
        }
    }
    
    /**
     * 
     * @throws ServletException 
     */
    private void startFilter() throws ServletException {
        if (System.getProperty("os.name").toLowerCase().indexOf("win") == -1)
        {
            LOGGER.log(Level.SEVERE, "Not a Windows OS. NegotiateSSO will not work. Plugin Disabled.");
            enabled = false;
            return;
        }
        
        LOGGER.log(Level.INFO, "Starting Security Filter");
        this.filter = new NegSecFilter();
        filter.setImpersonate(allowImpersonate);
        filter.setAuth(authProvider);
        filter.setPrincipalFormat(principalFormat); // default "fqn", options "fqn", "sid", "both"
        filter.setRoleFormat(roleFormat); // default "fqn", options "fqn", "sid", "both", "none"
        SecurityFilterConfig config = new SecurityFilterConfig();
        config.setParameter("roleFormat", roleFormat);
        config.setParameter("principalFormat", principalFormat);
        config.setParameter("impersonate", String.valueOf(allowImpersonate));
        config.setParameter("allowGuestLogin", String.valueOf(Boolean.FALSE));
        config.setParameter("securityFilterProviders", providers); // split around any whitespace: \t\n\x0B\f\r
        //config.setParameter("securityFilterProviders", NegotiateSecurityFilterProvider.class.getName()); // split around any whitespace: \t\n\x0B\f\r
        //config.setParameter("securityFilterProviders", BasicSecurityFilterProvider.class.getName()); // split around any whitespace: \t\n\x0B\f\r
        config.setParameter("authProvider", authProvider.getClass().getName());
        //config.setParameter("authProvider", WindowAuthForJenkins.class.getName());
        if (providers.contains("NegotiateSecurityFilterProvider"))
        {
            //config.setParameter("waffle.servlet.spi.BasicSecurityFilterProvider/realm", "");
            //config.setParameter("waffle.servlet.spi.NegotiateSecurityFilterProvider/protocols", "Negotiate NTLM"); // split around any whitespace: \t\n\x0B\f\r
            config.setParameter("waffle.servlet.spi.NegotiateSecurityFilterProvider/protocols", protocols); // split around any whitespace: \t\n\x0B\f\r
        }
        
        filter.init(config);
        
        // https://github.com/dblock/waffle/blob/master/Docs/tomcat/TomcatSingleSignOnValve.md
        //    fqn: Fully qualified names, such as domain\\username. When unavailable, a SID is used. This is the default.
        //    sid: SID in the S- format.
        //    both: Both a fully qualified name and a SID in the S- format. The fully qualified name is placed in the list first. Tomcat assumes that the first entry of this list is a username.
        //    none Do not include a principal name. Permitted only for roleFormat.
        PluginServletFilter.addFilter(filter);
    }

    /**
     * Safe and complete removal of the filter from the system.
     *
     * @throws ServletException if PluginServletFilter does
     */
    private void removeFilter() throws ServletException {
        if (filter != null) {
            PluginServletFilter.removeFilter(filter);
            filter.destroy();
            filter = null;
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
     * @return 
     * @throws Descriptor.FormException if any data in the form is wrong.
     * @throws IOException when adding and removing the filter.
     * @throws ServletException when the filter is created faulty config.
     */
    @Override
    public boolean configure(StaplerRequest req, JSONObject formData)
            throws Descriptor.FormException {
        try {
            
        if (System.getProperty("os.name").toLowerCase().indexOf("win") == -1)
        {
            LOGGER.log(Level.SEVERE, "Not a Windows OS. NegotiateSSO will not work. Plugin Disabled.");
            removeFilter();
            enabled = false;
        }
        else if (formData.has("enabled")) {

            JSONObject data = (JSONObject) formData.get("enabled");

            if (!data.has("allowImpersonate") || !data.has("roleFormat") || !data.has("principalFormat")) {
                throw new Descriptor.FormException("Malformed form recieved. Try again.", "enabled");
                //return false;
            }

            //Then processing data that it's up to the user to get correct.
            this.enabled = true;

            this.allowImpersonate = (Boolean) data.get("allowImpersonate");
            this.roleFormat = (String) data.get("roleFormat");
            this.principalFormat = (String) data.get("principalFormat");
            this.protocols = (String) data.get("protocols");
            this.providers = (String) data.get("providers");

            removeFilter();
            startFilter();

        } else {
            removeFilter();
            enabled = false;
        }

        save();
        }
        catch (ServletException e)
        {
            LOGGER.log(Level.SEVERE, "Failed initialize plugin due to faulty config.", e);
            try {
                removeFilter();
            }
            catch (ServletException x)
            {
                // Nothing.
            }
            enabled = false;
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
        return enabled;
    }

    /**
     * Used by groovy for data-binding.
     *
     * @return the current role format
     */
    public String getRoleFormat() {
        return roleFormat;
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
        return principalFormat;
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
     * @param protocol set the principal format
     */
    public void setProtocols(String protocol) {
        this.protocols = protocol;
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
        return allowImpersonate;
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
     * Used by groovy for data-binding.
     *
     * @return the allowed provider strings
     */
    public ListBoxModel doFillProvidersItems() {
        ListBoxModel items = new ListBoxModel();
        items.add("Negotiate, then Basic", NegotiateSecurityFilterProvider.class.getName() + " " + BasicSecurityFilterProvider.class.getName());
        items.add("Negotiate only", NegotiateSecurityFilterProvider.class.getName());
        items.add("Basic (pop-up login) only", BasicSecurityFilterProvider.class.getName());
        return items;
    }
}
