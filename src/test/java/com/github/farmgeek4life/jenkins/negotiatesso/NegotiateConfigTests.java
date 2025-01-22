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
 *  This code is based on the KerberosSSO plugin, also licensed under the MIT
 *  License. See https://github.com/jenkinsci/kerberos-sso-plugin for license
 *  details.
 */
package com.github.farmgeek4life.jenkins.negotiatesso;

import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static hudson.Functions.isWindows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * UI tests for the global configuration page of the plugin.
 * @author Bryson Gibbons
 */
@WithJenkins
class NegotiateConfigTests {

    /**
     * Tests if Negotiate SSO plugin has a section on the global config page.
     */
    @Test
    void testNegotiateHasConfigPage(JenkinsRule rule) throws Exception {
        HtmlPage currentPage = rule.createWebClient().goTo("configureSecurity");
        HtmlElement enabled = currentPage.getElementByName("_.enabled");
        assertNotNull(enabled, "Negotiate configuration page missing.");
    }

    /**
     * Tests if Negotiate SSO plugin block can be expanded.
     */
    @Test
    void testEnableNegotiate(JenkinsRule rule) throws Exception {
        HtmlPage currentPage = rule.createWebClient().goTo("configureSecurity");
        HtmlElement enabled = currentPage.getElementByName("_.enabled");
        enabled.fireEvent("click");
        assertNotNull(currentPage.getElementByName("_.redirectEnabled"), "Optional block wasn't expanded.");
    }

    /**
     * Tests if the NegotiateSSO class changes attributes if a new config is submitted.
     * @throws Exception if something goes wrong
     */
    @Test
    void testIfConfigCanBeUpdated(JenkinsRule rule) throws Exception {
        assertFalse(NegotiateSSO.getInstance().getEnabled(), "Plugin already enabled");

        HtmlPage currentPage = rule.createWebClient().goTo("configureSecurity");
        HtmlForm form = currentPage.getFormByName("config");
        assertNotNull(form);

        form.getInputByName("_.enabled").click();
        form.getSelectByName("_.principalFormat").setSelectedAttribute("both", true);
        form.getSelectByName("_.roleFormat").setSelectedAttribute("sid", true);

        rule.submit(form);

        boolean wasEnabled = NegotiateSSO.getInstance().getEnabled();
        if (isWindows()) {
            assertTrue(wasEnabled, "Plugin wasn't enabled after saving the new config");
        }
        else {
            assertFalse(wasEnabled, "Plugin was enabled on a non-Windows OS");
        }
    }
}
