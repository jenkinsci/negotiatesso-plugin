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

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runners.model.Statement;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * UI tests for the global configuration page of the plugin.
 * @author Bryson Gibbons
 */
public class NegotiateConfigTests {
    /**
     * Time limit in seconds for timed tests.
     */
    public static final int TIME_LIMIT = 10;

    /**
     * Jenkins rule instance.
     */
    // CS IGNORE VisibilityModifier FOR NEXT 3 LINES. REASON: Mocks tests.
    @Rule
    public RestartableJenkinsRule rule = new RestartableJenkinsRule();
    
    /**
     * 
     */
    private boolean IsWindowsOS() {
        return System.getProperty("os.name").toLowerCase().contains("win");
    }

    /**
     * Tests if Negotiate SSO plugin has a section on the global config page.
     */
    @Test
    public void testNegotiateHasConfigPage() {
        rule.addStep(new Statement() {
            @Override public void evaluate() throws Throwable {
                HtmlPage currentPage = rule.j.createWebClient().goTo("configureSecurity");
                HtmlElement enabled = currentPage.getElementByName("_.enabled");
                assertNotNull("Negotiate configuration page missing.", enabled);
            }
        });

    }

    /**
     * Tests if Negotiate SSO plugin block can be expanded.
     */
    @Test
    public void testEnableNegotiate() {
        rule.addStep(new Statement() {
            @Override public void evaluate() throws Throwable {
                HtmlPage currentPage = rule.j.createWebClient().goTo("configureSecurity");
                HtmlElement enabled = currentPage.getElementByName("_.enabled");
                enabled.fireEvent("click");
                assertNotNull("Optional block wasn't expanded.", currentPage.getElementByName("_.redirectEnabled"));
            }
        });
    }

    /**
     * Tests if the NegotiateSSO class changes attributes if a new config is submitted.
     * @throws Exception if something goes wrong
     */
    @Test
    public void testIfConfigCanBeUpdated() throws Exception {
        rule.addStep(new Statement() {
            @Override public void evaluate() throws Throwable {
                assertFalse("Plugin already enabled", NegotiateSSO.getInstance().getEnabled());
                
                HtmlPage currentPage = rule.j.createWebClient().goTo("configureSecurity");
                HtmlForm form = currentPage.getFormByName("config");
                assertNotNull(form);

                form.getInputByName("_.enabled").click();
                form.getSelectByName("_.principalFormat").setSelectedAttribute("both", true);
                form.getSelectByName("_.roleFormat").setSelectedAttribute("sid", true);

                try {
                    rule.j.submit(form);
                    // CS IGNORE EmptyBlock FOR NEXT 3 LINES. REASON: Mocks Tests.
                } catch (FailingHttpStatusCodeException e) {
                    // Expected since filter cannot be added to Jenkins rule.
                }

                boolean wasEnabled = NegotiateSSO.getInstance().getEnabled();
                if (IsWindowsOS()) {
                    assertTrue("Plugin wasn't enabled after saving the new config", wasEnabled);
                }
                else {
                    assertFalse("Plugin was enabled on a non-Windows OS", wasEnabled);
                }
            }
        });
    }
}
