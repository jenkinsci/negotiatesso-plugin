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

package com.github.farmgeek4life.jenkins.negotiatesso

import lib.FormTagLib

def form = namespace(FormTagLib)
def location = "/plugin/NegotiateSSO/"

form.section(title:"Windows Negotiate Single Sign-On") {
    form.optionalBlock(title:_("EnablePlugin"), help:location+"/help-overview.html", field:"enabled") {
        
        form.section(title:_("Windows Negotiate Single Sign On properties")) {
            form.entry(field: "principalFormat", title:_("Principal Format"), help:location+"/help-principal-format.html") {
                form.select(field: "principalFormat")
            }

            form.entry(field: "roleFormat", title:_("Role Format"), help:location+"/help-role-format.html") {
                form.select(field: "roleFormat")
            }

            form.entry(field: "providers", title:_("Authentication Packages"), help:location+"/help-providers.html") {
                form.select(field: "providers")
            }

            form.entry(field: "protocols", title:_("Authentication Protocols"), help:location+"/help-protocols.html") {
                form.select(field: "protocols")
            }

            form.entry(title:_("Allow Impersonate"), help:location+"/help-allow-impersonate.html") {
                form.checkbox(field: "allowImpersonate")
            }
                
            form.entry(title:_("Allow Localhost"), help:location+"/help-allow-localhost.html") {
                form.checkbox(field: "allowLocalhost")
            }
            
            form.optionalBlock(title:_("DoRedirect"), help:location+"/help-redirect.html", field:"redirectEnabled") {
                form.entry(title:_("RedirectTo"), field:"redirect") {
                    form.textbox(field: "redirect")
                }
            }
        }
    }
}



