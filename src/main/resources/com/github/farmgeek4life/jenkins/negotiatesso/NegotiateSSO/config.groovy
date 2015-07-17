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



