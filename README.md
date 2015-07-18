## NegotiateSSO

A SSO plugin for Jenkins 1.580 and above, running on Windows in a domain environment, using only the built-in Jetty web server.

# Requirements:
* Jenkins is running as a service
* Jenkins is on a Windows system
* Jenkins is authenticating using the Active Directory plugin
* Service account that Jenkins uses must have kerberos authentication privileges on the domain
* Windows system account (on the domain) must be configured to allow kerberos authentication (HTTP SPNs)
* Clients accessing Jenkins must be on the same domain (Not tested in a cross-domain environment)
* Access to Jenkins using a web browser on the hosting system is recommended during initial configuration (as is leaving "Allow Localhost" checked until it all works)

For this plugin to work, Jenkins needs to be running as a service that has permission to perform kerberos authentication, and the system needs to have a domain configuration that allows kerberos authentication. See https://github.com/dblock/waffle/blob/master/Docs/Troubleshooting.md for some tips on this.

My testing configuration has Jenkins running as Local System, with HTTP/hostname and HTTP/hostname.domain SPNs.

This uses the Waffle security classes to operate the single sign on, and relies the permissions settings of the Active Directory plugin for user permissions.

As a side note, do not enable impersonation unless every user who has permissions to edit job configurations also has write privileges on the corresponding workspaces...

This started because of I failed to get KerberosSSO working on a Jenkins instance running on a Windows server, and so, apparently, have the creators of KerberosSSO. So I set out to create an extension that did have working SSO for an ActiveDirectory domain.
This started out heavily based on the KerberosSSO plugin (see https://wiki.jenkins-ci.org/display/JENKINS/Kerberos+SSO+Plugin and https://github.com/jenkinsci/kerberos-sso-plugin), and then suffered the massive changes as I replaced the entire functionality of the extension, as well as how it was implemented (from using Plugin to instead use extension points). However, I have kept some code and duplicated some later changes. There are some licenses (the MIT license) involved with this, and they will be taken care of as I get around to them (and if I have something wrong here, please tell me).