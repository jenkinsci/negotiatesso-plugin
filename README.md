# NegotiateSSO

A SSO plugin for Jenkins 1.580 and above, running on Windows in a domain environment, using only the built-in Jetty web server.
For proper functionality (in my testing) Jenkins needs to be running as a service (in particular, as Local System) and there needs to be the appropriate SPNs for the host system on the domain.

This uses the Waffle security classes to operate the single sign on, and relies the permissions settings of the Active Directory plugin for user permissions.

As a side note, do not enable impersonation unless every user who has permissions to edit job configurations also has write privileges on the corresponding workspaces...

This started because of I failed to get KerberosSSO working on a Jenkins instance running on a Windows server, and so, apparently, have the creators of KerberosSSO. So I set out to create an extension that did have working SSO for an ActiveDirectory domain.
This started out heavily based on the KerberosSSO plugin (see https://wiki.jenkins-ci.org/display/JENKINS/Kerberos+SSO+Plugin and https://github.com/jenkinsci/kerberos-sso-plugin), and then suffered the massive changes as I replaced the entire functionality of the extension, as well as how it was implemented (from using Plugin to instead use extension points). However, I have kept some code and duplicated some later changes. There are some licenses (the MIT license) involved with this, and they will be taken care of when I get around to it.