# NegotiateSSO

A SSO plugin for Jenkins 1.580 and above, running on Windows in a domain environment, using only the built-in Jetty web server.
For proper functionality (in my testing) Jenkins needs to be running as a service (in particular, as Local System) and there needs to be the appropriate SPNs for the host system on the domain.

This uses the Waffle security classes to operate the single sign on, and relies the permissions settings of the Active Directory plugin for user permissions.

As a side note, do not enable impersonation unless every user who has permissions to edit job configurations also has write privileges on the corresponding workspaces...
