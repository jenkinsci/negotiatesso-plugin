## Changelog

[![GitHub release](https://img.shields.io/github/release/jenkinsci/negotiatesso-plugin.svg?label=changelog)](https://github.com/jenkinsci/negotiatesso-plugin/releases/latest)

##### Versions newer than 1.3

See [GitHub Releases](https://github.com/jenkinsci/negotiatesso-plugin/releases)

##### Version 1.3 (JUN 4, 2018)
-   Fix an exception introduced in version 1.2

##### Version 1.2 (JUN 4, 2018)
-   [JENKINS-55697](https://issues.jenkins-ci.org/browse/JENKINS-55697) Security-901 Set user seed on successful authentication
-   Update baseline Jenkins version to Jenkins 2.150.2
-   Update parent POM reference to 3.39
-   Update Waffle-JNA dependency to 1.9.0 (requires Java 8)
-   FireLoggedIn event does not require reflection anymore - as the pom dependency on the core changed to 1.586

##### Version 1.1 (JUN 4, 2018)
-   Adjust the logging
-   Reduced the number of times the user is actually authenticated from all requests that should be authenticated to only on requests that should be authenticated when the user session has not been authenticated.
-   Update to plugin pom 2.11
-   Make sure the settings UI always has the correct information
-   [JENKINS-32197](https://issues.jenkins-ci.org/browse/JENKINS-32197) More URLs that NegSecFilter should not secure
-   [JENKINS-30095](https://issues.jenkins-ci.org/browse/JENKINS-30095) Make Jenkins 1.586 the minimum version (Dependency version issue)
-   [JENKINS-30116](https://issues.jenkins-ci.org/browse/JENKINS-30116) NegSecFilter should not secure notifyCommit URLs
-   Remove use of functions only present in Java 1.8
-   Update to plugin pom 2.3 (but build against Jenkins 1.586)
-   Mirror the method that Jenkins uses to determine if a URI managed by a plugin should be secured (avoid needing to explicitly list each path that shouldn't be secured)

##### Version 1.0 (JUN 4, 2018)
-   First release
