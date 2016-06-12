# Carbon Security Login Module - JWT
---

|  Branch | Build Status |
| :------------ |:-------------
| master      | [![Build Status](https://wso2.org/jenkins/buildStatus/icon?job=carbon-security-login-module-jwt)](https://wso2.org/jenkins/job/carbon-security-login-module-jwt) |


---
Carbon Security Login Module - JWT provides a JWT login module for the [Carbon Security](https://github.com/wso2/carbon-security.git).

## Download

Use Maven snippet:
````xml
<dependency>
    <groupId>org.wso2.carbon.security.caas.module</groupId>
    <artifactId>org.wso2.carbon.security.caas.module.jwt</artifactId>
    <version>${org.wso2.carbon.security.caas.module.jwt.version}</version>
</dependency>
````

### Snapshot Releases

Use following Maven repository for snapshot versions of Carbon Security.

````xml
<repository>
    <id>wso2.snapshots</id>
    <name>WSO2 Snapshot Repository</name>
    <url>http://maven.wso2.org/nexus/content/repositories/snapshots/</url>
    <snapshots>
        <enabled>true</enabled>
        <updatePolicy>daily</updatePolicy>
    </snapshots>
    <releases>
        <enabled>false</enabled>
    </releases>
</repository>
````

### Released Versions

Use following Maven repository for released stable versions of Carbon Security.

````xml
<repository>
    <id>wso2.releases</id>
    <name>WSO2 Releases Repository</name>
    <url>http://maven.wso2.org/nexus/content/repositories/releases/</url>
    <releases>
        <enabled>true</enabled>
        <updatePolicy>daily</updatePolicy>
        <checksumPolicy>ignore</checksumPolicy>
    </releases>
</repository>
````
## Building From Source

Clone this repository first (`git clone https://github.com/wso2-extensions/carbon-security-login-module-jwt.git`) and use Maven install to build
`mvn clean install`.

## Contributing to Carbon Security Projects

Pull requests are highly encouraged and we recommend you to create a [JIRA](https://wso2.org/jira/browse/CSECURITY) to discuss the issue or feature that you
 are contributing to.

## License

Carbon Security User Store is available under the Apache 2 License.

## Copyright

Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.