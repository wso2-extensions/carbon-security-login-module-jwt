/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.security.caas.module.jwt.test.osgi;

import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;
import org.ops4j.pax.exam.testng.listener.PaxExam;
import org.osgi.framework.BundleContext;
import org.testng.Assert;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.kernel.context.PrivilegedCarbonContext;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;
import org.wso2.carbon.messaging.CarbonMessage;
import org.wso2.carbon.messaging.DefaultCarbonMessage;
import org.wso2.carbon.security.caas.api.ProxyCallbackHandler;
import org.wso2.carbon.security.caas.module.jwt.test.osgi.util.SecurityOSGiTestUtils;

import java.nio.file.Paths;
import java.util.List;
import javax.inject.Inject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import static org.ops4j.pax.exam.CoreOptions.systemProperty;

/**
 * JAAS OSGI Tests.
 */

@Listeners(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class JAASTests {

    @Inject
    private BundleContext bundleContext;

    @Inject
    private CarbonServerInfo carbonServerInfo;

    @Configuration
    public Option[] createConfiguration() {

        List<Option> optionList = SecurityOSGiTestUtils.getDefaultSecurityPAXOptions();

        optionList.add(systemProperty("java.security.auth.login.config").value(Paths.get(
                SecurityOSGiTestUtils.getCarbonHome(), "conf", "security", "carbon-jaas.config").toString()));

        return optionList.toArray(new Option[optionList.size()]);
    }

    @Test
    public void testJWTLogin() throws LoginException {

        PrivilegedCarbonContext.destroyCurrentContext();

        //JWT for user: admin.
        String encodedJWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6NDEwMjQyNTAwMH0.E2SstYw2upLmIf0FqYNM_hS" +
                            "PJ9j-vrYwep9nEAHu-OgxEBGU9-e1UXT9FTQ9ZJnkLgO4DypF_kAW2xbA6SOhwSpT_BQHcXJta_yCrPcnxH09vtk" +
                            "HN35zl9UzS7d3CCLaKrDNWMWnf6Z9XcbDJjOvakVhbf7UFPI0ec0fNx0RbbQ";

        CarbonMessage carbonMessage = new DefaultCarbonMessage();
        carbonMessage.setHeader("Authorization", "Bearer " + encodedJWT);

        ProxyCallbackHandler callbackHandler = new ProxyCallbackHandler(carbonMessage);
        LoginContext loginContext = new LoginContext("CarbonSecurityJWTConfig", callbackHandler);

        loginContext.login();
        Assert.assertTrue(true);
    }

    @Test
    public void testJWTLoginFailure() {

        PrivilegedCarbonContext.destroyCurrentContext();

        //JWT for username: test.
        String encodedJWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjo0MTAyNDI1MDAwfQ.UGwW7DmszZ-a2_YkNVgh9Ss-" +
                            "fIJ5rAAQj9z9d8WNdJw1D_qQKDFbYztuorXl45iUIgjkQA1gIqgVUDd8ERuhpegiELevGi-_W0cQAawy2GRV5A2k" +
                            "-y4EhQ-H065sJol4Npaw7dCTBYEbXzHYrxfcSkjXb92i8m-7mMK6pMJs5lo";

        CarbonMessage carbonMessage = new DefaultCarbonMessage();
        carbonMessage.setHeader("Authorization", "Bearer " + encodedJWT);

        ProxyCallbackHandler callbackHandler = new ProxyCallbackHandler(carbonMessage);
        LoginContext loginContext;
        try {
            loginContext = new LoginContext("CarbonSecurityJWTConfig", callbackHandler);
            loginContext.login();
            Assert.assertTrue(false, "Login succeeded for a non-existing user.");
        } catch (LoginException e) {
            Assert.assertTrue(true);
        }

    }

    @Test
    public void testExpiredJWTLogin() {
        PrivilegedCarbonContext.destroyCurrentContext();

        //Expired JWT for username: admin.
        String encodedJWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTQzMjkxNTA1MH0.k0y0nP0yvZSVF2P5HAYOdEv" +
                            "QvimqHUODkHT-XZisrTZAOTbJJzr71JqKcIF_uhb-g53dcKF4DuGGUvBTPFB1bs-NM8oS0MoOxdBqnce8G0axG7i" +
                            "5AzKIHN_S23Qj29YIPyXeITYF0Bpjl9nBjsYXw5o_v5IzF1q6jCbLptW7nW4";

        CarbonMessage carbonMessage = new DefaultCarbonMessage();
        carbonMessage.setHeader("Authorization", "Bearer " + encodedJWT);

        ProxyCallbackHandler callbackHandler = new ProxyCallbackHandler(carbonMessage);
        LoginContext loginContext;
        try {
            loginContext = new LoginContext("CarbonSecurityJWTConfig", callbackHandler);
            loginContext.login();
            Assert.assertTrue(false, "Login succeeded for an expired Signed JWT.");
        } catch (LoginException e) {
            Assert.assertTrue(true);
        }

    }

}
