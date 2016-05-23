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

package org.wso2.carbon.security.caas.module.jwt.internal;

import org.wso2.carbon.security.caas.user.core.service.RealmService;

/**
 * Carbon security data holder.
 * @since 1.0.0
 */
public class JWTLoginModuleDataHolder {

    private static JWTLoginModuleDataHolder instance = new JWTLoginModuleDataHolder();

    private RealmService realmService;

    private JWTLoginModuleDataHolder() {
    }

    /**
     * Get the instance of this class.
     * @return CarbonSecurityDataHolder.
     */
    public static JWTLoginModuleDataHolder getInstance() {
        return instance;
    }

    public void registerCarbonRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public void unregisterCarbonRealmService() {
        this.realmService = null;
    }

    public RealmService getCarbonRealmService() {

        if (this.realmService == null) {
            throw new IllegalStateException("Carbon Realm Service is null.");
        }
        return this.realmService;
    }
}
