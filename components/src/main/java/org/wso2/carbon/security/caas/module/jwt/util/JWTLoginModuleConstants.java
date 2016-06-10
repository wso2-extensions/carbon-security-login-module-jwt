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

package org.wso2.carbon.security.caas.module.jwt.util;

/**
 * Constants needed for JWTLoginModule.
 */
public class JWTLoginModuleConstants {

    /**
     * JWTLoginModule specific error codes.
     */
    public enum JWTErrorMessages {

        JWT_PARSE_ERROR(10100, "Error while parsing the JWT. Possibly due to a malformed JWT."),
        SUBJECT_NOT_FOUND_ERROR(10101, "Mandatory subject claim not found in the JWT."),
        EXPIRED_JWT_ERROR(10102, "JWT is expired."),
        SIGNATURE_VERIFICATION_ERROR(10103, "Error while JWT signature verification."),
        PUBLIC_KEY_ERROR (10104, "Error while retrieving public key for alias: %s."),
        IDENTITY_STORE_ERROR(10105, "Error while retrieving user data from Identity Stores."),
        USER_NOT_FOUND_ERROR(10106, "User information cannot be found for the given username: %s.");

        private final int code;
        private final String description;

        JWTErrorMessages(int code, String description) {
            this.code = code;
            this.description = description;
        }

        public int getCode() {
            return code;
        }

        public String getDescription() {
            return description;
        }

        @Override
        public String toString() {
            return code + " - " + description;
        }
    }
}
