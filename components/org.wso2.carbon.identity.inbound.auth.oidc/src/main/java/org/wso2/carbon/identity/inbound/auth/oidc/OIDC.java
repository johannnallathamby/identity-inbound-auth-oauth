/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.inbound.auth.oidc;

import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;

public class OIDC {

    public static final String OPENID_SCOPE = "openid";
    public static final String NONCE = "nonce";
    public static final String DISPLAY = "display";
    public static final String ID_TOKEN = "id_token";
    public static final String ID_TOKEN_HINT = "id_token_hint";
    public static final String LOGIN_HINT = "login_hint";
    public static final String PROMPT = "prompt";

    public static class Prompt {
        public static final String LOGIN = "login";
        public static final String CONSENT = "consent";
        public static final String NONE = "none";
    }

    public static class IDTokenDigAlg {

        public static final String SHA256 = "SHA-256";
        public static final String SHA384 = "SHA-384";
        public static final String SHA512 = "SHA-512";
    }

    public static final String ACCESS_TOKEN = "ACCESS_TOKEN";
    public static final String USERNAME = "username";
    public static final String IDP_ENTITY_ID = "IdPEntityId";
    public static final String NONE = "none";

    public static final String OIDC_SCOPE_CONFIG_FILE_NAME = "oidc-scope-config.xml";
    public static final String OIDC_SCOPE_CONFIG_RESOURCE_PATH = "/oidc";
}
