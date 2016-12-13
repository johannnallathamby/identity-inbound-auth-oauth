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

package org.wso2.carbon.identity.inbound.auth.oidc.handler;

import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionResponse;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2ServerConfig;
import org.wso2.carbon.identity.inbound.auth.oidc.OIDC;

public class OIDCIntrospectionHandler extends IntrospectionHandler {

    protected IntrospectionResponse.IntrospectionResponseBuilder introspectToken(
            AccessToken accessToken, IntrospectionMessageContext messageContext,
            IntrospectionResponse.IntrospectionResponseBuilder builder) {

        super.introspectToken(accessToken, messageContext,builder);
        if(ResponseType.TOKEN.toString().equals(accessToken.getGrantType()) ||
           OIDC.ResponseType.ID_TOKEN_TOKEN.equals(accessToken.getGrantType())) {
            builder.setIss(OAuth2ServerConfig.getInstance().getOAuth2AuthzEPUrl());
        } else {
            builder.setIss(OAuth2ServerConfig.getInstance().getOAuth2TokenEPUrl());
        }
        return builder;
    }
}
