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

package org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz;

import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2ServerConfig;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

public class ConsentResponseFactory extends HttpIdentityResponseFactory {

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        return identityResponse instanceof ConsentResponse;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {

        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();
        create(builder, identityResponse);
        return builder;
    }

    @Override
    public void create(HttpIdentityResponse.HttpIdentityResponseBuilder builder, IdentityResponse identityResponse) {

        ConsentResponse consentResponse = (ConsentResponse)identityResponse;

        String consentPageURL = OAuth2ServerConfig.getInstance().getConsentPageURL();

        Map<String,String[]> modifiableMap = new HashMap(consentResponse.getParameterMap());
        modifiableMap.put("application", new String[]{consentResponse.getApplicationName()});
        modifiableMap.put(OAuth2.LOGGED_IN_USER, new String[]{consentResponse.getAuthenticatedSubjectId()});
        modifiableMap.put(OAuth2.SESSION_DATA_KEY_CONSENT, new String[]{consentResponse.getSessionDataKeyConsent()});

        builder.setParameters(modifiableMap);
        builder.setStatusCode(HttpServletResponse.SC_FOUND);
        builder.setRedirectURL(consentPageURL);
    }
}
