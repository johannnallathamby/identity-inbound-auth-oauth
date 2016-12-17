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

package org.wso2.carbon.identity.inbound.auth.oauth2new.revoke;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;

import javax.servlet.http.HttpServletResponse;

public class RevocationResponseFactory extends HttpIdentityResponseFactory {

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        return identityResponse instanceof RevocationResponse;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {

        HttpIdentityResponse.HttpIdentityResponseBuilder responseBuilder = new
                HttpIdentityResponse.HttpIdentityResponseBuilder();
        create(responseBuilder, identityResponse);
        return responseBuilder;
    }

    @Override
    public void create(HttpIdentityResponse.HttpIdentityResponseBuilder builder, IdentityResponse identityResponse) {

        RevocationResponse revocationResponse = (RevocationResponse)identityResponse;

        builder.setStatusCode(HttpServletResponse.SC_OK);
        if (StringUtils.isNotBlank(revocationResponse.getCallback())) {
            builder.setBody(revocationResponse.getCallback() + "();");
        }
        builder.addHeader(OAuth2.Header.CACHE_CONTROL, OAuth2.HeaderValue.CACHE_CONTROL_NO_STORE);
        builder.addHeader(OAuth2.Header.PRAGMA, OAuth2.HeaderValue.PRAGMA_NO_CACHE);
        if (StringUtils.isNotBlank(revocationResponse.getCallback())) {
            builder.setContentType("application/javascript");
        } else {
            builder.setContentType("text/html");
        }
    }
}
