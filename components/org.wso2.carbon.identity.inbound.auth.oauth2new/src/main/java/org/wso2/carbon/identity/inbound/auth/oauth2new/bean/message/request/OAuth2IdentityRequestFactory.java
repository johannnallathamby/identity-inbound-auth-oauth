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

package org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;

import java.io.IOException;
import java.util.Scanner;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class OAuth2IdentityRequestFactory extends HttpIdentityRequestFactory {

    public int getPriority() {
        return 1;
    }

    @Override
    public OAuth2IdentityRequest.OAuth2IdentityRequestBuilder create(HttpServletRequest request,
                                                                   HttpServletResponse response) throws
                                                                                                 OAuth2ClientException {

        OAuth2IdentityRequest.OAuth2IdentityRequestBuilder builder =
                new OAuth2IdentityRequest.OAuth2IdentityRequestBuilder(request, response);
        create(builder, request, response);
        return builder;
    }

    @Override
    public void create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request,
                       HttpServletResponse response) throws OAuth2ClientException {

        OAuth2IdentityRequest.OAuth2IdentityRequestBuilder oAuth2IdentityRequestBuilder =
                (OAuth2IdentityRequest.OAuth2IdentityRequestBuilder) builder;
        try {
            super.create(oAuth2IdentityRequestBuilder, request, response);

            StringBuilder stringBuilder = new StringBuilder();
            Scanner scanner = null;
            try {
                scanner = new Scanner(request.getInputStream());
            } catch (IOException e) {
                throw FrameworkRuntimeException.error("Cannot read the request body.");
            }
            while (scanner.hasNextLine()) {
                stringBuilder.append(scanner.nextLine());
            }
            oAuth2IdentityRequestBuilder.setBody(stringBuilder.toString());

        } catch (FrameworkClientException e) {
            throw OAuth2ClientException.error(e.getMessage(), e);
        }
    }
}
