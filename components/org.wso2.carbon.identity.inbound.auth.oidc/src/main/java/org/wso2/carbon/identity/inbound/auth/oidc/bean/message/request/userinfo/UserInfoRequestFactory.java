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

package org.wso2.carbon.identity.inbound.auth.oidc.bean.message.request.userinfo;


import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.OAuth2IdentityRequestFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Utils;
import org.wso2.carbon.identity.inbound.auth.oidc.exception.OIDCClientException;

import java.io.IOException;
import java.util.Scanner;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;

public class UserInfoRequestFactory extends OAuth2IdentityRequestFactory {

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        if(super.canHandle(request, response)) {
            return request.getRequestURI().contains("/userinfo");
        }
        return false;
    }

    @Override
    public UserInfoRequest.UserInfoRequestBuilder create(HttpServletRequest request,
                                                           HttpServletResponse response) throws
                                                                                         OAuth2ClientException {

        UserInfoRequest.UserInfoRequestBuilder builder = new UserInfoRequest.UserInfoRequestBuilder();
        create(builder, request, response);
        return builder;
    }

    @Override
    public void create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request,
                       HttpServletResponse response) throws OAuth2ClientException {

        UserInfoRequest.UserInfoRequestBuilder userInfoRequestBuilder =
                (UserInfoRequest.UserInfoRequestBuilder)builder;
        super.create(userInfoRequestBuilder, request, response);
        boolean isBearerTokenAuthzHeader = isBearerTokenAuthzHeader(request);
        boolean isBearerTokenFormPost = isBearerTokenFormPost(request);
        String accessToken = null;
        if(isBearerTokenAuthzHeader && !isBearerTokenFormPost) {
            accessToken = extractAccessTokenFromAuthzHeader(request);
        } else if(!isBearerTokenAuthzHeader && isBearerTokenFormPost) {
            accessToken = extractAccessTokenFromFormBody(request);
        } else {
            throw OIDCClientException.error("Invalid userinfo request - Bearer token profile violation.");
        }
        userInfoRequestBuilder.setAccessToken(accessToken);
    }

    private boolean isBearerTokenAuthzHeader(HttpServletRequest request) {

        String authzHeader = request.getHeader(OAuth.HeaderType.AUTHORIZATION);
        if (StringUtils.isNotBlank(authzHeader)) {
            String[] authzHeaderInfo = authzHeader.trim().split(" ");
            if (OAuth.OAUTH_BEARER_TOKEN.equals(authzHeaderInfo[0])) {
                return true;
            }
        }
        return false;
    }

    private boolean isBearerTokenFormPost(HttpServletRequest request) {

        String token = request.getParameter(OAuth.OAUTH_ACCESS_TOKEN);
        if (StringUtils.isNotBlank(token)) {
            return true;
        }
        return false;
    }

    private String extractAccessTokenFromAuthzHeader(HttpServletRequest request) throws OIDCClientException {

        String authzHeader = request.getHeader(OAuth.HeaderType.AUTHORIZATION);
        String[] authzHeaderInfo = authzHeader.trim().split(" ");
        if(authzHeaderInfo.length == 2) {
            if(StringUtils.isNotBlank(authzHeaderInfo[1])) {
                return authzHeaderInfo[1];
            }
        }
        throw OIDCClientException.error("Bearer access token cannot be found in Authorization header.");
    }

    private String extractAccessTokenFromFormBody(HttpServletRequest request) throws OIDCClientException {

        String contentTypeHeaders = request.getHeader(HttpHeaders.CONTENT_TYPE);
        if (StringUtils.isEmpty(contentTypeHeaders)) {
            throw OIDCClientException.error("Content-Type header is missing.");
        }
        String body = getBody(request);
        if (!(contentTypeHeaders.trim()).contains(OAuth.ContentType.URL_ENCODED)) {
            throw OIDCClientException.error("Content-Type header is wrong.");
        }
        if (!OAuth2Utils.isPureAscii(body)) {
            throw OIDCClientException.error("Body contains non ASCII characters");
        }
        String[] accessTokens = request.getParameterValues(OAuth.OAUTH_ACCESS_TOKEN);
        if (accessTokens.length > 1) {
            throw OIDCClientException.error("Request contains more than one " + OAuth.ContentType
                    .URL_ENCODED + "access tokens.");
        }
        return accessTokens[0];
    }

    private String getBody(HttpServletRequest request) {

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
        return stringBuilder.toString();
    }
}
