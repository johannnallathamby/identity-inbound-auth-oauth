/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.inbound.auth.oauth2ext.grant.assertion.saml2;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.OAuth;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.XMLObject;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.TokenRequestFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SAML2AssertionGrantFactory extends TokenRequestFactory {

    private static Log log = LogFactory.getLog(SAML2AssertionGrantFactory.class);

    @Override
    public String getName() {
        return "SAML2AssertionGrantFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        if(super.canHandle(request, response)) {
            if (StringUtils.equals(SAML2GrantConstants.SAML2_GRANT_TYPE, request.getParameter(OAuth.OAUTH_GRANT_TYPE))) {
                return true;
            }
        }
        return false;
    }

    @Override
    public SAML2AssertionGrantRequest.SAML2AssertionGrantBuilder create(HttpServletRequest request,
                                                                        HttpServletResponse response)
            throws OAuth2ClientException {

        SAML2AssertionGrantRequest.SAML2AssertionGrantBuilder builder = new SAML2AssertionGrantRequest.SAML2AssertionGrantBuilder
                (request, response);
        create(builder, request, response);
        return builder;
    }

    @Override
    public void create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request,
                       HttpServletResponse response)
            throws OAuth2ClientException {

        super.create(builder, request, response);

        SAML2AssertionGrantRequest.SAML2AssertionGrantBuilder saml2AssertionGrantBuilder = (SAML2AssertionGrantRequest
                .SAML2AssertionGrantBuilder)builder;
        String assertionString = request.getParameter(OAuth.OAUTH_ASSERTION);
        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.SAML_ASSERTION)) {
            log.debug("SAML2 assertion: " + new String(Base64.decodeBase64(assertionString)));
        }
        Assertion assertion = null;
        try {
            XMLObject saml2Object = IdentityUtil.unmarshall(new String(Base64.decodeBase64(assertionString)));
            assertion = (Assertion) saml2Object;
        } catch (IdentityException e) {
            throw OAuth2ClientException.error("Error occurred while unmarshalling SAML2 assertion", e);
        } catch (ClassCastException e) {
            throw OAuth2ClientException.error("XML object is not a SAML2 assertion", e);
        }
        saml2AssertionGrantBuilder.setAssertion(assertion);
        saml2AssertionGrantBuilder.setAssertionType(request.getParameter(OAuth.OAUTH_ASSERTION_TYPE));
        saml2AssertionGrantBuilder.setScopes(OAuth2Util.buildScopeSet(request.getParameter(OAuth.OAUTH_SCOPE)));
    }
}
