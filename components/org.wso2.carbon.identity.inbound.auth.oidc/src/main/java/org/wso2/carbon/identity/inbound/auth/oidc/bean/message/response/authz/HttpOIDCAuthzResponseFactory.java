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

package org.wso2.carbon.identity.inbound.auth.oidc.bean.message.response.authz;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz.AuthzResponse;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz.HttpAuthzResponseFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.inbound.auth.oidc.bean.message.response.token.OIDCTokenResponse;
import org.wso2.carbon.identity.inbound.auth.oidc.model.OIDCServerConfig;
import org.wso2.carbon.identity.inbound.auth.oidc.util.OIDCUtils;

public class HttpOIDCAuthzResponseFactory extends HttpAuthzResponseFactory {

    @Override
    public String getName() {
        return "HttpOIDCAuthzResponseFactory";
    }

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        if(identityResponse instanceof OIDCAuthzResponse) {
            return true;
        }
        return false;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {

        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse.HttpIdentityResponseBuilder();
        create(builder, identityResponse);
        return builder;
    }

    @Override
    public void create(HttpIdentityResponse.HttpIdentityResponseBuilder builder, IdentityResponse identityResponse) {

        OIDCAuthzResponse authzResponse = ((OIDCAuthzResponse)identityResponse);
        IDTokenClaimsSet idTokenClaimsSet = authzResponse.getIdTokenClaimsSet();
        String idToken = createIDToken(idTokenClaimsSet, authzResponse).serialize();
        authzResponse.getBuilder().setParam("id_token", idToken);

        OAuthResponse response = null;
        try {
            response = authzResponse.getBuilder().buildQueryMessage();
        } catch (OAuthSystemException e) {
            throw OAuth2RuntimeException.error("Error occurred while building query message for authorization " +
                                               "response");
        }
        builder.setStatusCode(response.getResponseStatus());
        builder.setHeaders(response.getHeaders());
        builder.addHeader(OAuth2.Header.CACHE_CONTROL,
                          OAuth2.HeaderValue.CACHE_CONTROL_NO_STORE);
        builder.addHeader(OAuth2.Header.PRAGMA,
                          OAuth2.HeaderValue.PRAGMA_NO_CACHE);
    }

    protected JWT createIDToken(IDTokenClaimsSet claimSet, OIDCAuthzResponse response) {

        JWTClaimsSet jwtClaimsSet = null;
        try {
            jwtClaimsSet = claimSet.toJWTClaimsSet();
        } catch (ParseException e) {
            throw OAuth2RuntimeException.error("Error occurred while parsing IDTokenClaimSet to JWTClaimSet");
        }
        if (JWSAlgorithm.NONE.equals(OIDCServerConfig.getInstance().getIdTokenSigAlg())) {
            return new PlainJWT(jwtClaimsSet);
        }
        return signJWT(jwtClaimsSet, response.getTenantDomain());
    }

    /**
     * Generic Signing function
     *
     * @param jwtClaimsSet contains JWT body
     * @param tenantDomain
     * @return signed JWT
     */
    protected SignedJWT signJWT(JWTClaimsSet jwtClaimsSet, String tenantDomain)  {

        Algorithm sigAlg = OIDCServerConfig.getInstance().getIdTokenSigAlg();
        if (JWSAlgorithm.RS256.equals(sigAlg) || JWSAlgorithm.RS384.equals(sigAlg) ||
            JWSAlgorithm.RS512.equals(sigAlg)) {
            return OIDCUtils.signJWTWithRSA(jwtClaimsSet, tenantDomain);
        } else if (JWSAlgorithm.HS256.equals(sigAlg) || JWSAlgorithm.HS384.equals(sigAlg) ||
                   JWSAlgorithm.HS512.equals(sigAlg)) {
            // return signWithHMAC(jwtClaimsSet,jwsAlgorithm,request); implementation need to be done
            return null;
        } else {
            // return signWithEC(jwtClaimsSet,jwsAlgorithm,request); implementation need to be done
            return null;
        }
    }
}
