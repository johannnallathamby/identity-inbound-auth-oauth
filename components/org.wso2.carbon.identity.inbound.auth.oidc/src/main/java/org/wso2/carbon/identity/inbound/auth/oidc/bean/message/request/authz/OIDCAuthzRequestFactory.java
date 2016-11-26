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

package org.wso2.carbon.identity.inbound.auth.oidc.bean.message.request.authz;

import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsTransport;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.authz.AuthzRequestFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.util.OAuth2Util;
import org.wso2.carbon.identity.inbound.auth.oidc.OIDC;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.text.ParseException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class OIDCAuthzRequestFactory extends AuthzRequestFactory {

    @Override
    public String getName() {
        return "OIDCAuthzRequestFactory";
    }

    @Override
    public int getPriority() {
        return 0;
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        if(super.canHandle(request, response)) {
            Set<String> scopes = OAuth2Util.buildScopeSet(request.getParameter(OAuth.OAUTH_SCOPE));
            if (scopes.contains(OIDC.OPENID_SCOPE)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public OIDCAuthzRequest.OIDCAuthzRequestBuilder create(HttpServletRequest request,
                                                           HttpServletResponse response) throws OAuth2ClientException {

        OIDCAuthzRequest.OIDCAuthzRequestBuilder builder = new OIDCAuthzRequest.OIDCAuthzRequestBuilder
                (request, response);
        create(builder, request, response);
        return builder;
    }

    @Override
    public void create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request,
                       HttpServletResponse response)
            throws OAuth2ClientException {

        OIDCAuthzRequest.OIDCAuthzRequestBuilder oidcAuthzRequestBuilder =
                (OIDCAuthzRequest.OIDCAuthzRequestBuilder)builder;
        super.create(oidcAuthzRequestBuilder, request, response);
        oidcAuthzRequestBuilder.setNonce(request.getParameter(OIDC.NONCE));
        oidcAuthzRequestBuilder.setDisplay(request.getParameter(OIDC.DISPLAY));
        oidcAuthzRequestBuilder.setIdTokenHint(request.getParameter(OIDC.ID_TOKEN_HINT));
        oidcAuthzRequestBuilder.setLoginHint(request.getParameter(OIDC.LOGIN_HINT));
        Set<String> prompts = OAuth2Util.buildScopeSet(request.getParameter(OIDC.PROMPT));
        if(prompts.contains(OIDC.Prompt.NONE) && prompts.size() > 1){
            throw OAuth2ClientException.error("Prompt value 'none' cannot be used with other " +
                                              "prompts. Prompt: " + request.getParameter(OIDC.PROMPT));
        }
        oidcAuthzRequestBuilder.setPrompts(prompts);
        if (prompts.contains(OIDC.Prompt.LOGIN)) {
            oidcAuthzRequestBuilder.setLoginRequired(true);
        }
        if(prompts.contains(OIDC.Prompt.CONSENT)) {
            oidcAuthzRequestBuilder.setConsentRequired(true);
        }
        parseClaims((OIDCAuthzRequest.OIDCAuthzRequestBuilder)builder, request, response);
    }

    protected void parseClaims(OIDCAuthzRequest.OIDCAuthzRequestBuilder builder, HttpServletRequest request,
                               HttpServletResponse response) throws OAuth2ClientException {

        Set<OIDCAuthzRequest.Claim> claims = new HashSet();
        String claimsParam = request.getParameter("claims");
        JSONObject object = null;
        try {
            object = com.nimbusds.jose.util.JSONObjectUtils.parse(claimsParam);
        } catch (ParseException e) {
            throw OAuth2ClientException.error("Error occurred while parsing claims parameter " + claims);
        }
        JSONObject userinfo = (JSONObject)object.get("userinfo");
        JSONObject idToken = (JSONObject)object.get("id_token");
        JSONObject[] array = new JSONObject[] {userinfo, idToken};
        for(int i = 0; i < 2 ; i++) {
            String claimURI = null;
            ClaimsTransport claimsTransport = i == 0 ? ClaimsTransport.USERINFO : ClaimsTransport.ID_TOKEN;
            ClaimRequirement claimRequirement = ClaimRequirement.VOLUNTARY;
            String value = null;
            List<String> values = null;
            JSONObject item = array[i];
            for (Map.Entry<String, Object> entry : item.entrySet()) {
                claimURI = entry.getKey();
                JSONObject claimAttrs = (JSONObject) entry.getValue();
                if (claimAttrs != null) {
                    if(claimAttrs.get("essential") != null && (Boolean) claimAttrs.get("essential")) {
                        claimRequirement = ClaimRequirement.ESSENTIAL;
                    }
                    value = (String) claimAttrs.get("value");
                    JSONArray jsonValues = (JSONArray) claimAttrs.get("values");
                    if (jsonValues != null && !jsonValues.isEmpty()) {
                        Iterator ite = jsonValues.iterator();
                        while (ite.hasNext()) {
                            String next = (String) ite.next();
                            values.add(next);
                        }
                    }
                }
                OIDCAuthzRequest.Claim claim = new OIDCAuthzRequest.Claim(claimURI, claimsTransport,
                                                                          claimRequirement, value, values);
                builder.addClaim(claim);
            }
        }
    }
}
