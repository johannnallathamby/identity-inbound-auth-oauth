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

package org.wso2.carbon.identity.inbound.auth.oauth2ext.grant.iwa.ntlm;

import com.sun.jna.platform.win32.Sspi;
import org.apache.catalina.Realm;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant.AuthorizationGrantHandler;
import waffle.apache.NegotiateAuthenticator;
import waffle.servlet.NegotiateSecurityFilter;
import waffle.util.Base64;
import waffle.windows.auth.IWindowsCredentialsHandle;
import waffle.windows.auth.impl.WindowsAccountImpl;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;
import waffle.windows.auth.impl.WindowsCredentialsHandleImpl;
import waffle.windows.auth.impl.WindowsSecurityContextImpl;

import javax.security.auth.Subject;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.Set;

public class IWANTLMGrantHandler extends AuthorizationGrantHandler {

    private static Log log = LogFactory.getLog(IWANTLMGrantHandler.class);

    @Override
    public boolean canHandle(MessageContext messageContext) {
        if(IWANTLMConstants.IWA_NTLM_GRANT_TYPE.equals(
                ((TokenMessageContext)messageContext).getRequest().getGrantType())) {
            return true;
        }
        return false;
    }

    @Override
    public void validateGrant(TokenMessageContext messageContext) throws OAuth2ClientException, OAuth2Exception {

        super.validateGrant(messageContext);

        String windowsToken = ((IWANTLMGrantRequest)messageContext.getRequest()).getWindowsToken();
        Set<String> scopes = ((IWANTLMGrantRequest)messageContext.getRequest()).getScopes();

        NegotiateSecurityFilter filter;

        filter = new NegotiateSecurityFilter();
        filter.setAuth(new WindowsAuthProviderImpl());
        try {
            filter.init(null);
        } catch (ServletException e) {
            throw OAuth2RuntimeException.error("Error while initializing Negotiate Security Filter.", e);
        }
        boolean authenticated;
        IWindowsCredentialsHandle clientCredentials;
        WindowsSecurityContextImpl clientContext;
        filter.setRoleFormat("both");

        // Logging the windows authentication object
        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.NTLM_TOKEN)) {
            log.debug("Received NTLM Token : " + windowsToken);
        }

        // client credentials handle
        clientCredentials = WindowsCredentialsHandleImpl.getCurrent(IWANTLMConstants.SECURITY_PACKAGE);
        clientCredentials.initialize();
        // initial client security context
        clientContext = new WindowsSecurityContextImpl();
        clientContext.setPrincipalName(WindowsAccountImpl.getCurrentUsername());
        clientContext.setCredentialsHandle(clientCredentials.getHandle());
        clientContext.setSecurityPackage(IWANTLMConstants.SECURITY_PACKAGE);
        clientContext.initialize(null, null, WindowsAccountImpl.getCurrentUsername());

        SimpleHttpRequest request = new SimpleHttpRequest();
        SimpleFilterChain filterChain = new SimpleFilterChain();

        while (true) {
            try {
                request.addHeader("Authorization", IWANTLMConstants.SECURITY_PACKAGE + " " + windowsToken);
                SimpleHttpResponse response = new SimpleHttpResponse();
                try {
                    filter.doFilter(request, response, filterChain);
                } catch (IOException e) {
                    throw OAuth2RuntimeException.error("Error while processing negotiate the filter.", e);
                }
                Subject subject = (Subject) request.getSession().getAttribute("javax.security.auth.subject");
                authenticated = (subject != null && !subject.getPrincipals().isEmpty());
                if (authenticated) {
                    if (log.isDebugEnabled()) {
                        log.debug("NTLM token is authenticated.");
                    }
                    //TODO: need to verify this logic of setting authorized user
                    String usernameWithDomain = WindowsAccountImpl.getCurrentUsername();
                    String username = usernameWithDomain.split("\\\\")[1];
                    messageContext.setAuthzUser(
                            AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
                    messageContext.setApprovedScopes(scopes);
                    break;
                }
                String continueToken = response.getHeader("WWW-Authenticate").
                        substring(IWANTLMConstants.SECURITY_PACKAGE.length() + 1);
                byte[] continueTokenBytes = Base64.decode(continueToken);
                Sspi.SecBufferDesc continueTokenBuffer = new Sspi.
                        SecBufferDesc(Sspi.SECBUFFER_TOKEN, continueTokenBytes);
                clientContext.initialize(clientContext.getHandle(), continueTokenBuffer, "localhost");
                windowsToken = Base64.encode(clientContext.getToken());
            } catch (Exception e) {
                throw OAuth2RuntimeException.error("Error while validating the IWA-NTLM grant.", e);
            }
        }
    }
}
