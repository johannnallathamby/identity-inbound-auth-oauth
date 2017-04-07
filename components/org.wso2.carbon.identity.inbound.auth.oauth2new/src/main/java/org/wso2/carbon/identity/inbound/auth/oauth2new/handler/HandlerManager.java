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

package org.wso2.carbon.identity.inbound.auth.oauth2new.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.inbound.auth.oauth2new.OAuth2.ClientType;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.context.TokenMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.AsyncDAO;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.CacheBackedOAuth2DAO;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.OAuth2DAOHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2AuthnException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.inbound.auth.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.client.ClientAuthHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.interceptor.OAuth2EventInterceptor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.issuer.AccessTokenResponseIssuer;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.persist.TokenPersistenceProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.internal.OAuth2DataHolder;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.RORevocationMessageContext;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.RevocationMessageContext;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HandlerManager {

    private static final Log log = LogFactory.getLog(HandlerManager.class);

    private static volatile HandlerManager instance = new HandlerManager();
    private Map<String,CacheBackedOAuth2DAO> cachedDAOMap = new HashMap<>();

    private HandlerManager() {

    }

    public static HandlerManager getInstance() {
        return instance;
    }

    public ClientType clientType(OAuth2MessageContext messageContext) {

        List<ClientAuthHandler> handlers = OAuth2DataHolder.getInstance().getClientAuthHandlers();
        for(ClientAuthHandler handler:handlers){
            try {
                if (handler.isEnabled(messageContext) && handler.canHandle(messageContext)) {
                    return handler.clientType(messageContext);
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + handler.getName() + " can handle " +
                          messageContext.toString());
            }
        }
        throw OAuth2RuntimeException.error("Cannot find ClientAuthHandler to handle this request");
    }

    public void authenticateClient(OAuth2MessageContext messageContext) throws OAuth2AuthnException {

        List<ClientAuthHandler> handlers = OAuth2DataHolder.getInstance().getClientAuthHandlers();
        for(ClientAuthHandler handler:handlers){
            try {
                if (handler.isEnabled(messageContext) && handler.canHandle(messageContext)) {
                    handler.authenticate(messageContext);
                    return;
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + handler.getName() + " can handle " +
                          messageContext.toString());
            }
        }
        throw OAuth2RuntimeException.error("Cannot find ClientAuthHandler to handle this request");
    }

    public AccessToken issueAccessToken(OAuth2MessageContext messageContext) {

        List<AccessTokenResponseIssuer> handlers = OAuth2DataHolder.getInstance().getAccessTokenIssuers();
        for(AccessTokenResponseIssuer handler:handlers){
            try {
                if (handler.isEnabled(messageContext) && handler.canHandle(messageContext)) {
                    return handler.issue(messageContext);
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + handler.getName() + " can handle " +
                          messageContext.toString());
            }
        }
        throw OAuth2RuntimeException.error("Cannot find AccessTokenResponseIssuer to handle this request");
    }

    public OAuth2DAO getOAuth2DAO(OAuth2MessageContext messageContext) {

        // Call HandlerManager and get the corresponding OAuth2DAOHandler first
        List<OAuth2DAOHandler> handlers = OAuth2DataHolder.getInstance().getOAuth2DAOHandlers();
        for(OAuth2DAOHandler handler:handlers){
            try {
                if (handler.isEnabled(messageContext) && handler.canHandle(messageContext)) {
                    //Wrap the OAuth2DAOHandler
                    OAuth2DAO dao = cachedDAOMap.get(handler.getName());
                    if (dao == null) {
                        synchronized (handler.getName().intern()) {
                            if (dao == null) {
                                OAuth2DAO asyncDAO = new AsyncDAO(handler);
                                CacheBackedOAuth2DAO cachedDAO = new CacheBackedOAuth2DAO(asyncDAO);
                                cachedDAOMap.put(handler.getName(), cachedDAO);
                                return cachedDAO;
                            }
                        }
                    }
                    return dao;
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + handler.getName() + " can handle " +
                          messageContext.toString());
            }
        }
        throw OAuth2RuntimeException.error("Cannot find OAuth2DAOHandler to handle this request");
    }

    public TokenPersistenceProcessor getTokenPersistenceProcessor(OAuth2MessageContext messageContext) {

        List<TokenPersistenceProcessor> handlers = OAuth2DataHolder.getInstance().getTokenPersistenceProcessors();
        for(TokenPersistenceProcessor handler:handlers){
            try {
                if (handler.isEnabled(messageContext) && handler.canHandle(messageContext)) {
                    return handler;
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + handler.getName() + " can handle " +
                          messageContext.toString());
            }
        }
        throw OAuth2RuntimeException.error("Cannot find AccessTokenResponseIssuer to handle this request");
    }

    public void validateGrant(TokenMessageContext messageContext) throws OAuth2ClientException, OAuth2Exception {

        List<AuthorizationGrantHandler> handlers = OAuth2DataHolder.getInstance().getGrantHandlers();
        for(AuthorizationGrantHandler handler:handlers){
            try {
                if (handler.isEnabled(messageContext) && handler.canHandle(messageContext)) {
                    handler.validateGrant(messageContext);
                    return;
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + handler.getName() + " can handle " +
                          messageContext.toString());
            }
        }
        throw OAuth2RuntimeException.error("Cannot find AuthorizationGrantHandler to handle this request");
    }

    public IntrospectionHandler getIntrospectionHandler(IntrospectionMessageContext messageContext) {

        List<IntrospectionHandler> handlers = OAuth2DataHolder.getInstance().getIntrospectionHandlers();
        for(IntrospectionHandler handler:handlers){
            try {
                if (handler.isEnabled(messageContext) && handler.canHandle(messageContext)) {
                    return handler;
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + handler.getName() + " can handle " +
                          messageContext.toString());
            }
        }
        throw OAuth2RuntimeException.error("Cannot find IntrospectionHandler to handle this request");
    }

    public void triggerPreTokenIssuers(OAuth2MessageContext messageContext) {
        for(OAuth2EventInterceptor interceptor : OAuth2DataHolder.getInstance().getInterceptors()) {
            try {
                if (interceptor.isEnabled(messageContext) && interceptor.canHandle(messageContext)) {
                    interceptor.onPreTokenIssue(messageContext);
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + interceptor.getName() + " can handle " +
                          messageContext.toString());
            }
        }
    }

    public void triggerPostTokenIssuers(OAuth2MessageContext messageContext) {
        for(OAuth2EventInterceptor interceptor : OAuth2DataHolder.getInstance().getInterceptors()) {
            try {
                if (interceptor.isEnabled(messageContext) && interceptor.canHandle(messageContext)) {
                    interceptor.onPostTokenIssue(messageContext);
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + interceptor.getName() + " can handle " +
                          messageContext.toString());
            }
        }
    }

    public void triggerPreTokenRevocationsByClient(RevocationMessageContext messageContext) {
        for(OAuth2EventInterceptor interceptor : OAuth2DataHolder.getInstance().getInterceptors()) {
            try {
                if (interceptor.isEnabled(messageContext) && interceptor.canHandle(messageContext)) {
                    interceptor.onPreTokenRevocationByClient(messageContext);
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + interceptor.getName() + " can handle " +
                          messageContext.toString());
            }
        }
    }

    public void triggerPostTokenRevocationsByClient(RevocationMessageContext messageContext) {
        for(OAuth2EventInterceptor interceptor : OAuth2DataHolder.getInstance().getInterceptors()) {
            try {
                if (interceptor.isEnabled(messageContext) && interceptor.canHandle(messageContext)) {
                    interceptor.onPostTokenRevocationByClient(messageContext);
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + interceptor.getName() + " can handle " +
                          messageContext.toString());
            }
        }
    }

    public void triggerPreTokenRevocationsByResourceOwner(AuthenticatedUser user, RORevocationMessageContext
            messageContext) {
        for(OAuth2EventInterceptor interceptor : OAuth2DataHolder.getInstance().getInterceptors()) {
            try {
                if (interceptor.isEnabled(messageContext) && interceptor.canHandle(messageContext)) {
                    interceptor.onPreTokenRevocationByResourceOwner(user, messageContext);
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + interceptor.getName() + " can handle " +
                          messageContext.toString());
            }
        }
    }

    public void triggerPostTokenRevocationsByResourceOwner(AuthenticatedUser user, RORevocationMessageContext
            messageContext) {
        for(OAuth2EventInterceptor interceptor : OAuth2DataHolder.getInstance().getInterceptors()) {
            try {
                if (interceptor.isEnabled(messageContext) && interceptor.canHandle(messageContext)) {
                    interceptor.onPostTokenRevocationByResourceOwner(user, messageContext);
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + interceptor.getName() + " can handle " +
                          messageContext.toString());
            }
        }
    }

    public void triggerPreTokenRevocationsByResourceOwner(AuthenticatedUser user, String clientId,
                                                          RORevocationMessageContext messageContext) {
        for(OAuth2EventInterceptor interceptor : OAuth2DataHolder.getInstance().getInterceptors()) {
            try {
                if (interceptor.isEnabled(messageContext) && interceptor.canHandle(messageContext)) {
                    interceptor.onPreTokenRevocationByResourceOwner(user, clientId, messageContext);
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + interceptor.getName() + " can handle " +
                          messageContext.toString());
            }
        }
    }

    public void triggerPostTokenRevocationsByResourceOwner(AuthenticatedUser user, String clientId,
                                                           RORevocationMessageContext messageContext) {
        for(OAuth2EventInterceptor interceptor : OAuth2DataHolder.getInstance().getInterceptors()) {
            try {
                if (interceptor.isEnabled(messageContext) && interceptor.canHandle(messageContext)) {
                    interceptor.onPostTokenRevocationByResourceOwner(user, clientId, messageContext);
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + interceptor.getName() + " can handle " +
                          messageContext.toString());
            }
        }
    }

    public void triggerPreTokenIntrospections(IntrospectionMessageContext messageContext) {
        for(OAuth2EventInterceptor interceptor : OAuth2DataHolder.getInstance().getInterceptors()) {
            try {
                if (interceptor.isEnabled(messageContext) && interceptor.canHandle(messageContext)) {
                    interceptor.onPreTokenIntrospection(messageContext);
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + interceptor.getName() + " can handle " +
                          messageContext.toString());
            }
        }
    }

    public void triggerPostTokenIntrospections(IntrospectionMessageContext messageContext) {
        for(OAuth2EventInterceptor interceptor : OAuth2DataHolder.getInstance().getInterceptors()) {
            try {
                if (interceptor.isEnabled(messageContext) && interceptor.canHandle(messageContext)) {
                    interceptor.onPostTokenIntrospection(messageContext);
                }
            } catch (Exception e) {
                log.error("Error occurred while checking if " + interceptor.getName() + " can handle " +
                          messageContext.toString());
            }
        }
    }
}
