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

package org.wso2.carbon.identity.inbound.auth.oauth2new.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.authz.AuthzRequestFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.authzcode.AuthzCodeGrantFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.clientcredentials.ClientCredentialsGrantFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.password.PasswordGrantFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.token.refresh.RefreshGrantFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz.AuthzResponseFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.authz.ConsentResponseFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.response.token.TokenResponseFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.OAuth2DAOHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.dao.jdbc.JDBCOAuth2DAO;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.client.BasicAuthHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.client.ClientAuthHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant.AuthzCodeGrantHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant.PasswordGrantHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant.RefreshGrantHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.interceptor.OAuth2EventInterceptor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.issuer.AccessTokenResponseIssuer;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.issuer.BearerTokenResponseIssuer;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.persist.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.persist.TokenPersistenceProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionResponseFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionRequestFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2ServerConfig;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.authz.AuthzProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.authz.CodeResponseProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.authz.TokenResponseProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.token.TokenProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.RevocationResponseFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.OAuth2TokenRevocationService;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.OAuth2TokenRevocationServiceImpl;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.RevocationProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.RevocationRequestFactory;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="identity.oauth2.component" immediate="true"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService"
 * unbind="unsetRegistryService"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 * @scr.reference name="identityCoreInitializedEventService"
 * interface="org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent" cardinality="1..1"
 * policy="dynamic" bind="setIdentityCoreInitializedEventService" unbind="unsetIdentityCoreInitializedEventService"
 * @scr.reference name="ApplicationManagementService"
 * interface="org.wso2.carbon.identity.application.mgt.ApplicationManagementService" cardinality="1..1"
 * policy="dynamic" bind="setApplicationManagementService" unbind="unsetApplicationManagementService"
 * @scr.reference name="oauth2.handler.client.auth"
 * interface="org.wso2.carbon.identity.inbound.auth.oauth2new.handler.client.ClientAuthHandler" cardinality="0..n"
 * policy="dynamic" bind="addClientAuthHandler" unbind="removeClientAuthHandler"
 * @scr.reference name="oauth2.handler.issuer.token"
 * interface="org.wso2.carbon.identity.inbound.auth.oauth2new.handler.issuer.AccessTokenResponseIssuer"
 * cardinality="0..n"
 * policy="dynamic" bind="addAccessTokenResponseIssuer" unbind="removeAccessTokenResponseIssuer"
 * @scr.reference name="oauth2.handler.persist.token"
 * interface="org.wso2.carbon.identity.inbound.auth.oauth2new.handler.persist.TokenPersistenceProcessor" cardinality="0..n"
 * policy="dynamic" bind="addTokenPersistenceProcessor" unbind="removeTokenPersistenceProcessor"
 * @scr.reference name="oauth2.handler.dao"
 * interface="org.wso2.carbon.identity.inbound.auth.oauth2new.dao.OAuth2DAO" cardinality="0..n"
 * policy="dynamic" bind="addOAuth2DAOHandler" unbind="removeOAuth2DAOHandler"
 * @scr.reference name="oauth2.handler.grant"
 * interface="org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant.AuthorizationGrantHandler" cardinality="0..n"
 * policy="dynamic" bind="addAuthorizationGrantHandler" unbind="removeAuthorizationGrantHandler"
 * @scr.reference name="oauth2.handler.introspection"
 * interface="org.wso2.carbon.identity.inbound.auth.oauth2new.introspection.IntrospectionHandler" cardinality="0..n"
 * policy="dynamic" bind="addIntrospectionHandler" unbind="removeIntrospectionHandler"
 * @scr.reference name="org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor"
 * interface="org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor" cardinality="0..n" policy="dynamic"
 * bind="setOAuth2EventInterceptor" unbind="unsetOAuth2EventInterceptor"
 */
public class OAuth2ServiceComponent {

    private static Log log = LogFactory.getLog(OAuth2ServiceComponent.class);

    protected void activate(ComponentContext context) {

        try {
            OAuth2ServerConfig.getInstance();

            OAuth2DataHolder.getInstance().getOAuth2DAOHandlers().add(new OAuth2DAOHandler(new JDBCOAuth2DAO()));
            OAuth2DataHolder.getInstance().getTokenPersistenceProcessors().add(new PlainTextPersistenceProcessor());
            OAuth2DataHolder.getInstance().getAccessTokenIssuers().add(new BearerTokenResponseIssuer());
            OAuth2DataHolder.getInstance().getClientAuthHandlers().add(new BasicAuthHandler());
            OAuth2DataHolder.getInstance().getGrantHandlers().add(new AuthzCodeGrantHandler());
            OAuth2DataHolder.getInstance().getGrantHandlers().add(new PasswordGrantHandler());
            OAuth2DataHolder.getInstance().getGrantHandlers().add(new RefreshGrantHandler());
            OAuth2DataHolder.getInstance().getIntrospectionHandlers().add(new IntrospectionHandler());

            ServiceRegistration authzProcessor = context.getBundleContext().registerService(
                    IdentityProcessor.class.getName(), new AuthzProcessor(), null);
            if (authzProcessor != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" AuthzProcessor is registered");
                }
            } else {
                log.error("AuthzProcessor could not be registered");
            }
            ServiceRegistration codeRespProcessor = context.getBundleContext().registerService(
                    IdentityProcessor.class.getName(), new CodeResponseProcessor(), null);
            if (codeRespProcessor != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" CodeResponseProcessor is registered");
                }
            } else {
                log.error("CodeResponseProcessor could not be registered");
            }
            ServiceRegistration tokenRespProcessor = context.getBundleContext().registerService(
                    IdentityProcessor.class.getName(), new TokenResponseProcessor(), null);
            if (tokenRespProcessor != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" TokenResponseProcessor is registered");
                }
            } else {
                log.error("TokenResponseProcessor could not be registered");
            }
            ServiceRegistration tokenProcessor = context.getBundleContext().registerService(
                    IdentityProcessor.class.getName(), new TokenProcessor(), null);
            if (tokenProcessor != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" TokenProcessor is registered");
                }
            } else {
                log.error("TokenProcessor could not be registered");
            }

            ServiceRegistration authzReqFactory = context.getBundleContext().registerService(
                    HttpIdentityRequestFactory.class.getName(), new AuthzRequestFactory(), null);
            if (authzReqFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" AuthzRequestFactory is registered");
                }
            } else {
                log.error("AuthzRequestFactory could not be registered");
            }
            ServiceRegistration authzApprovedReqFactory = context.getBundleContext().registerService(
                    HttpIdentityRequestFactory.class.getName(), new AuthzRequestFactory(), null);
            if (authzApprovedReqFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" AuthzApprovedReqFactory is registered");
                }
            } else {
                log.error("AuthzApprovedReqFactory could not be registered");
            }
            ServiceRegistration authzCodeGrantFactory = context.getBundleContext().registerService(
                    HttpIdentityRequestFactory.class.getName(), new AuthzCodeGrantFactory(), null);
            if (authzCodeGrantFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" AuthzCodeGrantFactory is registered");
                }
            } else {
                log.error("AuthzCodeGrantFactory could not be registered");
            }
            ServiceRegistration passwordGrantFactory = context.getBundleContext().registerService(
                    HttpIdentityRequestFactory.class.getName(), new PasswordGrantFactory(), null);
            if (passwordGrantFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" PasswordGrantFactory is registered");
                }
            } else {
                log.error("PasswordGrantFactory could not be registered");
            }
            ServiceRegistration clientCredGrant = context.getBundleContext().registerService(
                    HttpIdentityRequestFactory.class.getName(), new ClientCredentialsGrantFactory(), null);
            if (clientCredGrant != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" ClientCredentialsGrantFactory is registered");
                }
            } else {
                log.error("ClientCredentialsGrantFactory could not be registered");
            }
            ServiceRegistration refreshGrantFactory = context.getBundleContext().registerService(
                    HttpIdentityRequestFactory.class.getName(), new RefreshGrantFactory(), null);
            if (refreshGrantFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" RefreshGrantFactory is registered");
                }
            } else {
                log.error("RefreshGrantFactory could not be registered");
            }

            ServiceRegistration httpAuthzRespFactory = context.getBundleContext().registerService(
                    HttpIdentityResponseFactory.class.getName(), new AuthzResponseFactory(), null);
            if (httpAuthzRespFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" HttpAuthzResponseFactory is registered");
                }
            } else {
                log.error("HttpAuthzResponseFactory could not be registered");
            }
            ServiceRegistration httpConsentRespFactory = context.getBundleContext().registerService(
                    HttpIdentityResponseFactory.class.getName(), new ConsentResponseFactory(), null);
            if (httpConsentRespFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" HttpConsentResponseFactory is registered");
                }
            } else {
                log.error("HttpConsentResponseFactory could not be registered");
            }
            ServiceRegistration httpTokenRespFactory = context.getBundleContext().registerService(
                    HttpIdentityResponseFactory.class.getName(), new TokenResponseFactory(), null);
            if (httpTokenRespFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" HttpTokenResponseFactory is registered");
                }
            } else {
                log.error("HttpTokenResponseFactory could not be registered");
            }

            ServiceRegistration revocationReqFactory = context.getBundleContext().registerService(
                    HttpIdentityResponseFactory.class.getName(), new RevocationRequestFactory(), null);
            if (revocationReqFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" RevocationRequestFactory is registered");
                }
            } else {
                log.error("RevocationRequestFactory could not be registered");
            }
            ServiceRegistration httpRevocationRespFactory = context.getBundleContext().registerService(
                    HttpIdentityResponseFactory.class.getName(), new RevocationResponseFactory(), null);
            if (httpRevocationRespFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" HttpRevocationResponseFactory is registered");
                }
            } else {
                log.error("HttpRevocationResponseFactory could not be registered");
            }
            ServiceRegistration revokeProcessor = context.getBundleContext().registerService(
                    IdentityProcessor.class.getName(), new RevocationProcessor(), null);
            if (revokeProcessor != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" RevocationProcessor is registered");
                }
            } else {
                log.error("RevocationProcessor could not be registered");
            }
            ServiceRegistration revocationService = context.getBundleContext().registerService(
                    OAuth2TokenRevocationService.class.getName(), OAuth2TokenRevocationServiceImpl.getInstance(), null);
            if (revokeProcessor != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" OAuth2RevocationServiceImpl is registered");
                }
            } else {
                log.error("OAuth2RevocationServiceImpl could not be registered");
            }

            ServiceRegistration introspectionReqFactory = context.getBundleContext().registerService(
                    HttpIdentityRequestFactory.class.getName(), new IntrospectionRequestFactory(), null);
            if (introspectionReqFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" IntrospectionRequestFactory is registered");
                }
            } else {
                log.error("RevocationRequestFactory could not be registered");
            }
            ServiceRegistration introspectionRespFactory = context.getBundleContext().registerService(
                    HttpIdentityResponseFactory.class.getName(), new IntrospectionResponseFactory(), null);
            if (introspectionRespFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" HttpIntrospectionResponseFactory is registered");
                }
            } else {
                log.error("HttpIntrospectionResponseFactory could not be registered");
            }
            ServiceRegistration introspectionProcessor = context.getBundleContext().registerService(
                    IdentityProcessor.class.getName(), new IntrospectionProcessor(), null);
            if (introspectionProcessor != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" IntrospectionProcessor is registered");
                }
            } else {
                log.error("IntrospectionProcessor could not be registered");
            }
            if (log.isDebugEnabled()) {
                log.debug("OAuth2 bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal("Error occurred while activating OAuth2 bundle");
        }
    }

    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("OAuth2 bundle is deactivated");
        }
    }

    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the RealmService");
        }
        OAuth2DataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the RealmService");
        }
        OAuth2DataHolder.getInstance().setRealmService(null);
    }

    protected void setRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the RegistryService");
        }
        OAuth2DataHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the RegistryService");
        }
        OAuth2DataHolder.getInstance().setRegistryService(null);
    }

    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the IdentityCoreInitializedEventService");
        }
        OAuth2DataHolder.getInstance().setIdentityCoreInitializedEvent(identityCoreInitializedEvent);
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the IdentityCoreInitializedEventService");
        }
        OAuth2DataHolder.getInstance().setIdentityCoreInitializedEvent(null);
    }

    protected void addClientAuthHandler(ClientAuthHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding ClientAuthHandler " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getClientAuthHandlers().add(handler);
    }

    protected void removeClientAuthHandler(ClientAuthHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing ClientAuthHandler " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getClientAuthHandlers().remove(handler);
    }

    protected void addAccessTokenResponseIssuer(AccessTokenResponseIssuer handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding AccessTokenResponseIssuer " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getAccessTokenIssuers().add(handler);
    }

    protected void removeAccessTokenResponseIssuer(AccessTokenResponseIssuer handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing AccessTokenResponseIssuer " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getAccessTokenIssuers().remove(handler);
    }

    protected void addTokenPersistenceProcessor(TokenPersistenceProcessor persistenceProcessor) {
        if (log.isDebugEnabled()) {
            log.debug("Adding AccessTokenResponseIssuer " + persistenceProcessor.getName());
        }
        OAuth2DataHolder.getInstance().getTokenPersistenceProcessors().add(persistenceProcessor);
    }

    protected void removeTokenPersistenceProcessor(TokenPersistenceProcessor persistenceProcessor) {
        if (log.isDebugEnabled()) {
            log.debug("Removing AccessTokenResponseIssuer " + persistenceProcessor.getName());
        }
        OAuth2DataHolder.getInstance().getTokenPersistenceProcessors().remove(persistenceProcessor);
    }

    protected void addOAuth2DAOHandler(OAuth2DAOHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding AccessTokenResponseIssuer " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getOAuth2DAOHandlers().add(handler);
    }

    protected void removeOAuth2DAOHandler(OAuth2DAOHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing AccessTokenResponseIssuer " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getOAuth2DAOHandlers().remove(handler);
    }

    protected void addAuthorizationGrantHandler(AuthorizationGrantHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding AuthorizationGrantHandler " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getGrantHandlers().add(handler);
    }

    protected void removeAuthorizationGrantHandler(AuthorizationGrantHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing AuthorizationGrantHandler " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getGrantHandlers().remove(handler);
    }

    protected void addIntrospectionHandler(IntrospectionHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding IntrospectionHandler " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getIntrospectionHandlers().add(handler);
    }

    protected void removeIntrospectionHandler(IntrospectionHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing IntrospectionHandler " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getIntrospectionHandlers().remove(handler);
    }

    protected void setApplicationManagementService(ApplicationManagementService service) {
        if (log.isDebugEnabled()) {
            log.debug("Adding ApplicationManagementService.");
        }
        OAuth2DataHolder.getInstance().setAppMgtService(service);
    }

    protected void unsetApplicationManagementService(ApplicationManagementService service) {
        if (log.isDebugEnabled()) {
            log.debug("Removing ApplicationManagementService.");
        }
        OAuth2DataHolder.getInstance().setAppMgtService(null);
    }

    protected void setOAuth2EventInterceptor(OAuth2EventInterceptor interceptor) {

        if (log.isDebugEnabled()) {
            log.debug("Setting OAuth2EventInterceptor " + interceptor.getClass().getName());
        }
        OAuth2DataHolder.getInstance().getInterceptors().add(interceptor);
    }

    protected void unsetOAuth2EventInterceptor(OAuth2EventInterceptor interceptor) {

        if (log.isDebugEnabled()) {
            log.debug("Un-setting OAuth2EventInterceptor " + interceptor.getClass().getName());
        }
        OAuth2DataHolder.getInstance().getInterceptors().remove(interceptor);
    }

}
