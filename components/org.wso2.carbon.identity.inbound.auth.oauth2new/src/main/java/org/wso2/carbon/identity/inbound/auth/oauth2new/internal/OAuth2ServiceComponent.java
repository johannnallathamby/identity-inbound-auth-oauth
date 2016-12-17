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
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.inbound.auth.oauth2new.analytics.DASDataPublisher;
import org.wso2.carbon.identity.inbound.auth.oauth2new.bean.message.request.authz.AuthzApprovedRequestFactory;
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
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant.ClientCredentialsGrantHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant.PasswordGrantHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant.RefreshGrantHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.interceptor.OAuth2EventInterceptor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.issuer.AccessTokenResponseIssuer;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.issuer.BearerTokenResponseIssuer;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.persist.PlainTextPersistenceProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.persist.TokenPersistenceProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionRequestFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionResponseFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.model.OAuth2ServerConfig;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.authz.AuthzProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.authz.CodeResponseProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.authz.TokenResponseProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.processor.token.TokenProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.RevocationProcessor;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.RevocationRequestFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.RevocationResponseFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.RevocationService;
import org.wso2.carbon.identity.inbound.auth.oauth2new.revoke.RevocationServiceImpl;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

@Component(
        name = "identity.oauth2new.component",
        immediate = true
)
public class OAuth2ServiceComponent {

    private static Log log = LogFactory.getLog(OAuth2ServiceComponent.class);

    @SuppressWarnings("unchecked")
    @Activate
    protected void activate(ComponentContext context) {

        try {

            OAuth2ServerConfig.getInstance();

            OAuth2DataHolder.getInstance().getOAuth2DAOHandlers().add(new OAuth2DAOHandler(new JDBCOAuth2DAO()));
            OAuth2DataHolder.getInstance().getTokenPersistenceProcessors().add(new PlainTextPersistenceProcessor());
            OAuth2DataHolder.getInstance().getAccessTokenIssuers().add(new BearerTokenResponseIssuer());
            OAuth2DataHolder.getInstance().getClientAuthHandlers().add(new BasicAuthHandler());
            OAuth2DataHolder.getInstance().getGrantHandlers().add(new AuthzCodeGrantHandler());
            OAuth2DataHolder.getInstance().getGrantHandlers().add(new PasswordGrantHandler());
            OAuth2DataHolder.getInstance().getGrantHandlers().add(new ClientCredentialsGrantHandler());
            OAuth2DataHolder.getInstance().getGrantHandlers().add(new RefreshGrantHandler());
            OAuth2DataHolder.getInstance().getIntrospectionHandlers().add(new IntrospectionHandler());
            OAuth2DataHolder.getInstance().getOAuth2DAOHandlers().add(new OAuth2DAOHandler(new JDBCOAuth2DAO()));
            OAuth2DataHolder.getInstance().getInterceptors().add(new DASDataPublisher());

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
                    HttpIdentityRequestFactory.class.getName(), new AuthzApprovedRequestFactory(), null);
            if (authzApprovedReqFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" AuthzApprovedRequestFactory is registered");
                }
            } else {
                log.error("AuthzApprovedRequestFactory could not be registered");
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
                    HttpIdentityRequestFactory.class.getName(), new RevocationRequestFactory(), null);
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
                    RevocationService.class.getName(), RevocationServiceImpl.getInstance(), null);
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
            log.fatal("Error occurred while activating OAuth2 bundle", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("OAuth2 bundle is deactivated");
        }
    }

    @Reference(
            name = "user.realmservice.default",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
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

    @Reference(
            name = "registry.service",
            service = org.wso2.carbon.registry.core.service.RegistryService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRegistryService"
    )
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

    @Reference(
            name = "identityCoreInitializedEventService",
            service = org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService"
    )
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

    @Reference(
            name = "identity.application.management.component",
            service = org.wso2.carbon.identity.application.mgt.ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationManagementService"
    )
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

    @Reference(
            name = "oauth2.handler.client.auth",
            service = org.wso2.carbon.identity.inbound.auth.oauth2new.handler.client.ClientAuthHandler.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeClientAuthHandler"
    )
    protected void addClientAuthHandler(ClientAuthHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding ClientAuthHandler " + handler.getName());
        }
        handler.init(null);
        OAuth2DataHolder.getInstance().getClientAuthHandlers().add(handler);
    }

    protected void removeClientAuthHandler(ClientAuthHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing ClientAuthHandler " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getClientAuthHandlers().remove(handler);
    }

    @Reference(
            name = "oauth2.handler.issuer.token",
            service = org.wso2.carbon.identity.inbound.auth.oauth2new.handler.issuer.AccessTokenResponseIssuer.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeAccessTokenResponseIssuer"
    )
    protected void addAccessTokenResponseIssuer(AccessTokenResponseIssuer handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding AccessTokenResponseIssuer " + handler.getName());
        }
        handler.init(null);
        OAuth2DataHolder.getInstance().getAccessTokenIssuers().add(handler);
    }

    protected void removeAccessTokenResponseIssuer(AccessTokenResponseIssuer handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing AccessTokenResponseIssuer " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getAccessTokenIssuers().remove(handler);
    }

    @Reference(
            name = "oauth2.handler.persist.token",
            service = org.wso2.carbon.identity.inbound.auth.oauth2new.handler.persist.TokenPersistenceProcessor.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeTokenPersistenceProcessor"
    )
    protected void addTokenPersistenceProcessor(TokenPersistenceProcessor handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding AccessTokenResponseIssuer " + handler.getName());
        }
        handler.init(null);
        OAuth2DataHolder.getInstance().getTokenPersistenceProcessors().add(handler);
    }

    protected void removeTokenPersistenceProcessor(TokenPersistenceProcessor persistenceProcessor) {
        if (log.isDebugEnabled()) {
            log.debug("Removing AccessTokenResponseIssuer " + persistenceProcessor.getName());
        }
        OAuth2DataHolder.getInstance().getTokenPersistenceProcessors().remove(persistenceProcessor);
    }

    @Reference(
            name = "oauth2.handler.dao",
            service = org.wso2.carbon.identity.inbound.auth.oauth2new.dao.OAuth2DAOHandler.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeOAuth2DAOHandler"
    )
    protected void addOAuth2DAOHandler(OAuth2DAOHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding AccessTokenResponseIssuer " + handler.getName());
        }
        handler.init(null);
        OAuth2DataHolder.getInstance().getOAuth2DAOHandlers().add(handler);
    }

    protected void removeOAuth2DAOHandler(OAuth2DAOHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing AccessTokenResponseIssuer " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getOAuth2DAOHandlers().remove(handler);
    }

    @Reference(
            name = "oauth2.handler.grant",
            service = org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant.AuthorizationGrantHandler.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeAuthorizationGrantHandler"
    )
    protected void addAuthorizationGrantHandler(AuthorizationGrantHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding AuthorizationGrantHandler " + handler.getName());
        }
        handler.init(null);
        OAuth2DataHolder.getInstance().getGrantHandlers().add(handler);
    }

    protected void removeAuthorizationGrantHandler(AuthorizationGrantHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing AuthorizationGrantHandler " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getGrantHandlers().remove(handler);
    }

    @Reference(
            name = "oauth2.handler.introspection",
            service = org.wso2.carbon.identity.inbound.auth.oauth2new.introspect.IntrospectionHandler.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeIntrospectionHandler"
    )
    protected void addIntrospectionHandler(IntrospectionHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding IntrospectionHandler " + handler.getName());
        }
        handler.init(null);
        OAuth2DataHolder.getInstance().getIntrospectionHandlers().add(handler);
    }

    protected void removeIntrospectionHandler(IntrospectionHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing IntrospectionHandler " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getIntrospectionHandlers().remove(handler);
    }

    @Reference(
            name = "oauth2.interceptor",
            service = org.wso2.carbon.identity.inbound.auth.oauth2new.handler.interceptor.OAuth2EventInterceptor.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeOAuth2EventInterceptor"
    )
    protected void addOAuth2EventInterceptor(OAuth2EventInterceptor handler) {
        if (log.isDebugEnabled()) {
            log.debug("Setting OAuth2EventInterceptor " + handler.getName());
        }
        handler.init(null);
        OAuth2DataHolder.getInstance().getInterceptors().add(handler);
    }

    protected void removeOAuth2EventInterceptor(OAuth2EventInterceptor handler) {
        if (log.isDebugEnabled()) {
            log.debug("Un-setting OAuth2EventInterceptor " + handler.getName());
        }
        OAuth2DataHolder.getInstance().getInterceptors().remove(handler);
    }

    @Reference(
            name = "org.wso2.carbon.event.stream.core",
            service = org.wso2.carbon.event.stream.core.EventStreamService.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetEventStreamService"
    )
    protected void setEventStreamService(EventStreamService eventStreamService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting EventStreamService.");
        }
        OAuth2DataHolder.getInstance().setEventStreamService(eventStreamService);
    }

    protected void unsetEventStreamService(EventStreamService eventStreamService) {
        if (log.isDebugEnabled()) {
            log.debug("Un-setting EventStreamService.");
        }
        OAuth2DataHolder.getInstance().setEventStreamService(null);
    }

}
