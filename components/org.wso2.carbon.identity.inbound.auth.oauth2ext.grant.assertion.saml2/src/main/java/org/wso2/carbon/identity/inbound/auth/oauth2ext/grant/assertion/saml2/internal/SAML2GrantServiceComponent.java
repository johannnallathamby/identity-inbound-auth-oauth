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

package org.wso2.carbon.identity.inbound.auth.oauth2ext.grant.assertion.saml2.internal;

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
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2ext.grant.assertion.saml2.SAML2AssertionGrantFactory;
import org.wso2.carbon.identity.inbound.auth.oauth2ext.grant.assertion.saml2.SAML2AssertionGrantHandler;
import org.wso2.carbon.identity.inbound.auth.oauth2new.handler.grant.AuthorizationGrantHandler;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

@Component(
        name = "oauth2ext.grant.assertion.saml2.component",
        immediate = true
)
public class SAML2GrantServiceComponent {

    private static Log log = LogFactory.getLog(SAML2GrantServiceComponent.class);

    @SuppressWarnings("unchecked")
    @Activate
    protected void activate(ComponentContext context) {

        try {

            ServiceRegistration saml2AssertionGrantHandler = context.getBundleContext().registerService(
                    AuthorizationGrantHandler.class.getName(), new SAML2AssertionGrantHandler(), null);
            if (saml2AssertionGrantHandler != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" SAML2AssertionGrantHandler is registered");
                }
            } else {
                log.error("SAML2AssertionGrantHandler could not be registered");
            }

            ServiceRegistration  saml2AssertionGrantReqFactory = context.getBundleContext().registerService(
                    HttpIdentityRequestFactory.class.getName(), new SAML2AssertionGrantFactory(), null);
            if (saml2AssertionGrantReqFactory != null) {
                if (log.isDebugEnabled()) {
                    log.debug(" SAML2AssertionGrantFactory is registered");
                }
            } else {
                log.error("SAML2AssertionGrantFactory could not be registered");
            }

            if (log.isDebugEnabled()) {
                log.debug("SAML2AssertionGrantHandler bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal("Error occurred while activating SAML2AssertionGrantHandler bundle", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("SAML2AssertionGrantHandler bundle is deactivated");
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
        SAML2AssertionGrantDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the RealmService");
        }
        SAML2AssertionGrantDataHolder.getInstance().setRealmService(null);
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
        SAML2AssertionGrantDataHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the RegistryService");
        }
        SAML2AssertionGrantDataHolder.getInstance().setRegistryService(null);
    }

    @Reference(
            name = "idp.mgt.dscomponent",
            service = org.wso2.carbon.idp.mgt.IdpManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdPManager"
    )
    protected void setIdPManager(IdpManager idPManager) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the IdpManager");
        }
        SAML2AssertionGrantDataHolder.getInstance().setIdpManager(idPManager);
    }

    protected void unsetIdPManager(IdpManager idPManager) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the IdpManager");
        }
        SAML2AssertionGrantDataHolder.getInstance().setIdpManager(null);
    }

}
