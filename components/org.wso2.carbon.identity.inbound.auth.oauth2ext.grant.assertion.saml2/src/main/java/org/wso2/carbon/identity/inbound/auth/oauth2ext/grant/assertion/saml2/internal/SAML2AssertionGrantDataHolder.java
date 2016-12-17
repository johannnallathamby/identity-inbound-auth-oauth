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

import org.wso2.carbon.identity.inbound.auth.oauth2new.internal.OAuth2DataHolder;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.registry.api.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

public class SAML2AssertionGrantDataHolder {

    private static volatile SAML2AssertionGrantDataHolder instance = new SAML2AssertionGrantDataHolder();
    private RealmService realmService;
    private RegistryService registryService;
    private IdpManager idpManager;

    private SAML2AssertionGrantDataHolder() {

    }

    public static SAML2AssertionGrantDataHolder getInstance() {
        return instance;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRegistryService(RegistryService registryService) {
        this.registryService = registryService;
    }

    public RegistryService getRegistryService() {
        return registryService;
    }

    public void setIdpManager(IdpManager idpManager) {
        this.idpManager = idpManager;
    }

    public IdpManager getIdPManager() {
        return idpManager;
    }

}
