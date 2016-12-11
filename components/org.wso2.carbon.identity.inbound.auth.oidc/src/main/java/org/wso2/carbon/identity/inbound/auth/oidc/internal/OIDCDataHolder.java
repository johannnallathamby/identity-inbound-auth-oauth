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

package org.wso2.carbon.identity.inbound.auth.oidc.internal;

import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.inbound.auth.oidc.handler.IDTokenHandler;
import org.wso2.carbon.registry.api.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.List;

public class OIDCDataHolder {

    private static OIDCDataHolder instance = new OIDCDataHolder();
    private RealmService realmService;
    private RegistryService registryService;
    private List<IDTokenHandler> idTokenHandlers = new ArrayList<>();
    private ApplicationManagementService appMgtService = null;

    private OIDCDataHolder() {

    }

    public static OIDCDataHolder getInstance() {
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

    public List<IDTokenHandler> getIDTokenHandlers() {
        return idTokenHandlers;
    }

    public void setAppMgtService(ApplicationManagementService appMgtService) {
        this.appMgtService = appMgtService;
    }

    public ApplicationManagementService getAppMgtService() {
        return appMgtService;
    }
}
