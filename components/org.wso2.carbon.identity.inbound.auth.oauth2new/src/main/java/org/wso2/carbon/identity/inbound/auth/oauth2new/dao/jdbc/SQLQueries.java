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

package org.wso2.carbon.identity.inbound.auth.oauth2new.dao.jdbc;

public class SQLQueries {

    public static final String INSERT_OAUTH2_ACCESS_TOKEN = "INSERT INTO $accessTokenStoreTable (ACCESS_TOKEN, " +
            "REFRESH_TOKEN, CONSUMER_KEY_ID, AUTHZ_USER, TENANT_ID, USER_DOMAIN, TIME_CREATED, " +
            "REFRESH_TOKEN_TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_VALIDITY_PERIOD, TOKEN_SCOPE_HASH, " +
            "TOKEN_STATE, USER_TYPE, TOKEN_ID, GRANT_TYPE, SUBJECT_IDENTIFIER) SELECT ?,?,ID,?,?,?,?,?,?,?,?,?,?,?,?," +
            "? FROM IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

    public static final String INSERT_OAUTH2_TOKEN_SCOPE = "INSERT INTO IDN_OAUTH2_ACCESS_TOKEN_SCOPE (TOKEN_ID, " +
            "TOKEN_SCOPE, TENANT_ID) VALUES (?,?,?)";

    public static final String RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_MYSQL = "SELECT TOKEN_ID, ACCESS_TOKEN, " +
            "AUTHZ_USER, IDN_OAUTH2_ACCESS_TOKEN_SELECTED.TENANT_ID, USER_DOMAIN, TOKEN_SCOPE, TOKEN_STATE, " +
            "TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_TIME_CREATED, " +
            "REFRESH_TOKEN_VALIDITY_PERIOD, GRANT_TYPE, SUBJECT_IDENTIFIER FROM ( SELECT " +
            "ACCESS_TOKEN, AUTHZ_USER, TENANT_ID, USER_DOMAIN, TOKEN_STATE, TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_TIME_CREATED, " +
            "REFRESH_TOKEN_VALIDITY_PERIOD, TOKEN_ID, GRANT_TYPE, SUBJECT_IDENTIFIER CONSUMER_KEY FROM " +
            "IDN_OAUTH2_ACCESS_TOKEN " +
            "WHERE REFRESH_TOKEN = ? ORDER BY TIME_CREATED DESC " +
            "LIMIT 1) IDN_OAUTH2_ACCESS_TOKEN_SELECTED LEFT JOIN IDN_OAUTH2_ACCESS_TOKEN_SCOPE ON " +
            "IDN_OAUTH2_ACCESS_TOKEN_SELECTED.TOKEN_ID = IDN_OAUTH2_ACCESS_TOKEN_SCOPE.TOKEN_ID";

    public static final String RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_DB2SQL = "SELECT ACCESS_TOKEN, AUTHZ_USER, " +
            "IDN_OAUTH2_ACCESS_TOKEN_SELECTED.TENANT_ID, USER_DOMAIN, TOKEN_SCOPE, TOKEN_STATE, TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_TIME_CREATED, " +
            "REFRESH_TOKEN_VALIDITY_PERIOD, GRANT_TYPE, SUBJECT_IDENTIFIER FROM ( SELECT " +
            "ACCESS_TOKEN, AUTHZ_USER, TOKEN_STATE, TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_TIME_CREATED, " +
            "REFRESH_TOKEN_VALIDITY_PERIOD, TOKEN_ID, GRANT_TYPE, SUBJECT_IDENTIFIER CONSUMER_KEY FROM " +
            "IDN_OAUTH2_ACCESS_TOKEN " +
            "WHERE REFRESH_TOKEN = ? ORDER BY TIME_CREATED DESC " +
            "FETCH FIRST 1 ROWS ONLY) IDN_OAUTH2_ACCESS_TOKEN_SELECTED LEFT JOIN IDN_OAUTH2_ACCESS_TOKEN_SCOPE ON " +
            "IDN_OAUTH2_ACCESS_TOKEN_SELECTED.TOKEN_ID = IDN_OAUTH2_ACCESS_TOKEN_SCOPE.TOKEN_ID";

    public static final String RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_ORACLE = "SELECT ACCESS_TOKEN, AUTHZ_USER, " +
            "IDN_OAUTH2_ACCESS_TOKEN_SELECTED.TENANT_ID, USER_DOMAIN, TOKEN_SCOPE, TOKEN_STATE, TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_TIME_CREATED, " +
            "REFRESH_TOKEN_VALIDITY_PERIOD, GRANT_TYPE, SUBJECT_IDENTIFIER FROM ( SELECT * FROM " +
            "(SELECT ACCESS_TOKEN, AUTHZ_USER, TENANT_ID, USER_DOMAIN, TOKEN_STATE, TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_TIME_CREATED, " +
            "REFRESH_TOKEN_VALIDITY_PERIOD, TOKEN_ID, GRANT_TYPE, SUBJECT_IDENTIFIER CONSUMER_KEY FROM " +
            "IDN_OAUTH2_ACCESS_TOKEN WHERE REFRESH_TOKEN = ? ORDER BY TIME_CREATED DESC) " +
            "WHERE ROWNUM < 2 )  IDN_OAUTH2_ACCESS_TOKEN_SELECTED LEFT JOIN IDN_OAUTH2_ACCESS_TOKEN_SCOPE ON " +
            "IDN_OAUTH2_ACCESS_TOKEN_SELECTED.TOKEN_ID = IDN_OAUTH2_ACCESS_TOKEN_SCOPE.TOKEN_ID";

    public static final String RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_MSSQL = "SELECT ACCESS_TOKEN, AUTHZ_USER, " +
            "IDN_OAUTH2_ACCESS_TOKEN_SELECTED.TENANT_ID, USER_DOMAIN, TOKEN_SCOPE, TOKEN_STATE, TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_TIME_CREATED, " +
            "REFRESH_TOKEN_VALIDITY_PERIOD, GRANT_TYPE, SUBJECT_IDENTIFIER FROM (SELECT TOP 1 "
            + "ACCESS_TOKEN, " +
            "AUTHZ_USER, TENANT_ID, USER_DOMAIN, TOKEN_SCOPE, TOKEN_STATE, TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_TIME_CREATED, TOKEN_ID " +
            "REFRESH_TOKEN_VALIDITY_PERIOD, TOKEN_ID, GRANT_TYPE, SUBJECT_IDENTIFIER CONSUMER_KEY FROM " +
            "IDN_OAUTH2_ACCESS_TOKEN WHERE REFRESH_TOKEN = ? ORDER BY TIME_CREATED DESC) " +
            "IDN_OAUTH2_ACCESS_TOKEN_SELECTED LEFT JOIN IDN_OAUTH2_ACCESS_TOKEN_SCOPE ON IDN_OAUTH2_ACCESS_TOKEN_SCOPE" +
            ".TOKEN_ID  = IDN_OAUTH2_ACCESS_TOKEN_SCOPE.TOKEN_ID";

    public static final String RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_POSTGRESQL = "SELECT ACCESS_TOKEN, AUTHZ_USER, " +
            "IDN_OAUTH2_ACCESS_TOKEN_SELECTED.TENANT_ID, USER_DOMAIN, TOKEN_SCOPE, TOKEN_STATE, TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_TIME_CREATED," +
            " REFRESH_TOKEN_VALIDITY_PERIOD, GRANT_TYPE, SUBJECT_IDENTIFIER FROM (SELECT " +
            "ACCESS_TOKEN, AUTHZ_USER, TENANT_ID, USER_DOMAIN, TOKEN_STATE, TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_TIME_CREATED, " +
            "REFRESH_TOKEN_VALIDITY_PERIOD, TOKEN_ID, GRANT_TYPE, SUBJECT_IDENTIFIER CONSUMER_KEY FROM " +
            "IDN_OAUTH2_ACCESS_TOKEN WHERE REFRESH_TOKEN = ? ORDER BY TIME_CREATED DESC " +
            "LIMIT 1) IDN_OAUTH2_ACCESS_TOKEN_SELECTED LEFT JOIN IDN_OAUTH2_ACCESS_TOKEN_SCOPE ON " +
            "IDN_OAUTH2_ACCESS_TOKEN_SELECTED.TOKEN_ID = IDN_OAUTH2_ACCESS_TOKEN_SCOPE.TOKEN_ID";

    public static final String RETRIEVE_ACCESS_TOKEN_VALIDATION_DATA_INFORMIX = "SELECT ACCESS_TOKEN, AUTHZ_USER, " +
            "IDN_OAUTH2_ACCESS_TOKEN_SELECTED.TENANT_ID, USER_DOMAIN, TOKEN_SCOPE, TOKEN_STATE, TIME_CREATED, VALIDITY_PERIOD, REFRESH_TOKEN_TIME_CREATED, " +
            "REFRESH_TOKEN_VALIDITY_PERIOD, GRANT_TYPE, SUBJECT_IDENTIFIER FROM ( SELECT FIRST 1 " +
            "ACCESS_TOKEN, AUTHZ_USER, TENANT_ID, USER_DOMAIN, TOKEN_STATE, TIME_CREATED, VALIDITY_PERIOD, " +
            "REFRESH_TOKEN_TIME_CREATED, REFRESH_TOKEN_VALIDITY_PERIOD, TOKEN_ID, GRANT_TYPE, " +
            "SUBJECT_IDENTIFIER CONSUMER_KEY FROM IDN_OAUTH2_ACCESS_TOKEN WHERE " +
            "REFRESH_TOKEN = ? " +
            "ORDER BY TIME_CREATED DESC) IDN_OAUTH2_ACCESS_TOKEN_SELECTED LEFT JOIN IDN_OAUTH2_ACCESS_TOKEN_SCOPE ON " +
            "IDN_OAUTH2_ACCESS_TOKEN_SELECTED.TOKEN_ID = IDN_OAUTH2_ACCESS_TOKEN_SCOPE.TOKEN_ID";

    public static final String UPDATE_ACCESS_TOKEN_STATE = "UPDATE IDN_OAUTH2_ACCESS_TOKEN SET TOKEN_STATE=?, " +
            "TOKEN_STATE_ID=? WHERE ACCESS_TOKEN=?";

    public static final String GET_ACCESS_TOKEN_BY_CODE = "SELECT ACCESS_TOKEN FROM IDN_OAUTH2_ACCESS_TOKEN WHERE " +
            "TOKEN_ID = (SELECT TOKEN_ID FROM IDN_OAUTH2_AUTHORIZATION_CODE WHERE AUTHORIZATION_CODE=?)";

    public static final String GET_ACCESS_TOKEN_BY_CODE_MYSQL = "SELECT ACCESS_TOKEN FROM IDN_OAUTH2_ACCESS_TOKEN WHERE " +
            "TOKEN_ID = (SELECT TOKEN_ID FROM (SELECT TOKEN_ID FROM IDN_OAUTH2_AUTHORIZATION_CODE WHERE " +
            "AUTHORIZATION_CODE=?) AUTHORIZATION_CODE_SELECTED)";

    public static final String UPDATE_ACCESS_TOKEN_STATE_BY_CODE = "UPDATE IDN_OAUTH2_ACCESS_TOKEN SET TOKEN_STATE=?," +
            " TOKEN_STATE_ID=? WHERE ACCESS_TOKEN=?";

    public static final String STORE_AUTHORIZATION_CODE = "INSERT INTO IDN_OAUTH2_AUTHORIZATION_CODE " +
            "(CODE_ID, AUTHORIZATION_CODE, CONSUMER_KEY_ID, CALLBACK_URL, SCOPE, AUTHZ_USER, USER_DOMAIN, TENANT_ID, " +
            "TIME_CREATED, VALIDITY_PERIOD, SUBJECT_IDENTIFIER) SELECT ?,?,ID,?,?,?,?,?,?,?,? FROM " +
            "IDN_OAUTH_CONSUMER_APPS WHERE CONSUMER_KEY=?";

    public static final String RETRIEVE_AUTHZ_CODE = "SELECT CODE_ID, AUTHZ_USER, USER_DOMAIN, TENANT_ID, SCOPE, " +
            "CALLBACK_URL, TIME_CREATED,VALIDITY_PERIOD, STATE, " +
            "SUBJECT_IDENTIFIER CONSUMER_KEY, PKCE_CODE_CHALLENGE, PKCE_CODE_CHALLENGE_METHOD FROM " +
            "IDN_OAUTH2_AUTHORIZATION_CODE WHERE AUTHORIZATION_CODE = ? AUTHORIZATION_CODE_SELECTED INNER JOIN " +
            "IDN_OAUTH2_CONSUMER_APPS ON AUTHORIZATION_CODE_SELECTED.CONSUMER_KEY_ID = IDN_OAUTH2_AUTHORIZATION_CODE" +
            ".ID";

    public static final String UPDATE_AUTHZ_CODE_STATE = "UPDATE IDN_OAUTH2_AUTHORIZATION_CODE SET " +
            "STATE=? WHERE AUTHORIZATION_CODE=?";

    public static final String UPDATE_NEW_TOKEN_AGAINST_AUTHZ_CODE = "UPDATE IDN_OAUTH2_AUTHORIZATION_CODE SET " +
            "TOKEN_ID=? WHERE AUTHORIZATION_CODE= (SELECT " +
            "AUTHORIZATION_CODE FROM " +
            "IDN_OAUTH2_AUTHORIZATION_CODE WHERE AUTHORIZATION_CODE=? )";

    public static final String UPDATE_NEW_TOKEN_AGAINST_AUTHZ_CODE_MYSQL = "UPDATE IDN_OAUTH2_AUTHORIZATION_CODE SET " +
            "TOKEN_ID=? WHERE AUTHORIZATION_CODE= (SELECT AUTHORIZATION_CODE FROM(SELECT AUTHORIZATION_CODE FROM " +
            "IDN_OAUTH2_AUTHORIZATION_CODE WHERE AUTHORIZATION_CODE=? ) AUTHORIZATION_CODE_SELECTED)";

    public static final String GET_DISTINCT_APPS_AUTHORIZED_BY_USER_ALL_TIME = "SELECT DISTINCT CONSUMER_KEY FROM " +
            "IDN_OAUTH2_ACCESS_TOKEN JOIN IDN_OAUTH_CONSUMER_APPS ON CONSUMER_KEY_ID = " +
            "ID WHERE AUTHZ_USER=? AND IDN_OAUTH2_ACCESS_TOKEN.TENANT_ID=? AND IDN_OAUTH2_ACCESS_TOKEN.USER_DOMAIN=? " +
            "AND (TOKEN_STATE='ACTIVE' OR TOKEN_STATE='EXPIRED')";

    public static final String RETRIEVE_ACTIVE_EXPIRED_ACCESS_TOKEN = "SELECT TOKEN_ID, CONSUMER_KEY, AUTHZ_USER, " +
            "ACCESS_TOKEN_TABLE.TENANT_ID, USER_DOMAIN, TOKEN_SCOPE, TIME_CREATED, REFRESH_TOKEN_TIME_CREATED, " +
            "VALIDITY_PERIOD, REFRESH_TOKEN_VALIDITY_PERIOD, REFRESH_TOKEN, " +
            "GRANT_TYPE, SUBJECT_IDENTIFIER, TOKEN_STATE " +
            "FROM (SELECT TOKEN_ID, CONSUMER_KEY, AUTHZ_USER, IDN_OAUTH2_ACCESS_TOKEN.TENANT_ID, " +
            "IDN_OAUTH2_ACCESS_TOKEN.USER_DOMAIN, TIME_CREATED, REFRESH_TOKEN_TIME_CREATED, VALIDITY_PERIOD, " +
            "REFRESH_TOKEN_VALIDITY_PERIOD, REFRESH_TOKEN, IDN_OAUTH2_ACCESS_TOKEN.GRANT_TYPE, " +
            "SUBJECT_IDENTIFIER, TOKEN_STATE " +
            "FROM IDN_OAUTH2_ACCESS_TOKEN JOIN IDN_OAUTH_CONSUMER_APPS ON CONSUMER_KEY_ID = ID " +
            "WHERE ACCESS_TOKEN=? AND (TOKEN_STATE='ACTIVE' OR TOKEN_STATE='EXPIRED')) ACCESS_TOKEN_TABLE LEFT " +
            "JOIN IDN_OAUTH2_ACCESS_TOKEN_SCOPE ON ACCESS_TOKEN_TABLE.TOKEN_ID = IDN_OAUTH2_ACCESS_TOKEN_SCOPE.TOKEN_ID";

    public static final String REVOKE_REFRESH_TOKEN = "UPDATE IDN_OAUTH2_ACCESS_TOKEN SET TOKEN_STATE='REVOKED', " +
            "TOKEN_STATE_ID=? WHERE REFRESH_TOKEN=?";

}
