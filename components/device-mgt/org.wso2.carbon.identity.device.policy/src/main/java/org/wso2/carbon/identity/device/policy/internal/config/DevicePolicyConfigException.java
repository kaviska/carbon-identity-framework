/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.device.policy.internal.config;

/**
 * Exception thrown when device policy configuration cannot be loaded or parsed.
 */
public class DevicePolicyConfigException extends Exception {

    /**
     * Constructs a DevicePolicyConfigException with the specified message.
     *
     * @param message The detail message.
     */
    public DevicePolicyConfigException(String message) {

        super(message);
    }

    /**
     * Constructs a DevicePolicyConfigException with the specified message and cause.
     *
     * @param message The detail message.
     * @param cause   The cause.
     */
    public DevicePolicyConfigException(String message, Throwable cause) {

        super(message, cause);
    }
}
