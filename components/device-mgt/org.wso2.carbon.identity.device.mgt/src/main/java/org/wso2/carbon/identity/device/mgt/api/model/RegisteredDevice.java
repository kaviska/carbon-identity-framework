/*
* Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
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
* KIND, either express or implied. See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.wso2.carbon.identity.device.mgt.api.model;

import java.sql.Timestamp;

/**
 * Immutable model for a registered device.
 */
public class RegisteredDevice {

    private final String id;
    private final String userId;
    private final String deviceName;
    private final String deviceModel;
    private final String deviceOs;
    private final String deviceType;
    private final String publicKey;
    private final String challengeUsed;
    private final String status;
    private final Timestamp registeredAt;
    private final Timestamp lastUsedAt;
    private final String metadata;

    private RegisteredDevice(Builder builder) {

        this.id = builder.id;
        this.userId = builder.userId;
        this.deviceName = builder.deviceName;
        this.deviceModel = builder.deviceModel;
        this.deviceOs = builder.deviceOs;
        this.deviceType = builder.deviceType;
        this.publicKey = builder.publicKey;
        this.challengeUsed = builder.challengeUsed;
        this.status = builder.status;
        this.registeredAt = builder.registeredAt;
        this.lastUsedAt = builder.lastUsedAt;
        this.metadata = builder.metadata;
    }

    /**
     * Returns the device identifier.
     *
     * @return Device identifier.
     */
    public String getId() {

        return id;
    }

    /**
     * Returns the user identifier.
     *
     * @return User identifier.
     */
    public String getUserId() {

        return userId;
    }

    /**
     * Returns the display name of the device.
     *
     * @return Device name.
     */
    public String getDeviceName() {

        return deviceName;
    }

    /**
     * Returns the hardware model.
     *
     * @return Device model.
     */
    public String getDeviceModel() {

        return deviceModel;
    }

    /**
     * Returns the device operating system.
     *
     * @return Device OS.
     */
    public String getDeviceOs() {

        return deviceOs;
    }

    /**
     * Returns the device type.
     *
     * @return Device type.
     */
    public String getDeviceType() {

        return deviceType;
    }

    /**
     * Returns the registered public key.
     *
     * @return Public key.
     */
    public String getPublicKey() {

        return publicKey;
    }

    /**
     * Returns the signed challenge value.
     *
     * @return Challenge value.
     */
    public String getChallengeUsed() {

        return challengeUsed;
    }

    /**
     * Returns the current device status.
     *
     * @return Device status.
     */
    public String getStatus() {

        return status;
    }

    /**
     * Returns the registration timestamp.
     *
     * @return Registration timestamp.
     */
    public Timestamp getRegisteredAt() {

        return registeredAt;
    }

    /**
     * Returns the last-used timestamp.
     *
     * @return Last-used timestamp.
     */
    public Timestamp getLastUsedAt() {

        return lastUsedAt;
    }

    /**
     * Returns the metadata payload.
     *
     * @return Metadata string.
     */
    public String getMetadata() {

        return metadata;
    }

    /**
     * Builder for {@link RegisteredDevice}.
     */
    public static class Builder {

        private String id;
        private String userId;
        private String deviceName;
        private String deviceModel;
        private String deviceOs;
        private String deviceType;
        private String publicKey;
        private String challengeUsed;
        private String status = "ACTIVE";
        private Timestamp registeredAt;
        private Timestamp lastUsedAt;
        private String metadata;

        /**
         * Sets the device identifier.
         *
         * @param id Device identifier.
         * @return Builder instance.
         */
        public Builder id(String id) {

            this.id = id;
            return this;
        }

        /**
         * Sets the user identifier.
         *
         * @param userId User identifier.
         * @return Builder instance.
         */
        public Builder userId(String userId) {

            this.userId = userId;
            return this;
        }

        /**
         * Sets the device name.
         *
         * @param deviceName Device name.
         * @return Builder instance.
         */
        public Builder deviceName(String deviceName) {

            this.deviceName = deviceName;
            return this;
        }

        /**
         * Sets the device model.
         *
         * @param deviceModel Device model.
         * @return Builder instance.
         */
        public Builder deviceModel(String deviceModel) {

            this.deviceModel = deviceModel;
            return this;
        }

        /**
         * Sets the device OS.
         *
         * @param deviceOs Device OS.
         * @return Builder instance.
         */
        public Builder deviceOs(String deviceOs) {

            this.deviceOs = deviceOs;
            return this;
        }

        /**
         * Sets the device type.
         *
         * @param deviceType Device type.
         * @return Builder instance.
         */
        public Builder deviceType(String deviceType) {

            this.deviceType = deviceType;
            return this;
        }

        /**
         * Sets the public key.
         *
         * @param publicKey Public key.
         * @return Builder instance.
         */
        public Builder publicKey(String publicKey) {

            this.publicKey = publicKey;
            return this;
        }

        /**
         * Sets the challenge value.
         *
         * @param challengeUsed Challenge value.
         * @return Builder instance.
         */
        public Builder challengeUsed(String challengeUsed) {

            this.challengeUsed = challengeUsed;
            return this;
        }

        /**
         * Sets the device status.
         *
         * @param status Device status.
         * @return Builder instance.
         */
        public Builder status(String status) {

            this.status = status;
            return this;
        }

        /**
         * Sets the registration timestamp.
         *
         * @param registeredAt Registration timestamp.
         * @return Builder instance.
         */
        public Builder registeredAt(Timestamp registeredAt) {

            this.registeredAt = registeredAt;
            return this;
        }

        /**
         * Sets the last-used timestamp.
         *
         * @param lastUsedAt Last-used timestamp.
         * @return Builder instance.
         */
        public Builder lastUsedAt(Timestamp lastUsedAt) {

            this.lastUsedAt = lastUsedAt;
            return this;
        }

        /**
         * Sets metadata.
         *
         * @param metadata Metadata value.
         * @return Builder instance.
         */
        public Builder metadata(String metadata) {

            this.metadata = metadata;
            return this;
        }

        /**
         * Builds a registered device instance.
         *
         * @return Registered device.
         */
        public RegisteredDevice build() {

            return new RegisteredDevice(this);
        }
    }
}

