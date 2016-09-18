/*
 * Copyright 2016 281165273@qq.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package me.grapebaba.hyperledger.fabric;

import com.google.protobuf.ByteString;

import java.security.PrivateKey;

/**
 * Enrollment metadata.
 */
public class Enrollment {
    private ByteString cert;

    private ByteString chainKey;

    private PrivateKey key;

    private Enrollment(Builder builder) {
        setCert(builder.cert);
        setChainKey(builder.chainKey);
        setKey(builder.key);
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public ByteString getCert() {
        return cert;
    }

    public void setCert(ByteString cert) {
        this.cert = cert;
    }

    public ByteString getChainKey() {
        return chainKey;
    }

    public void setChainKey(ByteString chainKey) {
        this.chainKey = chainKey;
    }

    public PrivateKey getKey() {
        return key;
    }

    public void setKey(PrivateKey key) {
        this.key = key;
    }

    /**
     * {@code Enrollment} builder static inner class.
     */
    public static final class Builder {
        private ByteString cert;
        private ByteString chainKey;
        private PrivateKey key;

        private Builder() {
        }

        /**
         * Sets the {@code cert} and returns a reference to this Builder so that the methods can be chained together.
         *
         * @param cert the {@code cert} to set
         * @return a reference to this Builder
         */
        public Builder withCert(ByteString cert) {
            this.cert = cert;
            return this;
        }

        /**
         * Sets the {@code chainKey} and returns a reference to this Builder so that the methods can be chained together.
         *
         * @param chainKey the {@code chainKey} to set
         * @return a reference to this Builder
         */
        public Builder withChainKey(ByteString chainKey) {
            this.chainKey = chainKey;
            return this;
        }

        /**
         * Sets the {@code key} and returns a reference to this Builder so that the methods can be chained together.
         *
         * @param key the {@code key} to set
         * @return a reference to this Builder
         */
        public Builder withKey(PrivateKey key) {
            this.key = key;
            return this;
        }

        /**
         * Returns a {@code Enrollment} built from the parameters previously set.
         *
         * @return a {@code Enrollment} built with parameters of this {@code Enrollment.Builder}
         */
        public Enrollment build() {
            return new Enrollment(this);
        }
    }
}
