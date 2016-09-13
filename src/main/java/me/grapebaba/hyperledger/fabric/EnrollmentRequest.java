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

/**
 * A enrollment request is information required to enroll a user, peer, or other
 * type of member.
 */
public class EnrollmentRequest {
    private String enrollmentID;

    private String enrollmentSecret;

    public String getEnrollmentID() {
        return enrollmentID;
    }

    public String getEnrollmentSecret() {
        return enrollmentSecret;
    }

    private EnrollmentRequest(Builder builder) {
        enrollmentID = builder.enrollmentID;
        enrollmentSecret = builder.enrollmentSecret;
    }

    public static Builder newBuilder() {
        return new Builder();
    }


    /**
     * {@code EnrollmentRequest} builder static inner class.
     */
    public static final class Builder {
        private String enrollmentID;
        private String enrollmentSecret;

        private Builder() {
        }

        /**
         * Sets the {@code enrollmentID} and returns a reference to this Builder so that the methods can be chained together.
         *
         * @param enrollmentID the {@code enrollmentID} to set
         * @return a reference to this Builder
         */
        public Builder withEnrollmentID(String enrollmentID) {
            this.enrollmentID = enrollmentID;
            return this;
        }

        /**
         * Sets the {@code enrollmentSecret} and returns a reference to this Builder so that the methods can be chained together.
         *
         * @param enrollmentSecret the {@code enrollmentSecret} to set
         * @return a reference to this Builder
         */
        public Builder withEnrollmentSecret(String enrollmentSecret) {
            this.enrollmentSecret = enrollmentSecret;
            return this;
        }

        /**
         * Returns a {@code EnrollmentRequest} built from the parameters previously set.
         *
         * @return a {@code EnrollmentRequest} built with parameters of this {@code EnrollmentRequest.Builder}
         */
        public EnrollmentRequest build() {
            return new EnrollmentRequest(this);
        }
    }
}
