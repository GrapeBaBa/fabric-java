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

import protos.Ca;

import java.util.List;

/**
 * A registration request is information required to register a user, peer, or other
 * type of member.
 */
public class RegistrationRequest {

    private String enrollmentID;

    private List<Ca.Role> roles;

    private String affiliation;

    private List<Ca.Role> allowableRols;

    private List<Ca.Role> allowableDelegateRols;

    public String getEnrollmentID() {
        return enrollmentID;
    }

    public void setEnrollmentID(String enrollmentID) {
        this.enrollmentID = enrollmentID;
    }

    public List<Ca.Role> getRoles() {
        return roles;
    }

    public void setRoles(List<Ca.Role> roles) {
        this.roles = roles;
    }

    public String getAffiliation() {
        return affiliation;
    }

    public void setAffiliation(String affiliation) {
        this.affiliation = affiliation;
    }

    public List<Ca.Role> getAllowableRols() {
        return allowableRols;
    }

    public void setAllowableRols(List<Ca.Role> allowableRols) {
        this.allowableRols = allowableRols;
    }

    public List<Ca.Role> getAllowableDelegateRols() {
        return allowableDelegateRols;
    }

    public void setAllowableDelegateRols(List<Ca.Role> allowableDelegateRols) {
        this.allowableDelegateRols = allowableDelegateRols;
    }
}
