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
import java.util.Map;

/**
 * A member is an entity that transacts on a chain.
 * Types of members include end users, peers, etc.
 */
public class Member {
    private Chain chain;

    private String name;

    private List<Ca.Role> roles;

    private String account;

    private String affiliation;

    private String enrollmentSecret;

    private Enrollment enrollment;

    private MemberService memberService;

    private KVStore kvStore;

    private String kvStoreName;

    private Map<String, TCertGetter> tcertGetterMap;

    private int tcertBatchSize;

    public Member(String name, Chain chain) {
        this.name = name;
        this.chain = chain;
    }

    public Chain getChain() {
        return chain;
    }

    public void setChain(Chain chain) {
        this.chain = chain;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<Ca.Role> getRoles() {
        return roles;
    }

    public void setRoles(List<Ca.Role> roles) {
        this.roles = roles;
    }

    public String getAccount() {
        return account;
    }

    public void setAccount(String account) {
        this.account = account;
    }

    public String getAffiliation() {
        return affiliation;
    }

    public void setAffiliation(String affiliation) {
        this.affiliation = affiliation;
    }

    public String getEnrollmentSecret() {
        return enrollmentSecret;
    }

    public void setEnrollmentSecret(String enrollmentSecret) {
        this.enrollmentSecret = enrollmentSecret;
    }

    public Enrollment getEnrollment() {
        return enrollment;
    }

    public void setEnrollment(Enrollment enrollment) {
        this.enrollment = enrollment;
    }

    public MemberService getMemberService() {
        return memberService;
    }

    public void setMemberService(MemberService memberService) {
        this.memberService = memberService;
    }

    public KVStore getKvStore() {
        return kvStore;
    }

    public void setKvStore(KVStore kvStore) {
        this.kvStore = kvStore;
    }

    public String getKvStoreName() {
        return kvStoreName;
    }

    public void setKvStoreName(String kvStoreName) {
        this.kvStoreName = kvStoreName;
    }

    public Map<String, TCertGetter> getTcertGetterMap() {
        return tcertGetterMap;
    }

    public void setTcertGetterMap(Map<String, TCertGetter> tcertGetterMap) {
        this.tcertGetterMap = tcertGetterMap;
    }

    public int getTcertBatchSize() {
        return tcertBatchSize;
    }

    public void setTcertBatchSize(int tcertBatchSize) {
        this.tcertBatchSize = tcertBatchSize;
    }
}
