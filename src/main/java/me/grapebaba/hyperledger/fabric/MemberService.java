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

import com.google.common.util.concurrent.ListenableFuture;

/**
 * A service for interacting membersrvc.
 */
public interface MemberService {

    /**
     * Register the member and return an enrollment secret.
     *
     * @param registrationRequest Registration request with the following fields: name, role
     * @param registrar           The identity of the registar (i.e. who is performing the registration)
     * @return A listenableFuture for adding listener to handle enrollmentSecret
     */
    ListenableFuture<String> register(RegistrationRequest registrationRequest, Member registrar);
}
