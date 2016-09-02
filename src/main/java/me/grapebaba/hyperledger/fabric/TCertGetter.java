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
import protos.Ca;

import java.util.List;

/**
 * A class to get TCerts.
 * There is one class per set of attributes requested by each member.
 */
public class TCertGetter {
    private Chain chain;

    private Member member;

    private List<String> attrs;

    private String key;

    private MemberService memberService;

    private List<Object> tcerts;

    //private arrivalRate

    //private getTcertResponseTime

    private ListenableFuture<Ca.TCert> getTCertWaiters;

    private boolean gettingTCerts;
}
