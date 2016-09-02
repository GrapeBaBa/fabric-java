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

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

/**
 * The class representing a chain with which the client SDK interacts.
 */
public class Chain {

    private LoadingCache<String, Member> members;

    public Chain() {

    }

    private void initialize() {
        members = CacheBuilder.newBuilder().build(new CacheLoader<String, Member>() {
            @Override
            public Member load(String key) throws Exception {
                return new Member(key, Chain.this);
            }
        });
    }

//// Name of the chain is only meaningful to the client
//    private name:string;
//
//    // The peers on this chain to which the client can connect
//    private peers:Peer[] = [];
//
//    // Security enabled flag
//    private securityEnabled:boolean = true;
//
//    // A member cache associated with this chain
//    // TODO: Make an LRU to limit size of member cache
//    private members:{[name:string]:Member} = {};
//
//    // The number of tcerts to get in each batch
//    private tcertBatchSize:number = 200;
//
//    // The registrar (if any) that registers & enrolls new members/users
//    private registrar:Member;
//
//    // The member services used for this chain
//    private memberServices:MemberServices;
//
//    // The key-val store used for this chain
//    private keyValStore:KeyValStore;
//
//    // Is in dev mode or network mode
//    private devMode:boolean = false;
//
//    // If in prefetch mode, we prefetch tcerts from member services to help performance
//    private preFetchMode:boolean = true;
//
//    // Temporary variables to control how long to wait for deploy and invoke to complete before
//    // emitting events.  This will be removed when the SDK is able to receive events from the
//    private deployWaitTime:number = 20;
//    private invokeWaitTime:number = 5;
//
//    // The crypto primitives object
//    cryptoPrimitives:crypto.Crypto;
//

}
