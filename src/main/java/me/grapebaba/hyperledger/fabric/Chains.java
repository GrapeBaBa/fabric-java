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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutionException;

/**
 * Chain manager.
 */
public abstract class Chains {

    private static final Logger LOGGER = LoggerFactory.getLogger(Chains.class);

    private static final LoadingCache<String, Chain> CHAINS = CacheBuilder.newBuilder().build(new CacheLoader<String, Chain>() {
        @Override
        public Chain load(String key) throws Exception {
            return new Chain(key);
        }
    });

    public static Chain getChain(String name) {
        try {
            return CHAINS.get(name);
        } catch (ExecutionException e) {
            LOGGER.error("Get chain exception", e);
            throw new RuntimeException(e);
        }
    }
}
