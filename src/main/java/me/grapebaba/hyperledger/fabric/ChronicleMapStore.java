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

import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import net.openhft.chronicle.map.ChronicleMap;
import net.openhft.chronicle.map.ChronicleMapBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;

/**
 * KVStore implementation based on ChronicleMap.
 */
public class ChronicleMapStore implements KVStore<Member> {
    private static final Logger LOGGER = LoggerFactory.getLogger(ChronicleMapStore.class);

    private final ChronicleMap<String, Member> store;

    public ChronicleMapStore(String filePath) {
        try {
            this.store = ChronicleMapBuilder
                    .of(String.class, Member.class)
                    .entries(50000)
                    .createOrRecoverPersistedTo(new File(filePath));
        } catch (IOException e) {
            LOGGER.error("Initialize persistent KVStore exception", e);
            throw new RuntimeException(e);
        }
    }


    @Override
    public ListenableFuture<Member> getValue(String name) {
        return Futures.immediateFuture(store.get(name));
    }

    @Override
    public ListenableFuture<Member> setValue(String name, Member value) {
        return Futures.immediateFuture(store.put(name, value));
    }
}