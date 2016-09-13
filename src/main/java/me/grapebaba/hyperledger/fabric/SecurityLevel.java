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
 * Security levels.
 */
public enum SecurityLevel {
    CURVE_P_256_Size {
        @Override
        public String curveName() {
            return "secp256r1";
        }

        @Override
        public int size() {
            return 256;
        }
    }, CURVE_P_384_Size {
        @Override
        public String curveName() {
            return "secp384r1";
        }

        @Override
        public int size() {
            return 384;
        }
    };

    public abstract String curveName();

    public abstract int size();

    public static SecurityLevel from(String curveName) {
        switch (curveName) {
            case "secp256r1":
                return CURVE_P_256_Size;
            case "secp384r1":
                return CURVE_P_384_Size;
        }
        throw new RuntimeException(String.format("Not supported this curve name %s", curveName));
    }
}
