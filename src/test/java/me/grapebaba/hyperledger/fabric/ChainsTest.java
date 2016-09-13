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

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.junit.Test;

import java.security.PrivateKey;

/**
 * Test case for chains.
 */
public class ChainsTest {

    @Test
    public void testChain() {
//        Chain chain=Chains.getChain("test");
//        chain.setMembersStore(new ChronicleMapStore("/tmp/fabric-java/kvstore"));
//        chain.setMemberService(new MemberServiceImpl("localhost",999));

        Crypto crypto = new Crypto(SecurityLevel.CURVE_P_256_Size, HashAlgorithm.SHA3);
        PrivateKey privateKey = crypto.ecdsaKeyGen().getPrivate();
        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) privateKey;
        ECNamedCurveSpec ecNamedCurveParameterSpec = (ECNamedCurveSpec) bcecPrivateKey.getParams();
        System.out.print(ecNamedCurveParameterSpec.getName());

    }
}
