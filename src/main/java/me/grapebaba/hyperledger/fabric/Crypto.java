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


import com.google.protobuf.ByteString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * The crypto class contains implementations of various crypto primitives.
 */
public class Crypto {
    private static final Logger logger = LoggerFactory.getLogger(Crypto.class);

    private static final int NONCE_SIZE = 24;

    private final String curveName;

//    private HashAlgorithmEnum hashAlgorithm;

//    private Object hashFunctionKeyDerivation;

//    private int hashOutputSize;

//    private SecurityLevelEnum securityLevel;

//    private String suite;

    private final String signatureName;


    public Crypto(SecurityLevelEnum securityLevel, HashAlgorithmEnum hashAlgorithm) {
        curveName = SecurityLevelEnum.CURVE_P_256_Size == securityLevel ? "secp256r1" : "secp384r1";
        if (hashAlgorithm == HashAlgorithmEnum.SHA2 && securityLevel == SecurityLevelEnum.CURVE_P_384_Size) {
            throw new RuntimeException("SHA2 not support size 384");
        } else if (hashAlgorithm == HashAlgorithmEnum.SHA2 && securityLevel == SecurityLevelEnum.CURVE_P_256_Size) {
            signatureName = "SHA256withECDDSA";
        } else if (hashAlgorithm == HashAlgorithmEnum.SHA3 && securityLevel == SecurityLevelEnum.CURVE_P_384_Size) {
            signatureName = "SHA3-384withECDSA";
        } else {
            signatureName = "SHA3-256withECDSA";
        }
    }

    public byte[] generateNonce() {
        return SecureRandom.getSeed(NONCE_SIZE);
    }

    public KeyPair ecdsaKeyGen() {
        try {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(curveName);
            KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
            g.initialize(ecGenSpec);
            return g.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            logger.error("Generate keypair error, curveName {}", curveName);
            throw new RuntimeException(e);
        }
    }

//    public String ecdsaKeyFromPrivate(ByteString privateKey, BaseEncoding encoding) {
//        return encoding.encode(privateKey);
//    }
//
//    public String ecdsaKeyFromPublic(PublicKey publicKey, BaseEncoding encoding) {
//        final byte[] key = publicKey.getEncoded();
//        return encoding.encode(key);
//    }
//
//    public String ecdsaPEMToPublicKey(byte[] publicKey, BaseEncoding encoding) {
//        try {
//            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
//            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKey);
//            encoding.encode(keyFactory.generatePublic(pubKeySpec).getEncoded());
//        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
//            logger.error("Encode public key error");
//            throw new RuntimeException(e);
//        }
//    }
//
//    public byte[] ecdsaPrivateKeyToASN1(String privateKey, BaseEncoding encoding) {
//        try {
//            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
//            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encoding.decode(privateKey));
//            return keyFactory.generatePrivate(privateKeySpec).getEncoded();
//        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
//            logger.error("Decode private key error");
//            throw new RuntimeException(e);
//        }
//    }

    public ByteString ecdsaSign(ByteString privateKey, ByteString message) {
        try {
            Signature signature = Signature.getInstance(signatureName, "BC");
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey.toByteArray());
            signature.initSign(keyFactory.generatePrivate(privateKeySpec));
            signature.update(message.toByteArray());
            return ByteString.copyFrom(signature.sign());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            logger.error("Ecdsa sign error");
            throw new RuntimeException(e);
        }
    }

}
