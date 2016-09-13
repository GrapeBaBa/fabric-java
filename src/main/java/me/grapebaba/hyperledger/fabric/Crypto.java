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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final String curveName;

//    private HashAlgorithm hashAlgorithm;

//    private Object hashFunctionKeyDerivation;

//    private int hashOutputSize;

//    private SecurityLevel securityLevel;

//    private String suite;

    private final String signatureName;


    public Crypto(SecurityLevel securityLevel, HashAlgorithm hashAlgorithm) {
        curveName = SecurityLevel.CURVE_P_256_Size == securityLevel ? "secp256r1" : "secp384r1";
        if (hashAlgorithm == HashAlgorithm.SHA2 && securityLevel == SecurityLevel.CURVE_P_384_Size) {
            throw new RuntimeException("SHA2 not support size 384");
        } else if (hashAlgorithm == HashAlgorithm.SHA2 && securityLevel == SecurityLevel.CURVE_P_256_Size) {
            signatureName = "SHA256withECDDSA";
        } else if (hashAlgorithm == HashAlgorithm.SHA3 && securityLevel == SecurityLevel.CURVE_P_384_Size) {
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

//    public ByteString eciesDecrypt(PrivateKey recipientPrivateKey, String cipherText) {
//        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) recipientPrivateKey;
//        ECNamedCurveSpec ecNamedCurveSpec = (ECNamedCurveSpec) bcecPrivateKey.getParams();
//
//        int level = SecurityLevel.from(ecNamedCurveSpec.getName()).size();
//        //cipherText = ephemeralPubKeyBytes + encryptedTokBytes + macBytes
//        //ephemeralPubKeyBytes = first ((384+7)/8)*2 + 1 bytes = first 97 bytes
//        //hmac is sha3_384 = 48 bytes or sha3_256 = 32 bytes
//        int ephemeralPubKeyLength = ((level + 7) / 8) * 2 + 1;
//        int hmacLength = level >> 3;
//        int cipherTextLength = ByteString.copyFromUtf8(cipherText).size();
//
//        if (ct_len <= Rb_len + D_len)
//            throw new Error("Illegal cipherText length: " + ct_len + " must be > " + (Rb_len + D_len));
//
//        var Rb = cipherText.slice(0, Rb_len);  // ephemeral public key bytes
//        var EM = cipherText.slice(Rb_len, ct_len - D_len);  // encrypted content bytes
//        var D = cipherText.slice(ct_len - D_len);
//
//        // debug("Rb :\n", new Buffer(Rb).toString('hex'));
//        // debug("EM :\n", new Buffer(EM).toString('hex'));
//        // debug("D  :\n", new Buffer(D).toString('hex'));
//
//        var EC = elliptic.ec;
//        //var curve = elliptic.curves['p'+level];
//        var ecdsa = new EC('p' + level);
//
//        //convert bytes to usable key object
//        var ephPubKey = ecdsa.keyFromPublic(new Buffer(Rb, 'hex'), 'hex');
//        //var encPrivKey = ecdsa.keyFromPrivate(ecKeypair2.prvKeyObj.prvKeyHex, 'hex');
//        var privKey = ecdsa.keyFromPrivate(recipientPrivateKey.prvKeyHex, 'hex');
//        // debug('computing Z...', privKey, ephPubKey);
//
//        var Z = privKey.derive(ephPubKey.pub);
//        // debug('Z computed', Z);
//        // debug('secret:  ', new Buffer(Z.toArray(), 'hex'));
//        var kdfOutput = self.hkdf(Z.toArray(), ECIESKDFOutput, null, null);
//        var aesKey = kdfOutput.slice(0, AESKeyLength);
//        var hmacKey = kdfOutput.slice(AESKeyLength, AESKeyLength + HMACKeyLength);
//        // debug('secret:  ', new Buffer(Z.toArray(), 'hex'));
//        // debug('aesKey:  ', new Buffer(aesKey, 'hex'));
//        // debug('hmacKey: ', new Buffer(hmacKey, 'hex'));
//
//        var recoveredD = self.hmac(hmacKey, EM);
//        debug('recoveredD:  ', new Buffer(recoveredD).toString('hex'));
//
//        if (D.compare(new Buffer(recoveredD)) != 0) {
//            // debug("D="+D.toString('hex')+" vs "+new Buffer(recoveredD).toString('hex'));
//            throw new Error("HMAC verify failed");
//        }
//        var iv = EM.slice(0, IVLength);
//        var cipher = crypto.createDecipheriv('aes-256-cfb', new Buffer(aesKey), iv);
//        var decryptedBytes = cipher.update(EM.slice(IVLength));
//        // debug("decryptedBytes: ",new Buffer(decryptedBytes).toString('hex'));
//        return decryptedBytes;
//    }

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

    public static void main(String[] args) throws Exception {
        Crypto crypto = new Crypto(SecurityLevel.CURVE_P_256_Size, HashAlgorithm.SHA3);
        PrivateKey privateKey = crypto.ecdsaKeyGen().getPrivate();
        System.out.println(privateKey.getAlgorithm());
    }
}
