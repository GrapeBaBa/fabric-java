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
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * The crypto class contains implementations of various crypto primitives.
 */
public class Crypto {
    private static final Logger logger = LoggerFactory.getLogger(Crypto.class);

    private static final int NONCE_SIZE = 24;

    private static final int AESKEY_LENGTH = 32;

    private static final int HMACKEY_LENGTH = 32;

    private static final int BLOCK_BIT_SIZE = 256;

    private static final int IV_LENGTH = 16;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final String curveName;

    private final Digest digest;


    public Crypto(SecurityLevel securityLevel, HashAlgorithm hashAlgorithm) {
        curveName = SecurityLevel.CURVE_P_256_Size == securityLevel ? "secp256r1" : "secp384r1";
        if (hashAlgorithm == HashAlgorithm.SHA2 && securityLevel == SecurityLevel.CURVE_P_384_Size) {
            throw new RuntimeException("SHA2 not support size 384");
        } else if (hashAlgorithm == HashAlgorithm.SHA2 && securityLevel == SecurityLevel.CURVE_P_256_Size) {
            digest = new SHA256Digest();
        } else if (hashAlgorithm == HashAlgorithm.SHA3 && securityLevel == SecurityLevel.CURVE_P_384_Size) {
            digest = new SHA3Digest(384);
        } else {
            digest = new SHA3Digest();
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
            logger.error("Generate keypair exception", e);
            throw new RuntimeException(e);
        }
    }

    public ByteString eciesDecrypt(PrivateKey recipientPrivateKey, ByteString cipherText) {
        BCECPrivateKey bcecPrivateKey = (BCECPrivateKey) recipientPrivateKey;
        ECNamedCurveSpec ecNamedCurveSpec = (ECNamedCurveSpec) bcecPrivateKey.getParams();
        int level = SecurityLevel.from(ecNamedCurveSpec.getName()).size();

        //cipherText = ephemeralPubKeyBytes + encryptedTokBytes + macBytes
        //ephemeralPubKeyBytes = first ((384+7)/8)*2 + 1 bytes = first 97 bytes
        //hmac is sha3_384 = 48 bytes or sha3_256 = 32 bytes
        int ephemeralPubKeyLength = ((level + 7) / 8) * 2 + 1;
        int hmacLength = level >> 3;
        int cipherTextLength = cipherText.size();

        if (cipherTextLength <= ephemeralPubKeyLength + hmacLength)
            throw new RuntimeException(String.format("Illegal cipherText length: %d must be > %d", cipherTextLength, ephemeralPubKeyLength + hmacLength));

        ByteString ephemeralPubKey = cipherText.substring(0, ephemeralPubKeyLength);
        ByteString encryptedContent = cipherText.substring(ephemeralPubKeyLength, cipherTextLength - hmacLength);
        ByteString hmac = cipherText.substring(cipherTextLength - hmacLength);

        ECPrivateKeyParameters ecdhPrivateKeyParameters;
        try {
            ecdhPrivateKeyParameters = (ECPrivateKeyParameters) (PrivateKeyFactory.createKey(bcecPrivateKey.getEncoded()));
        } catch (IOException e) {
            logger.error("ECIES decrypt load private key exception", e);
            throw new RuntimeException(e);
        }
        ECDomainParameters ecDomainParameters = ecdhPrivateKeyParameters.getParameters();
        ECCurve ecCurve = ecDomainParameters.getCurve();
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(ecCurve.decodePoint(ephemeralPubKey.toByteArray()), ecDomainParameters);
        BasicAgreement agree = new ECDHBasicAgreement();
        agree.init(ecdhPrivateKeyParameters);
        byte[] keyAgreement = agree.calculateAgreement(ecPublicKeyParameters).toByteArray();

        HKDFParameters hkdfParameters = new HKDFParameters(keyAgreement, null, null);
        HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(digest);
        hkdfBytesGenerator.init(hkdfParameters);
        byte[] hkdfOutputBytes = new byte[AESKEY_LENGTH + HMACKEY_LENGTH];
        hkdfBytesGenerator.generateBytes(hkdfOutputBytes, 0, AESKEY_LENGTH + HMACKEY_LENGTH);
        ByteString hkdfOutput = ByteString.copyFrom(hkdfOutputBytes);
        ByteString aesKey = hkdfOutput.substring(0, AESKEY_LENGTH);
        ByteString hmacKey = hkdfOutput.substring(AESKEY_LENGTH, AESKEY_LENGTH + HMACKEY_LENGTH);
        HMac hMac = new HMac(digest);
        hMac.init(new KeyParameter(hmacKey.toByteArray()));
        hMac.update(encryptedContent.toByteArray(), 0, encryptedContent.size());
        byte[] recoveredHmac = new byte[hMac.getMacSize()];
        hMac.doFinal(recoveredHmac, 0);
        if (!MessageDigest.isEqual(hmac.toByteArray(), recoveredHmac)) {
            throw new RuntimeException("HMAC verify failed");
        }

        CFBBlockCipher aesCipher = new CFBBlockCipher(
                new AESEngine(), BLOCK_BIT_SIZE);
        ByteString iv = encryptedContent.substring(0, IV_LENGTH);
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(aesKey.toByteArray()), iv.toByteArray());
        aesCipher.init(false, ivAndKey);
        byte[] decryptedBytes = new byte[500];
        aesCipher.decryptBlock(encryptedContent.substring(IV_LENGTH).toByteArray(), 0, decryptedBytes, 0);
        return ByteString.copyFrom(decryptedBytes);
    }

    public BigInteger[] ecdsaSign(PrivateKey privateKey, ByteString message) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(digest));
        ECPrivateKeyParameters ecdhPrivateKeyParameters;
        try {
            ecdhPrivateKeyParameters = (ECPrivateKeyParameters) (PrivateKeyFactory.createKey(privateKey.getEncoded()));
        } catch (IOException e) {
            logger.error("ECDSA sign load private key exception", e);
            throw new RuntimeException(e);
        }
        signer.init(true, ecdhPrivateKeyParameters);
        return signer.generateSignature(message.toByteArray());
    }

    public static void main(String[] args) throws Exception {
        Crypto crypto = new Crypto(SecurityLevel.CURVE_P_256_Size, HashAlgorithm.SHA3);
        PrivateKey privateKey = crypto.ecdsaKeyGen().getPrivate();
        System.out.println(privateKey.getAlgorithm());
    }
}
