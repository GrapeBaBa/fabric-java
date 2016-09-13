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

import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.collect.Lists;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import io.grpc.Channel;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NegotiationType;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.SslContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import protos.*;

import javax.annotation.Nullable;
import javax.net.ssl.SSLException;
import java.io.File;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;

/**
 * An implementation for MemberService.
 *
 * @see me.grapebaba.hyperledger.fabric.MemberService
 */
public class MemberServiceImpl implements MemberService {
    private static final Logger logger = LoggerFactory.getLogger(MemberServiceImpl.class);

    private ECAAGrpc.ECAAFutureStub ecaaStub;

    private ECAPGrpc.ECAPFutureStub ecapStub;

    private TCAPGrpc.TCAPFutureStub tcapStub;

    private TLSCAPGrpc.TLSCAPFutureStub tlscapStub;

    private Crypto crypto;

    public MemberServiceImpl(String host, int port, String pemPath, String serverHostOverride) {
        Preconditions.checkNotNull(host);
        Preconditions.checkNotNull(port);
        Preconditions.checkNotNull(pemPath);
        Preconditions.checkNotNull(serverHostOverride);

        InetAddress address = null;
        try {
            address = InetAddress.getByAddress(serverHostOverride, InetAddress.getByName(host).getAddress());
        } catch (UnknownHostException e) {
            logger.error("Unknown host exception {}, host address {}", e, host);
            Throwables.propagate(e);
        }

        SslContext sslContext = null;
        try {
            sslContext = GrpcSslContexts.forClient().trustManager(
                    new File(pemPath)).build();
        } catch (SSLException e) {
            logger.error("SSL exception {}, pem path {}", e, pemPath);
            Throwables.propagate(e);
        }

        final Channel channel = NettyChannelBuilder.forAddress(new InetSocketAddress(address, port))
                .sslContext(sslContext)
                .build();

        initializeStubs(channel);
        crypto = new Crypto(SecurityLevel.CURVE_P_256_Size, HashAlgorithm.SHA3);
    }

    public MemberServiceImpl(String host, int port) {
        Preconditions.checkNotNull(host);
        Preconditions.checkNotNull(port);

        InetAddress address = null;
        try {
            address = InetAddress.getByName(host);
        } catch (UnknownHostException e) {
            logger.error("Unknown host exception {}, host address {}", e, host);
            Throwables.propagate(e);
        }

        final Channel channel = NettyChannelBuilder
                .forAddress(new InetSocketAddress(address, port))
                .negotiationType(NegotiationType.PLAINTEXT)
                .build();

        initializeStubs(channel);
    }

    @Override
    public ListenableFuture<String> register(RegistrationRequest registrationRequest, Member member) {
        if (Strings.isNullOrEmpty(registrationRequest.getEnrollmentID())) {
            return Futures.immediateFailedFuture(new RuntimeException("EnrollmentID is empty."));
        }

        if (null == member) {
            return Futures.immediateFailedFuture(new RuntimeException("Member is empty."));
        }

        Ca.Registrar.Builder registrarBuilder = Ca.Registrar.newBuilder()
                .setId(Ca.Identity.newBuilder().setId(member.getName()).build());

        if (!registrationRequest.getAllowableRols().isEmpty()) {
            registrarBuilder.addAllRoles(Lists.transform(registrationRequest.getAllowableRols(), new Function<Ca.Role, String>() {
                @Nullable
                @Override
                public String apply(@Nullable Ca.Role input) {
                    return input.name();
                }
            }));
        }
        if (!registrationRequest.getAllowableDelegateRols().isEmpty()) {
            registrarBuilder.addAllRoles(Lists.transform(registrationRequest.getAllowableDelegateRols(), new Function<Ca.Role, String>() {
                @Nullable
                @Override
                public String apply(@Nullable Ca.Role input) {
                    return input.name();
                }
            }));
        }

        Ca.RegisterUserReq registerUserReq = Ca.RegisterUserReq.newBuilder()
                .setId(Ca.Identity.newBuilder().setId(registrationRequest.getEnrollmentID()))
                .setRoleValue(rolesToMask(registrationRequest.getRoles()))
                .setAffiliation(registrationRequest.getAffiliation())
                .setRegistrar(registrarBuilder)
                .build();

        ByteString message = registerUserReq.toByteString();
        ByteString signedMessage = crypto.ecdsaSign(member.getEnrollment().getKey(), message);

        Ca.Signature.Builder signatureBuilder = Ca.Signature.newBuilder().setType(Ca.CryptoType.ECDSA)
                .setR(message)
                .setS(signedMessage);


        return Futures.transform(ecaaStub.registerUser(registerUserReq.toBuilder().setSig(signatureBuilder).build()), new Function<Ca.Token, String>() {
            @Nullable
            @Override
            public String apply(@Nullable Ca.Token input) {
                return input.getTok().toString();
            }
        });
    }

    @Override
    public ListenableFuture<Enrollment> enroll(EnrollmentRequest enrollmentRequest) {
        Preconditions.checkNotNull(enrollmentRequest.getEnrollmentID());
        Preconditions.checkNotNull(enrollmentRequest.getEnrollmentSecret());

        KeyPair signingKeyPair = crypto.ecdsaKeyGen();
        PublicKey signingPublicKey = signingKeyPair.getPublic();

        KeyPair encryptionKeyPair = crypto.ecdsaKeyGen();
        PublicKey encryptionPublicKey = encryptionKeyPair.getPublic();

        Ca.ECertCreateReq eCertCreateReq = Ca.ECertCreateReq.newBuilder().setId(Ca.Identity.newBuilder().setId(enrollmentRequest.getEnrollmentID()).build())
                .setTok(Ca.Token.newBuilder().setTok(ByteString.copyFromUtf8(enrollmentRequest.getEnrollmentSecret())).build())
                .setTs(Timestamp.newBuilder().setSeconds(System.currentTimeMillis() / 1000).setNanos(0))
                .setSign(Ca.PublicKey.newBuilder().setType(Ca.CryptoType.ECDSA).setKey(ByteString.copyFrom(signingPublicKey.getEncoded())).build())
                .setEnc(Ca.PublicKey.newBuilder().setType(Ca.CryptoType.ECDSA).setKey(ByteString.copyFrom(encryptionPublicKey.getEncoded())).build())
                .build();

        Futures.addCallback(ecapStub.createCertificatePair(eCertCreateReq), new FutureCallback<Ca.ECertCreateResp>() {
            @Override
            public void onSuccess(@Nullable Ca.ECertCreateResp result) {

            }

            @Override
            public void onFailure(Throwable t) {

            }
        });
        return null;
    }

    private void initializeStubs(Channel channel) {
        ecaaStub = ECAAGrpc.newFutureStub(channel);
        ecapStub = ECAPGrpc.newFutureStub(channel);
        tcapStub = TCAPGrpc.newFutureStub(channel);
        tlscapStub = TLSCAPGrpc.newFutureStub(channel);
    }

    // Convert a list of member type names to the role mask currently used by the peer
    private int rolesToMask(List<Ca.Role> roles) {
        int mask = 0;
        for (Ca.Role role : roles) {
            switch (role) {
                case CLIENT:
                    mask |= Ca.Role.CLIENT_VALUE;
                    break;       // Client mask
                case PEER:
                    mask |= Ca.Role.PEER_VALUE;
                    break;       // Peer mask
                case VALIDATOR:
                    mask |= Ca.Role.VALIDATOR_VALUE;
                    break;  // Validator mask
                case AUDITOR:
                    mask |= Ca.Role.AUDITOR_VALUE;
                    break;    // Auditor mask
            }
        }

        if (mask == 0) {
            mask = Ca.Role.CLIENT_VALUE;  // Client
        }

        return mask;
    }
}
