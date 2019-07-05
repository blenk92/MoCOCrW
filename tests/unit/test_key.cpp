/*
 * #%L
 * %%
 * Copyright (C) 2018 BMW Car IT GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "key.cpp"

using namespace mococrw;
using namespace ::testing;


class KeyHandlingTests : public ::testing::Test
{
public:
    void SetUp() override;

    static std::string _pemEccPrivKeySect409k1;
    static std::string _pemEccPubKeySect409k1;
    static std::string _pemEccPrivKeyED25519;
    static std::string _pemEccPubKeyED25519;
protected:
    mococrw::AsymmetricKeypair _rsaKeyPair = AsymmetricKeypair::generateRSA();
    mococrw::AsymmetricKeypair _rsaKeyPair2 = AsymmetricKeypair::generateRSA();
    mococrw::AsymmetricKeypair _eccKeyPairDefault = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _eccKeyPairDefault2 = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _eccKeyPairSect571r1 = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _eccKeyPairSecp521r1 = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _ED448KeyPair = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _ED448KeyPair_2 = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _ED25519KeyPair = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _ED25519KeyPair_2 = AsymmetricKeypair::generateECC();

};

void KeyHandlingTests::SetUp() {
    _rsaKeyPair = AsymmetricKeypair::generateRSA();
    _rsaKeyPair2 = AsymmetricKeypair::generateRSA();

    _eccKeyPairDefault = AsymmetricKeypair::generateECC();
    _eccKeyPairDefault2 = AsymmetricKeypair::generateECC();

    _eccKeyPairSect571r1 = AsymmetricKeypair::generate(mococrw::ECCSpec{openssl::ellipticCurveNid::SECT_571r1});
    _eccKeyPairSecp521r1 = AsymmetricKeypair::generate(mococrw::ECCSpec{openssl::ellipticCurveNid::SECP_521r1});

    _ED448KeyPair = AsymmetricKeypair::generate(mococrw::ECCSpec{openssl::ellipticCurveNid::ED448});
    _ED448KeyPair_2 = AsymmetricKeypair::generate(mococrw::ECCSpec{openssl::ellipticCurveNid::ED448});

    _ED25519KeyPair = AsymmetricKeypair::generate(mococrw::ECCSpec{openssl::ellipticCurveNid::ED25519});
    _ED25519KeyPair_2 = AsymmetricKeypair::generate(mococrw::ECCSpec{openssl::ellipticCurveNid::ED25519});
}

std::string KeyHandlingTests::_pemEccPrivKeySect409k1{R"(-----BEGIN PRIVATE KEY-----
MIHCAgEAMBAGByqGSM49AgEGBSuBBAAkBIGqMIGnAgEBBDQAF2zFhKyxJiI7bGvG
Mw9rq7DUvrqTDJMHeRttpsZc0i9tFbvmaT2J5U39/RkseDha2b87oWwDagAEAAdj
oVwkpy9CPA8RU3sd0aXV/XnHw5nE7HgINd6ApxCaknRebk4Vgbgz04588YqjqQpQ
TAA+hxkUt1ZInurAHTt/ECQpvt1YOTBgNigakbLzq1LsbbyLWJsH5diall6Is+lg
y2Mu1EA=
-----END PRIVATE KEY-----)"};

std::string KeyHandlingTests::_pemEccPubKeySect409k1{R"(-----BEGIN PUBLIC KEY-----
MH4wEAYHKoZIzj0CAQYFK4EEACQDagAEAAdjoVwkpy9CPA8RU3sd0aXV/XnHw5nE
7HgINd6ApxCaknRebk4Vgbgz04588YqjqQpQTAA+hxkUt1ZInurAHTt/ECQpvt1Y
OTBgNigakbLzq1LsbbyLWJsH5diall6Is+lgy2Mu1EA=
-----END PUBLIC KEY-----)"};

std::string KeyHandlingTests::_pemEccPrivKeyED25519{R"(-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHP1o8LJ4jNkuTyDT6uNtqLankRkQeAyAIflqvnjutC2
-----END PRIVATE KEY-----)"};

std::string KeyHandlingTests::_pemEccPubKeyED25519{R"(-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAlY+GiXLleFpEvVAOS/GJJTTpCA+fjRrCzjBpeLI73TY=
-----END PUBLIC KEY-----)"};


TEST_F(KeyHandlingTests, testGeneratedKeyIsNotNull)
{
    ASSERT_THAT(_rsaKeyPair.internal(), NotNull());
    ASSERT_THAT(_rsaKeyPair2.internal(), NotNull());

    ASSERT_THAT(_eccKeyPairDefault.internal(), NotNull());
    ASSERT_THAT(_eccKeyPairDefault2.internal(), NotNull());

    ASSERT_THAT(_eccKeyPairSecp521r1.internal(), NotNull());
    ASSERT_THAT(_eccKeyPairSect571r1.internal(), NotNull());

    ASSERT_THAT(_ED448KeyPair.internal(), NotNull());
    ASSERT_THAT(_ED25519KeyPair.internal(), NotNull());
}

TEST_F(KeyHandlingTests, testPublicKeyPemIsReproducible)
{
    const auto pemOfKey = _rsaKeyPair.publicKeyToPem();
    const auto pemOfKey2 = _rsaKeyPair.publicKeyToPem();

    const auto pemOfEccKey = _eccKeyPairDefault.publicKeyToPem();
    const auto pemOfEccKey2 = _eccKeyPairDefault.publicKeyToPem();

    const auto pemOfSectEccKey = _eccKeyPairSect571r1.publicKeyToPem();
    const auto pemOfSectEccKey2 = _eccKeyPairSect571r1.publicKeyToPem();

    const auto pemOfED448Key = _ED448KeyPair.publicKeyToPem();
    const auto pemOfED448Key2 = _ED448KeyPair.publicKeyToPem();

    const auto pemOfED25519Key = _ED25519KeyPair.publicKeyToPem();
    const auto pemOfED25519Key2 = _ED25519KeyPair.publicKeyToPem();

    ASSERT_EQ(pemOfKey, pemOfKey2);
    ASSERT_EQ(pemOfEccKey, pemOfEccKey2);
    ASSERT_EQ(pemOfSectEccKey, pemOfSectEccKey2);
    ASSERT_EQ(pemOfED448Key, pemOfED448Key2);
    ASSERT_EQ(pemOfED25519Key, pemOfED25519Key2);
}

TEST_F(KeyHandlingTests, testPubKeyFromSavedPemIsSameAsOriginalInOpenSSLObject)
{
    const auto pemOfPubkey = _rsaKeyPair.publicKeyToPem();
    const auto pemOfEccPubkey = _eccKeyPairDefault.publicKeyToPem();
    const auto pemOfSecpEccPubkey = _eccKeyPairSecp521r1.publicKeyToPem();
    const auto pemOfED448Key = _ED448KeyPair.publicKeyToPem();
    const auto pemOfED25519Key = _ED25519KeyPair.publicKeyToPem();

    auto rsaParsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfPubkey);
    auto eccParsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfEccPubkey);
    auto eccSecpParsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfSecpEccPubkey);
    auto ED448ParsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfED448Key);
    auto ED25519ParsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfED25519Key);

    ASSERT_EQ(_rsaKeyPair, rsaParsedKey);
    ASSERT_EQ(_eccKeyPairDefault, eccParsedKey);
    ASSERT_EQ(_eccKeyPairSecp521r1, eccSecpParsedKey);
    ASSERT_EQ(_ED448KeyPair, ED448ParsedKey);
    ASSERT_EQ(_ED25519KeyPair, ED25519ParsedKey);
    ASSERT_NE(_eccKeyPairSecp521r1, _rsaKeyPair);

}

TEST_F(KeyHandlingTests, testReadExternalEccPEMKey)
{
    /*Read private and public key from pem string*/
    auto eccPrivKey = mococrw::AsymmetricKeypair::readPrivateKeyFromPEM(
                                                  KeyHandlingTests::_pemEccPrivKeySect409k1, "");
    auto eccPubKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(
                                                   KeyHandlingTests::_pemEccPubKeySect409k1);

    /*Check key type and curve*/
    EXPECT_EQ(eccPrivKey.getType(), AsymmetricKey::KeyTypes::ECC);
    EXPECT_EQ(eccPubKey.getType(), AsymmetricKey::KeyTypes::ECC);

    auto privSpec = eccPrivKey.getKeySpec();
    auto pubSpec = eccPubKey.getKeySpec();
    EXPECT_EQ(dynamic_cast<ECCSpec*>(privSpec.get())->curve(), openssl::ellipticCurveNid::SECT_409k1);
    EXPECT_EQ(dynamic_cast<ECCSpec*>(pubSpec.get())->curve(), openssl::ellipticCurveNid::SECT_409k1);

    /*Write key to a new pem file and read back to compare with original*/
    /*Public key*/
    const auto pemOfPubkey = eccPubKey.publicKeyToPem();
    auto parsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfPubkey);
    ASSERT_EQ(eccPubKey, parsedKey);
    /*Private key*/
    const auto pemOfPrivateKey = eccPrivKey.privateKeyToPem("secret");
    auto retrievedKeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfPrivateKey, "secret");
    ASSERT_EQ(eccPrivKey, retrievedKeyPair);
}

TEST_F(KeyHandlingTests, testReadExternalED25519PEMKey)
{
    /*Read private and public key from pem string*/
    auto eccPrivKey = mococrw::AsymmetricKeypair::readPrivateKeyFromPEM(
                                                  KeyHandlingTests::_pemEccPrivKeyED25519, "");
    auto eccPubKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(
                                                   KeyHandlingTests::_pemEccPubKeyED25519);

    /*Check key type and curve*/
    EXPECT_EQ(eccPrivKey.getType(), AsymmetricKey::KeyTypes::ECC_ED);
    EXPECT_EQ(eccPubKey.getType(), AsymmetricKey::KeyTypes::ECC_ED);

    auto privSpec = eccPrivKey.getKeySpec();
    auto pubSpec = eccPubKey.getKeySpec();
    EXPECT_EQ(dynamic_cast<ECCSpec*>(privSpec.get())->curve(), openssl::ellipticCurveNid::ED25519);
    EXPECT_EQ(dynamic_cast<ECCSpec*>(pubSpec.get())->curve(), openssl::ellipticCurveNid::ED25519);

    /*Write key to a new pem file and read back to compare with original*/
    /*Public key*/
    const auto pemOfPubkey = eccPubKey.publicKeyToPem();
    auto parsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfPubkey);
    ASSERT_EQ(eccPubKey, parsedKey);
    /*Private key*/
    const auto pemOfPrivateKey = eccPrivKey.privateKeyToPem("secret");
    auto retrievedKeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfPrivateKey, "secret");
    ASSERT_EQ(eccPrivKey, retrievedKeyPair);
}

TEST_F(KeyHandlingTests, testPubkeyFromSavedPemIsSameAsOriginalInPEM)
{
    const auto pemOfKey = _rsaKeyPair.publicKeyToPem();
    const auto pemOfEccKey = _eccKeyPairDefault.publicKeyToPem();
    const auto pemOfSectEccKey = _eccKeyPairSect571r1.publicKeyToPem();
    const auto pemOfED448Key = _ED448KeyPair.publicKeyToPem();
    const auto pemOfED25519Key = _ED25519KeyPair.publicKeyToPem();

    auto parsedRsaKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfKey);
    auto parsedEccKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfEccKey);
    auto parsedSectEccKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfSectEccKey);
    auto parsedED448Key = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfED448Key);
    auto parsedED25519Key = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfED25519Key);

    ASSERT_EQ(pemOfKey, parsedRsaKey.publicKeyToPem());
    ASSERT_EQ(pemOfEccKey, parsedEccKey.publicKeyToPem());
    ASSERT_EQ(pemOfSectEccKey, parsedSectEccKey.publicKeyToPem());
    ASSERT_EQ(pemOfED448Key, parsedED448Key.publicKeyToPem());
    ASSERT_EQ(pemOfED25519Key, parsedED25519Key.publicKeyToPem());
}

TEST_F(KeyHandlingTests, testPrivKeyFromSavedPemIsSameAsOriginal)
{
    const auto pemOfPubKey = _rsaKeyPair.publicKeyToPem();
    const auto pemOfPrivateKey = _rsaKeyPair.privateKeyToPem("secret");

    auto retrievedKeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfPrivateKey, "secret");
    ASSERT_EQ(pemOfPubKey, retrievedKeyPair.publicKeyToPem());

    const auto pemOfEccPubKey = _eccKeyPairDefault.publicKeyToPem();
    const auto pemOfEccPrivateKey = _eccKeyPairDefault.privateKeyToPem("password");

    auto retrievedEccKeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfEccPrivateKey, "password");
    ASSERT_EQ(pemOfEccPubKey, retrievedEccKeyPair.publicKeyToPem());

    const auto pemOfSectEccPubKey = _eccKeyPairSect571r1.publicKeyToPem();
    const auto pemOfSectEccPrivateKey = _eccKeyPairSect571r1.privateKeyToPem("santa");

    auto retrievedSectEccKeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfSectEccPrivateKey, "santa");
    ASSERT_EQ(pemOfSectEccPubKey, retrievedSectEccKeyPair.publicKeyToPem());

    const auto pemOfSectED448PubKey = _ED448KeyPair.publicKeyToPem();
    const auto pemOfSectED448PrivateKey = _ED448KeyPair.privateKeyToPem("f00");

    auto retrievedED448KeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfSectED448PrivateKey, "f00");
    ASSERT_EQ(pemOfSectED448PubKey, retrievedED448KeyPair.publicKeyToPem());

    const auto pemOfSectED25519PubKey = _ED25519KeyPair.publicKeyToPem();
    const auto pemOfSectED25519PrivateKey = _ED25519KeyPair.privateKeyToPem("bar");

    auto retrievedED25519KeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfSectED25519PrivateKey, "bar");
    ASSERT_EQ(pemOfSectED25519PubKey, retrievedED25519KeyPair.publicKeyToPem());
}

TEST_F(KeyHandlingTests, testBothGeneratedKeysNotTheSame)
{
    ASSERT_NE(_rsaKeyPair, _rsaKeyPair2);

    ASSERT_NE(_eccKeyPairDefault, _eccKeyPairDefault2);

    ASSERT_NE(_ED448KeyPair, _ED448KeyPair_2);

    ASSERT_NE(_ED25519KeyPair, _ED25519KeyPair_2);
}

TEST_F(KeyHandlingTests, testThrowsWhenReadingPrivateKeyUsingWrongKey)
{
    const auto pemOfPrivateKey = _rsaKeyPair.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfPrivateKey, "wrongkey"),
                 mococrw::OpenSSLException);

    const auto pemOfEccPrivateKey = _eccKeyPairDefault.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfEccPrivateKey, "wrongkey"),
                 mococrw::OpenSSLException);

    const auto pemOfSecpEccPrivateKey = _eccKeyPairSecp521r1.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfSecpEccPrivateKey, "santa"),
                 mococrw::OpenSSLException);

    const auto pemOfED448PrivateKey = _ED448KeyPair.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfED448PrivateKey, "santa"),
                 mococrw::OpenSSLException);

    const auto pemOfED25519PrivateKey = _ED25519KeyPair.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfED25519PrivateKey, "santa"),
                 mococrw::OpenSSLException);
}

TEST_F(KeyHandlingTests, testKeyTypeChecking)
{
    EXPECT_EQ(_eccKeyPairDefault.getType(), AsymmetricKey::KeyTypes::ECC);
    EXPECT_EQ(_rsaKeyPair.getType(), AsymmetricKey::KeyTypes::RSA);
    EXPECT_EQ(_eccKeyPairSecp521r1.getType(), AsymmetricKey::KeyTypes::ECC);
    EXPECT_EQ(_eccKeyPairSect571r1.getType(), AsymmetricKey::KeyTypes::ECC);
    EXPECT_EQ(_ED448KeyPair.getType(), AsymmetricKey::KeyTypes::ECC_ED);
    EXPECT_EQ(_ED25519KeyPair.getType(), AsymmetricKey::KeyTypes::ECC_ED);
}

TEST_F(KeyHandlingTests, testGetKeySpec)
{
    auto defaultSpec =_eccKeyPairDefault.getKeySpec();
    auto Sect571r1Spec = _eccKeyPairSect571r1.getKeySpec();
    auto Secp521Spec = _eccKeyPairSecp521r1.getKeySpec();
    auto ED448Spec = _ED448KeyPair.getKeySpec();
    auto ED25519Spec = _ED25519KeyPair.getKeySpec();

    EXPECT_EQ(dynamic_cast<ECCSpec*>(defaultSpec.get())->curve(), openssl::ellipticCurveNid::PRIME_256v1);
    EXPECT_EQ(dynamic_cast<ECCSpec*>(Sect571r1Spec.get())->curve(), openssl::ellipticCurveNid::SECT_571r1);
    EXPECT_EQ(dynamic_cast<ECCSpec*>(Secp521Spec.get())->curve(), openssl::ellipticCurveNid::SECP_521r1);
    EXPECT_EQ(dynamic_cast<ECCSpec*>(ED448Spec.get())->curve(), openssl::ellipticCurveNid::ED448);
    EXPECT_EQ(dynamic_cast<ECCSpec*>(ED25519Spec.get())->curve(), openssl::ellipticCurveNid::ED25519);

    std::unique_ptr<RSASpec> defaultRSASpec (dynamic_cast<RSASpec*>(_rsaKeyPair.getKeySpec().release()));
    EXPECT_EQ(defaultRSASpec->numberOfBits(), 2048);
}

TEST_F(KeyHandlingTests, testGetSize)
{
    EXPECT_EQ(_rsaKeyPair.getKeySize(), 2048);
    EXPECT_EQ(_eccKeyPairDefault.getKeySize(), 256);
    EXPECT_EQ(_eccKeyPairSecp521r1.getKeySize(), 521);
    EXPECT_EQ(_eccKeyPairSect571r1.getKeySize(), 570);
    EXPECT_EQ(_ED448KeyPair.getKeySize(), 456);
    EXPECT_EQ(_ED25519KeyPair.getKeySize(), 253);
    auto rsaKey1024 = AsymmetricKeypair::generate(mococrw::RSASpec{1024});
    EXPECT_EQ(rsaKey1024.getKeySize(), 1024);
}

/* Test the KeySpec and the generation of keys that way */
TEST(KeySpecTest, testGeneratingRSAKeyWithDefaultParameters)
{
    RSASpec spec{};

    auto keypair = spec.generate();
    ASSERT_THAT(keypair.internal(), NotNull());
}

/* Test the KeySpec and the generation of keys that way */
TEST(KeySpecTest, testGeneratingEccKeyWithDefaultParameters)
{
    ECCSpec spec{};

    auto keypair = spec.generate();
    ASSERT_THAT(keypair.internal(), NotNull());
}

TEST(KeySpecTest, testThatDefaultParametersAreSane)
{
    RSASpec spec{};
    ASSERT_THAT(spec.numberOfBits(), Eq(2048));

    RSASpec nonDefault{1024};
    ASSERT_THAT(nonDefault.numberOfBits(), Eq(1024));

    ECCSpec defaultEccSpec{};
    ASSERT_EQ(defaultEccSpec.curve(), openssl::ellipticCurveNid::PRIME_256v1);

    ECCSpec nonDefaultEccSpec{openssl::ellipticCurveNid::SECT_283k1};
    ASSERT_EQ(nonDefaultEccSpec.curve(), openssl::ellipticCurveNid::SECT_283k1);
}

