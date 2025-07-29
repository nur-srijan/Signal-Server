package org.whispersystems.textsecuregcm.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for post-quantum cryptography utilities.
 * This demonstrates how to use CRYSTALS-Kyber and CRYSTALS-Dilithium
 * for secure key exchange and digital signatures.
 */
public class PQCryptoUtilTest {

    private static final Logger logger = LoggerFactory.getLogger(PQCryptoUtilTest.class);

    @BeforeEach
    void setUp() {
        logger.info("Setting up PQC test environment");
    }

    @Test
    @DisplayName("Test Kyber key generation and encapsulation/decapsulation")
    void testKyberKeyExchange() {
        logger.info("Testing Kyber key exchange mechanism");

        // Alice generates a key pair
        PQCryptoUtil.KyberKeyPair aliceKeyPair = PQCryptoUtil.generateKyberKeyPair();
        assertNotNull(aliceKeyPair);
        assertNotNull(aliceKeyPair.getPublicKey());
        assertNotNull(aliceKeyPair.getPrivateKey());

        // Bob encapsulates a secret using Alice's public key
        PQCryptoUtil.KyberEncapsulation encapsulation = PQCryptoUtil.encapsulate(aliceKeyPair.getPublicKey());
        assertNotNull(encapsulation);
        assertNotNull(encapsulation.getSharedSecret());
        assertNotNull(encapsulation.getCiphertext());

        // Alice decapsulates the secret using her private key
        byte[] decapsulatedSecret = PQCryptoUtil.decapsulate(aliceKeyPair.getPrivateKey(), encapsulation.getCiphertext());
        assertNotNull(decapsulatedSecret);

        // The shared secrets should be the same
        assertArrayEquals(encapsulation.getSharedSecret(), decapsulatedSecret);

        logger.info("Kyber key exchange test passed - shared secret length: {} bytes", decapsulatedSecret.length);

        // Clean up sensitive data
        PQCryptoUtil.clearSensitiveData(encapsulation.getSharedSecret());
        PQCryptoUtil.clearSensitiveData(decapsulatedSecret);
    }

    @Test
    @DisplayName("Test Dilithium signature generation and verification")
    void testDilithiumSignature() {
        logger.info("Testing Dilithium digital signature");

        // Generate a key pair for signing
        PQCryptoUtil.DilithiumKeyPair keyPair = PQCryptoUtil.generateDilithiumKeyPair();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublicKey());
        assertNotNull(keyPair.getPrivateKey());

        // Message to sign
        String message = "Hello, post-quantum world!";
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        // Sign the message
        byte[] signature = PQCryptoUtil.sign(keyPair.getPrivateKey(), messageBytes);
        assertNotNull(signature);
        assertTrue(signature.length > 0);

        // Verify the signature
        boolean isValid = PQCryptoUtil.verify(keyPair.getPublicKey(), messageBytes, signature);
        assertTrue(isValid);

        // Test with invalid signature
        signature[0] = (byte) (signature[0] ^ 1); // Flip a bit
        boolean isInvalid = PQCryptoUtil.verify(keyPair.getPublicKey(), messageBytes, signature);
        assertFalse(isInvalid);

        logger.info("Dilithium signature test passed - signature length: {} bytes", signature.length);
    }

    @Test
    @DisplayName("Test key serialization and reconstruction")
    void testKeySerialization() {
        logger.info("Testing key serialization and reconstruction");

        // Test Kyber key serialization
        PQCryptoUtil.KyberKeyPair originalKyberKeyPair = PQCryptoUtil.generateKyberKeyPair();
        
        byte[] publicKeyBytes = originalKyberKeyPair.getPublicKeyBytes();
        byte[] privateKeyBytes = originalKyberKeyPair.getPrivateKeyBytes();
        
        assertNotNull(publicKeyBytes);
        assertNotNull(privateKeyBytes);
        assertTrue(publicKeyBytes.length > 0);
        assertTrue(privateKeyBytes.length > 0);

        // Reconstruct keys from bytes
        var reconstructedPublicKey = PQCryptoUtil.reconstructKyberPublicKey(publicKeyBytes);
        var reconstructedPrivateKey = PQCryptoUtil.reconstructKyberPrivateKey(privateKeyBytes);
        
        assertNotNull(reconstructedPublicKey);
        assertNotNull(reconstructedPrivateKey);

        // Test with reconstructed keys
        PQCryptoUtil.KyberEncapsulation encapsulation = PQCryptoUtil.encapsulate(reconstructedPublicKey);
        byte[] decapsulatedSecret = PQCryptoUtil.decapsulate(reconstructedPrivateKey, encapsulation.getCiphertext());
        
        assertArrayEquals(encapsulation.getSharedSecret(), decapsulatedSecret);

        // Test Dilithium key serialization
        PQCryptoUtil.DilithiumKeyPair originalDilithiumKeyPair = PQCryptoUtil.generateDilithiumKeyPair();
        
        byte[] dilithiumPublicKeyBytes = originalDilithiumKeyPair.getPublicKeyBytes();
        byte[] dilithiumPrivateKeyBytes = originalDilithiumKeyPair.getPrivateKeyBytes();
        
        assertNotNull(dilithiumPublicKeyBytes);
        assertNotNull(dilithiumPrivateKeyBytes);

        // Reconstruct Dilithium keys
        var reconstructedDilithiumPublicKey = PQCryptoUtil.reconstructDilithiumPublicKey(dilithiumPublicKeyBytes);
        var reconstructedDilithiumPrivateKey = PQCryptoUtil.reconstructDilithiumPrivateKey(dilithiumPrivateKeyBytes);
        
        assertNotNull(reconstructedDilithiumPublicKey);
        assertNotNull(reconstructedDilithiumPrivateKey);

        // Test signatures with reconstructed keys
        byte[] testMessage = "Test message".getBytes(StandardCharsets.UTF_8);
        byte[] signature = PQCryptoUtil.sign(reconstructedDilithiumPrivateKey, testMessage);
        boolean isValid = PQCryptoUtil.verify(reconstructedDilithiumPublicKey, testMessage, signature);
        assertTrue(isValid);

        logger.info("Key serialization test passed - Kyber public key: {} bytes, Dilithium public key: {} bytes", 
                   publicKeyBytes.length, dilithiumPublicKeyBytes.length);

        // Clean up
        PQCryptoUtil.clearSensitiveData(encapsulation.getSharedSecret());
        PQCryptoUtil.clearSensitiveData(decapsulatedSecret);
        PQCryptoUtil.clearSensitiveData(privateKeyBytes);
        PQCryptoUtil.clearSensitiveData(dilithiumPrivateKeyBytes);
    }

    @Test
    @DisplayName("Test key derivation function")
    void testKeyDerivation() {
        logger.info("Testing key derivation function");

        // Generate a shared secret
        PQCryptoUtil.KyberKeyPair keyPair = PQCryptoUtil.generateKyberKeyPair();
        PQCryptoUtil.KyberEncapsulation encapsulation = PQCryptoUtil.encapsulate(keyPair.getPublicKey());
        
        byte[] sharedSecret = encapsulation.getSharedSecret();
        byte[] info = "Signal-PQC-Test".getBytes(StandardCharsets.UTF_8);
        
        // Derive keys of different lengths
        byte[] key16 = PQCryptoUtil.deriveKey(sharedSecret, info, 16);
        byte[] key32 = PQCryptoUtil.deriveKey(sharedSecret, info, 32);
        
        assertNotNull(key16);
        assertNotNull(key32);
        assertEquals(16, key16.length);
        assertEquals(32, key32.length);
        
        // Same inputs should produce same outputs
        byte[] key16_2 = PQCryptoUtil.deriveKey(sharedSecret, info, 16);
        assertArrayEquals(key16, key16_2);
        
        // Different info should produce different keys
        byte[] differentInfo = "Different-Info".getBytes(StandardCharsets.UTF_8);
        byte[] differentKey = PQCryptoUtil.deriveKey(sharedSecret, differentInfo, 16);
        assertFalse(java.util.Arrays.equals(key16, differentKey));

        logger.info("Key derivation test passed - derived keys of lengths: {}, {}", key16.length, key32.length);

        // Clean up
        PQCryptoUtil.clearSensitiveData(sharedSecret);
        PQCryptoUtil.clearSensitiveData(key16);
        PQCryptoUtil.clearSensitiveData(key32);
        PQCryptoUtil.clearSensitiveData(key16_2);
        PQCryptoUtil.clearSensitiveData(differentKey);
    }

    @Test
    @DisplayName("Test complete PQC workflow")
    void testCompleteWorkflow() {
        logger.info("Testing complete post-quantum cryptography workflow");

        // Simulate Alice and Bob setting up secure communication
        
        // 1. Alice generates her identity keys (both KEM and signature)
        PQCryptoUtil.KyberKeyPair aliceKemKeyPair = PQCryptoUtil.generateKyberKeyPair();
        PQCryptoUtil.DilithiumKeyPair aliceSignKeyPair = PQCryptoUtil.generateDilithiumKeyPair();
        
        // 2. Bob generates his identity keys
        PQCryptoUtil.KyberKeyPair bobKemKeyPair = PQCryptoUtil.generateKyberKeyPair();
        PQCryptoUtil.DilithiumKeyPair bobSignKeyPair = PQCryptoUtil.generateDilithiumKeyPair();
        
        // 3. Alice sends her public keys to Bob (signed)
        byte[] alicePublicKeyBundle = concatenate(
            aliceKemKeyPair.getPublicKeyBytes(),
            aliceSignKeyPair.getPublicKeyBytes()
        );
        byte[] aliceKeyBundleSignature = PQCryptoUtil.sign(aliceSignKeyPair.getPrivateKey(), alicePublicKeyBundle);
        
        // 4. Bob verifies Alice's key bundle signature
        boolean isAliceKeyBundleValid = PQCryptoUtil.verify(aliceSignKeyPair.getPublicKey(), alicePublicKeyBundle, aliceKeyBundleSignature);
        assertTrue(isAliceKeyBundleValid);
        
        // 5. Bob encapsulates a secret for Alice
        PQCryptoUtil.KyberEncapsulation encapsulation = PQCryptoUtil.encapsulate(aliceKemKeyPair.getPublicKey());
        
        // 6. Bob signs the encapsulation
        byte[] encapsulationSignature = PQCryptoUtil.sign(bobSignKeyPair.getPrivateKey(), encapsulation.getCiphertext());
        
        // 7. Alice verifies Bob's signature and decapsulates the secret
        boolean isEncapsulationValid = PQCryptoUtil.verify(bobSignKeyPair.getPublicKey(), encapsulation.getCiphertext(), encapsulationSignature);
        assertTrue(isEncapsulationValid);
        
        byte[] aliceSharedSecret = PQCryptoUtil.decapsulate(aliceKemKeyPair.getPrivateKey(), encapsulation.getCiphertext());
        
        // 8. Both parties should have the same shared secret
        assertArrayEquals(encapsulation.getSharedSecret(), aliceSharedSecret);
        
        // 9. Derive symmetric keys for encryption
        byte[] encryptionKey = PQCryptoUtil.deriveKey(aliceSharedSecret, "encryption".getBytes(), 32);
        byte[] macKey = PQCryptoUtil.deriveKey(aliceSharedSecret, "mac".getBytes(), 32);
        
        assertNotNull(encryptionKey);
        assertNotNull(macKey);
        assertFalse(java.util.Arrays.equals(encryptionKey, macKey));

        logger.info("Complete PQC workflow test passed - established secure communication with shared secret");

        // Clean up all sensitive data
        PQCryptoUtil.clearSensitiveData(encapsulation.getSharedSecret());
        PQCryptoUtil.clearSensitiveData(aliceSharedSecret);
        PQCryptoUtil.clearSensitiveData(encryptionKey);
        PQCryptoUtil.clearSensitiveData(macKey);
    }

    // Helper method to concatenate byte arrays
    private byte[] concatenate(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
