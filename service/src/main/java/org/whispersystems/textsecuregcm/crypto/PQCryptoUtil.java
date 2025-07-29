package org.whispersystems.textsecuregcm.crypto;

import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.bouncycastle.pqc.crypto.crystals.kyber.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecureRandom;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/**
 * Post-Quantum Cryptography utility class for Signal server.
 * This class provides wrapper methods for CRYSTALS-Kyber (KEM) and CRYSTALS-Dilithium (signatures)
 * to replace traditional ECDH and ECDSA operations.
 */
public class PQCryptoUtil {

    private static final Logger logger = LoggerFactory.getLogger(PQCryptoUtil.class);

    static {
        // Add BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());
        logger.info("BouncyCastle provider added for post-quantum cryptography");
    }

    /**
     * Generate a Kyber key pair for key encapsulation mechanism (KEM).
     * This replaces ECDH key exchange.
     */
    public static class KyberKeyPair {
        private final KyberPrivateKeyParameters privateKey;
        private final KyberPublicKeyParameters publicKey;

        public KyberKeyPair(KyberPrivateKeyParameters privateKey, KyberPublicKeyParameters publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public KyberPrivateKeyParameters getPrivateKey() {
            return privateKey;
        }

        public KyberPublicKeyParameters getPublicKey() {
            return publicKey;
        }

        public byte[] getPublicKeyBytes() {
            return publicKey.getEncoded();
        }

        public byte[] getPrivateKeyBytes() {
            return privateKey.getEncoded();
        }
    }

    /**
     * Generate a Dilithium key pair for digital signatures.
     * This replaces ECDSA signatures.
     */
    public static class DilithiumKeyPair {
        private final DilithiumPrivateKeyParameters privateKey;
        private final DilithiumPublicKeyParameters publicKey;

        public DilithiumKeyPair(DilithiumPrivateKeyParameters privateKey, DilithiumPublicKeyParameters publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public DilithiumPrivateKeyParameters getPrivateKey() {
            return privateKey;
        }

        public DilithiumPublicKeyParameters getPublicKey() {
            return publicKey;
        }

        public byte[] getPublicKeyBytes() {
            return publicKey.getEncoded();
        }

        public byte[] getPrivateKeyBytes() {
            return privateKey.getEncoded();
        }
    }

    /**
     * Generate a Kyber-768 key pair for key encapsulation.
     * Kyber-768 provides 128-bit security level.
     */
    public static KyberKeyPair generateKyberKeyPair() {
        try {
            KyberKeyPairGenerator keyGen = new KyberKeyPairGenerator();
            keyGen.init(new KyberKeyGenerationParameters(new SecureRandom(), KyberParameters.kyber768));
            
            AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();
            
            KyberPrivateKeyParameters privateKey = (KyberPrivateKeyParameters) keyPair.getPrivate();
            KyberPublicKeyParameters publicKey = (KyberPublicKeyParameters) keyPair.getPublic();
            
            logger.debug("Generated Kyber-768 key pair");
            return new KyberKeyPair(privateKey, publicKey);
        } catch (Exception e) {
            logger.error("Failed to generate Kyber key pair", e);
            throw new RuntimeException("Failed to generate Kyber key pair", e);
        }
    }

    /**
     * Generate a Dilithium-3 key pair for digital signatures.
     * Dilithium-3 provides 128-bit security level.
     */
    public static DilithiumKeyPair generateDilithiumKeyPair() {
        try {
            DilithiumKeyPairGenerator keyGen = new DilithiumKeyPairGenerator();
            keyGen.init(new DilithiumKeyGenerationParameters(new SecureRandom(), DilithiumParameters.dilithium3));
            
            AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();
            
            DilithiumPrivateKeyParameters privateKey = (DilithiumPrivateKeyParameters) keyPair.getPrivate();
            DilithiumPublicKeyParameters publicKey = (DilithiumPublicKeyParameters) keyPair.getPublic();
            
            logger.debug("Generated Dilithium-3 key pair");
            return new DilithiumKeyPair(privateKey, publicKey);
        } catch (Exception e) {
            logger.error("Failed to generate Dilithium key pair", e);
            throw new RuntimeException("Failed to generate Dilithium key pair", e);
        }
    }

    /**
     * Perform key encapsulation using Kyber.
     * This generates a shared secret and encapsulates it for the recipient.
     */
    public static class KyberEncapsulation {
        private final byte[] sharedSecret;
        private final byte[] ciphertext;

        public KyberEncapsulation(byte[] sharedSecret, byte[] ciphertext) {
            this.sharedSecret = sharedSecret;
            this.ciphertext = ciphertext;
        }

        public byte[] getSharedSecret() {
            return sharedSecret;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }
    }

    /**
     * Encapsulate a shared secret using Kyber public key.
     */
    public static KyberEncapsulation encapsulate(KyberPublicKeyParameters publicKey) {
        try {
            KyberKEMGenerator kemGen = new KyberKEMGenerator(new SecureRandom());
            SecretWithEncapsulation secretWithEncapsulation = kemGen.generateEncapsulated(publicKey);
            
            byte[] sharedSecret = secretWithEncapsulation.getSecret();
            byte[] ciphertext = secretWithEncapsulation.getEncapsulation();
            
            logger.debug("Performed Kyber key encapsulation");
            return new KyberEncapsulation(sharedSecret, ciphertext);
        } catch (Exception e) {
            logger.error("Failed to perform Kyber encapsulation", e);
            throw new RuntimeException("Failed to perform Kyber encapsulation", e);
        }
    }

    /**
     * Decapsulate a shared secret using Kyber private key.
     */
    public static byte[] decapsulate(KyberPrivateKeyParameters privateKey, byte[] ciphertext) {
        try {
            KyberKEMExtractor kemExtractor = new KyberKEMExtractor(privateKey);
            byte[] sharedSecret = kemExtractor.extractSecret(ciphertext);
            
            logger.debug("Performed Kyber key decapsulation");
            return sharedSecret;
        } catch (Exception e) {
            logger.error("Failed to perform Kyber decapsulation", e);
            throw new RuntimeException("Failed to perform Kyber decapsulation", e);
        }
    }

    /**
     * Sign a message using Dilithium private key.
     */
    public static byte[] sign(DilithiumPrivateKeyParameters privateKey, byte[] message) {
        try {
            DilithiumSigner signer = new DilithiumSigner();
            signer.init(true, privateKey);
            
            byte[] signature = signer.generateSignature(message);
            
            logger.debug("Generated Dilithium signature for message of length {}", message.length);
            return signature;
        } catch (Exception e) {
            logger.error("Failed to generate Dilithium signature", e);
            throw new RuntimeException("Failed to generate Dilithium signature", e);
        }
    }

    /**
     * Verify a signature using Dilithium public key.
     */
    public static boolean verify(DilithiumPublicKeyParameters publicKey, byte[] message, byte[] signature) {
        try {
            DilithiumSigner signer = new DilithiumSigner();
            signer.init(false, publicKey);
            
            boolean isValid = signer.verifySignature(message, signature);
            
            logger.debug("Verified Dilithium signature for message of length {}: {}", message.length, isValid);
            return isValid;
        } catch (Exception e) {
            logger.error("Failed to verify Dilithium signature", e);
            return false;
        }
    }

    /**
     * Reconstruct Kyber public key from bytes.
     */
    public static KyberPublicKeyParameters reconstructKyberPublicKey(byte[] keyBytes) {
        try {
            return new KyberPublicKeyParameters(KyberParameters.kyber768, keyBytes);
        } catch (Exception e) {
            logger.error("Failed to reconstruct Kyber public key", e);
            throw new RuntimeException("Failed to reconstruct Kyber public key", e);
        }
    }

    /**
     * Reconstruct Kyber private key from bytes.
     */
    public static KyberPrivateKeyParameters reconstructKyberPrivateKey(byte[] keyBytes) {
        try {
            return new KyberPrivateKeyParameters(KyberParameters.kyber768, keyBytes);
        } catch (Exception e) {
            logger.error("Failed to reconstruct Kyber private key", e);
            throw new RuntimeException("Failed to reconstruct Kyber private key", e);
        }
    }

    /**
     * Reconstruct Dilithium public key from bytes.
     */
    public static DilithiumPublicKeyParameters reconstructDilithiumPublicKey(byte[] keyBytes) {
        try {
            return new DilithiumPublicKeyParameters(DilithiumParameters.dilithium3, keyBytes);
        } catch (Exception e) {
            logger.error("Failed to reconstruct Dilithium public key", e);
            throw new RuntimeException("Failed to reconstruct Dilithium public key", e);
        }
    }

    /**
     * Reconstruct Dilithium private key from bytes.
     */
    public static DilithiumPrivateKeyParameters reconstructDilithiumPrivateKey(byte[] keyBytes) {
        try {
            return new DilithiumPrivateKeyParameters(DilithiumParameters.dilithium3, keyBytes);
        } catch (Exception e) {
            logger.error("Failed to reconstruct Dilithium private key", e);
            throw new RuntimeException("Failed to reconstruct Dilithium private key", e);
        }
    }

    /**
     * Secure key derivation function using provided shared secret.
     * This can be used to derive encryption keys from the Kyber shared secret.
     */
    public static byte[] deriveKey(byte[] sharedSecret, byte[] info, int keyLength) {
        try {
            // Use HKDF or similar key derivation function
            // This is a simplified example - you should use a proper KDF
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            digest.update(sharedSecret);
            digest.update(info);
            byte[] fullHash = digest.digest();
            
            // Return the first keyLength bytes
            return Arrays.copyOf(fullHash, Math.min(keyLength, fullHash.length));
        } catch (Exception e) {
            logger.error("Failed to derive key from shared secret", e);
            throw new RuntimeException("Failed to derive key from shared secret", e);
        }
    }

    /**
     * Utility method to securely clear sensitive data from memory.
     */
    public static void clearSensitiveData(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }
}
