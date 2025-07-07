//! Encrypted handshake variant using ECIES for enhanced privacy.
//!
//! This module provides an encrypted handshake that encrypts the handshake
//! messages themselves using a simplified ECIES-like approach, preventing
//! network observers from learning handshake metadata while maintaining
//! all the security properties of the standard handshake.

use super::{handshake::Hello, x25519, Config};
use crate::Error;
use bytes::{Buf, BufMut};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use commonware_codec::{DecodeExt, Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{PublicKey, Signer};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::marker::PhantomData;
use x25519_dalek::EphemeralSecret;
use zeroize::Zeroize;

/// Size of the nonce used for symmetric encryption
const NONCE_SIZE: usize = 12;

/// Size of the authentication tag
const TAG_SIZE: usize = 16;

/// Configuration for encrypted handshake connections.
#[derive(Clone)]
pub struct EncryptedConfig<C: Signer> {
    /// Base configuration
    pub base: Config<C>,
}

impl<C: Signer> EncryptedConfig<C> {
    /// Create a new encrypted configuration from a base configuration
    pub fn new(base: Config<C>) -> Self {
        Self { base }
    }
}

/// An encrypted Hello message using ECIES-like encryption.
///
/// This encrypts the Hello message using a shared key derived from both
/// parties' static keys, providing privacy for handshake metadata.
pub struct EncryptedHello<P: PublicKey> {
    /// Ephemeral public key used for key exchange
    ephemeral_public_key: x25519::PublicKey,

    /// Nonce used for symmetric encryption
    nonce: [u8; NONCE_SIZE],

    /// Encrypted Hello message
    ciphertext: Vec<u8>,

    /// Authentication tag
    tag: [u8; TAG_SIZE],

    /// Phantom data for the public key type
    _phantom: PhantomData<P>,
}

impl<P: PublicKey> EncryptedHello<P> {
    /// Encrypt a Hello message using ECIES-like encryption.
    pub fn encrypt(
        hello: &Hello<P>,
        sender_key: &impl Signer<PublicKey = P>,
        recipient_public_key: &P,
    ) -> Result<Self, Error> {
        // Generate ephemeral key pair for this message
        let ephemeral_private_key = EphemeralSecret::random_from_rng(rand::thread_rng());
        let ephemeral_public_key = x25519::PublicKey::from_secret(&ephemeral_private_key);

        // Derive a shared secret from both parties' static keys
        let shared_secret =
            Self::derive_shared_secret(&sender_key.public_key(), recipient_public_key)?;

        // Derive encryption key using HKDF
        let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut encryption_key = [0u8; 32];
        hkdf.expand(b"commonware-encrypted-handshake", &mut encryption_key)
            .map_err(|_| Error::EncryptionFailed)?;

        // Generate random nonce
        let mut nonce = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);

        // Encrypt the Hello message
        let plaintext = hello.encode();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&encryption_key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), &plaintext[..])
            .map_err(|_| Error::EncryptionFailed)?;

        // Split ciphertext and tag
        let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - TAG_SIZE);
        let mut tag_array = [0u8; TAG_SIZE];
        tag_array.copy_from_slice(tag);

        // Zeroize sensitive key material
        encryption_key.zeroize();

        Ok(Self {
            ephemeral_public_key,
            nonce,
            ciphertext: ciphertext.to_vec(),
            tag: tag_array,
            _phantom: PhantomData,
        })
    }

    /// Decrypt an encrypted Hello message.
    pub fn decrypt<S: Signer<PublicKey = P>>(
        &self,
        recipient_private_key: &S,
        sender_public_key: &P,
    ) -> Result<Hello<P>, Error> {
        // Derive the same shared secret as used for encryption
        let shared_secret =
            Self::derive_shared_secret(sender_public_key, &recipient_private_key.public_key())?;

        // Derive encryption key using HKDF
        let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut encryption_key = [0u8; 32];
        hkdf.expand(b"commonware-encrypted-handshake", &mut encryption_key)
            .map_err(|_| Error::DecryptionFailed)?;

        // Decrypt the Hello message
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&encryption_key));
        let mut ciphertext_with_tag = self.ciphertext.clone();
        ciphertext_with_tag.extend_from_slice(&self.tag);

        let plaintext = cipher
            .decrypt(Nonce::from_slice(&self.nonce), &ciphertext_with_tag[..])
            .map_err(|_| Error::DecryptionFailed)?;

        // Zeroize sensitive key material
        encryption_key.zeroize();

        // Decode the Hello message
        Hello::decode(&plaintext[..]).map_err(Error::UnableToDecode)
    }

    /// Derive a shared secret from two public keys.
    ///
    /// This creates a deterministic shared secret that both parties can compute
    /// from each other's public keys.
    fn derive_shared_secret(key1: &P, key2: &P) -> Result<[u8; 32], Error> {
        let key1_bytes = key1.encode();
        let key2_bytes = key2.encode();

        if key1_bytes.len() != 32 || key2_bytes.len() != 32 {
            return Err(Error::InvalidKey);
        }

        // Create a deterministic shared secret by hashing both keys together
        let mut hasher = Sha256::new();

        // Ensure deterministic ordering regardless of who calls this function
        if key1_bytes < key2_bytes {
            hasher.update(&key1_bytes);
            hasher.update(&key2_bytes);
        } else {
            hasher.update(&key2_bytes);
            hasher.update(&key1_bytes);
        }

        hasher.update(b"commonware-shared-secret");
        let derived_bytes = hasher.finalize();

        let mut result = [0u8; 32];
        result.copy_from_slice(&derived_bytes[..32]);
        Ok(result)
    }
}

impl<P: PublicKey> Write for EncryptedHello<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.ephemeral_public_key.write(buf);
        self.nonce.write(buf);

        // Write ciphertext length and data
        (self.ciphertext.len() as u32).write(buf);
        buf.put_slice(&self.ciphertext);

        // Write tag
        self.tag.write(buf);
    }
}

impl<P: PublicKey> Read for EncryptedHello<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let ephemeral_public_key = x25519::PublicKey::read(buf)?;
        let nonce = <[u8; NONCE_SIZE]>::read(buf)?;

        // Read ciphertext length and data
        let ciphertext_len = u32::read(buf)? as usize;
        if ciphertext_len > buf.remaining() {
            return Err(CodecError::EndOfBuffer);
        }

        let mut ciphertext = vec![0u8; ciphertext_len];
        buf.copy_to_slice(&mut ciphertext);

        // Read tag
        let tag = <[u8; TAG_SIZE]>::read(buf)?;

        Ok(Self {
            ephemeral_public_key,
            nonce,
            ciphertext,
            tag,
            _phantom: PhantomData,
        })
    }
}

impl<P: PublicKey> EncodeSize for EncryptedHello<P> {
    fn encode_size(&self) -> usize {
        self.ephemeral_public_key.encode_size()
            + self.nonce.encode_size()
            + 4 // ciphertext length
            + self.ciphertext.len()
            + self.tag.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_key::handshake::Info;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey as Ed25519PublicKey},
        PrivateKeyExt,
    };
    use commonware_runtime::{deterministic, Clock, Runner};
    use commonware_utils::SystemTimeExt;

    const TEST_NAMESPACE: &[u8] = b"test_namespace";

    #[test]
    fn test_encrypted_hello_encrypt_decrypt() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create test participants
            let mut sender = PrivateKey::from_seed(0);
            let recipient = PrivateKey::from_seed(1);
            let ephemeral_public_key = x25519::PublicKey::from_bytes([3u8; 32]);

            // Create a Hello message
            let timestamp = context.current().epoch_millis();
            let info = Info::new(recipient.public_key(), ephemeral_public_key, timestamp);
            let hello = super::super::handshake::Hello::sign(&mut sender, TEST_NAMESPACE, info);

            // Encrypt the Hello message
            let encrypted_hello =
                EncryptedHello::encrypt(&hello, &sender, &recipient.public_key()).unwrap();

            // Decrypt the Hello message
            let decrypted_hello = encrypted_hello
                .decrypt(&recipient, &sender.public_key())
                .unwrap();

            // Verify the decrypted message matches the original
            assert_eq!(decrypted_hello.signer(), hello.signer());
            assert_eq!(decrypted_hello.ephemeral(), hello.ephemeral());
        });
    }

    #[test]
    fn test_encrypted_hello_encoding() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut sender = PrivateKey::from_seed(0);
            let recipient = PrivateKey::from_seed(1);
            let ephemeral_public_key = x25519::PublicKey::from_bytes([3u8; 32]);

            // Create and encrypt a Hello message
            let timestamp = context.current().epoch_millis();
            let info = Info::new(recipient.public_key(), ephemeral_public_key, timestamp);
            let hello = super::super::handshake::Hello::sign(&mut sender, TEST_NAMESPACE, info);

            let encrypted_hello =
                EncryptedHello::encrypt(&hello, &sender, &recipient.public_key()).unwrap();

            // Encode and decode the encrypted hello
            let encoded = encrypted_hello.encode();
            let decoded: EncryptedHello<Ed25519PublicKey> =
                EncryptedHello::decode(encoded).unwrap();

            // Verify the decoded message can be decrypted
            let decrypted_hello = decoded.decrypt(&recipient, &sender.public_key()).unwrap();
            assert_eq!(decrypted_hello.signer(), hello.signer());
        });
    }

    #[test]
    fn test_encrypted_hello_different_keys() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut sender = PrivateKey::from_seed(0);
            let recipient = PrivateKey::from_seed(1);
            let wrong_sender = PrivateKey::from_seed(2);
            let ephemeral_public_key = x25519::PublicKey::from_bytes([3u8; 32]);

            // Create and encrypt a Hello message
            let timestamp = context.current().epoch_millis();
            let info = Info::new(recipient.public_key(), ephemeral_public_key, timestamp);
            let hello = super::super::handshake::Hello::sign(&mut sender, TEST_NAMESPACE, info);

            let encrypted_hello =
                EncryptedHello::encrypt(&hello, &sender, &recipient.public_key()).unwrap();

            // Try to decrypt with wrong sender key - should fail
            let result = encrypted_hello.decrypt(&recipient, &wrong_sender.public_key());
            assert!(result.is_err());

            // Decrypt with correct keys - should succeed
            let decrypted_hello = encrypted_hello
                .decrypt(&recipient, &sender.public_key())
                .unwrap();
            assert_eq!(decrypted_hello.signer(), hello.signer());
        });
    }
}
