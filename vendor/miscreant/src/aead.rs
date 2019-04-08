//! `aead.rs`: Authenticated Encryption with Associated Data (AEAD):
//! Symmetric encryption which ensures message confidentiality, integrity,
//! and authenticity.

use crate::{error::Error, siv::Siv, Aes128, Aes256};
#[cfg(feature = "alloc")]
use crate::{prelude::*, IV_SIZE};

use cmac::Cmac;
use crypto_mac::Mac;
use ctr::Ctr128;
use generic_array::{typenum::U16, ArrayLength};
use pmac::Pmac;
use stream_cipher::{NewStreamCipher, SyncStreamCipher};

/// An Authenticated Encryption with Associated Data (AEAD) algorithm.
pub trait Aead {
    /// Size of a key associated with this AEAD algorithm
    type KeySize: ArrayLength<u8>;

    /// Size of a MAC tag
    type TagSize: ArrayLength<u8>;

    /// Create a new AEAD instance
    ///
    /// Panics if the key is the wrong length
    fn new(key: &[u8]) -> Self;

    /// Encrypt the given plaintext in-place, replacing it with the SIV tag and
    /// ciphertext. Requires a buffer with 16-bytes additional space.
    ///
    /// To encrypt data, it is recommended to use this API instead of the lower-level `Siv` API.
    ///
    /// # Usage
    ///
    /// It's important to note that only the *end* of the buffer will be
    /// treated as the input plaintext:
    ///
    /// ```rust
    /// let buffer = [0u8; 21];
    /// let plaintext = &buffer[..buffer.len() - 16];
    /// ```
    ///
    /// In this case, only the *last* 5 bytes are treated as the plaintext,
    /// since `21 - 16 = 5` (the AES block size is 16-bytes).
    ///
    /// The buffer must include an additional 16-bytes of space in which to
    /// write the SIV tag (at the beginning of the buffer).
    /// Failure to account for this will leave you with plaintext messages that
    /// are missing their first 16-bytes!
    ///
    /// # Panics
    ///
    /// Panics if `plaintext.len()` is less than `M::OutputSize`.
    /// Panics if `nonce.len()` is greater than `MAX_ASSOCIATED_DATA`.
    /// Panics if `associated_data.len()` is greater than `MAX_ASSOCIATED_DATA`.
    fn seal_in_place(&mut self, nonce: &[u8], associated_data: &[u8], buffer: &mut [u8]);

    /// Decrypt the given ciphertext in-place, authenticating it against the
    /// synthetic IV included in the message.
    ///
    /// To decrypt data, it is recommended to use this API instead of the lower-level `Siv` API.
    ///
    /// Returns a slice containing a decrypted message on success.
    fn open_in_place<'a>(
        &mut self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], Error>;

    /// Encrypt the given plaintext, allocating and returning a Vec<u8> for the ciphertext
    #[cfg(feature = "alloc")]
    fn seal(&mut self, nonce: &[u8], associated_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut buffer = vec![0; IV_SIZE + plaintext.len()];
        buffer[IV_SIZE..].copy_from_slice(plaintext);
        self.seal_in_place(nonce, associated_data, &mut buffer);
        buffer
    }

    /// Decrypt the given ciphertext, allocating and returning a Vec<u8> for the plaintext
    #[cfg(feature = "alloc")]
    fn open(
        &mut self,
        nonce: &[u8],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::from(ciphertext);
        self.open_in_place(nonce, associated_data, &mut buffer)?;
        buffer.drain(..IV_SIZE);
        Ok(buffer)
    }
}

/// The `SivAead` type wraps the more powerful `Siv` interface in a more
/// commonly used Authenticated Encryption with Associated Data (AEAD) API,
/// which accepts a key, nonce, and associated data when encrypting/decrypting.
pub struct SivAead<C, M>
where
    C: NewStreamCipher<NonceSize = U16> + SyncStreamCipher,
    M: Mac<OutputSize = U16>,
{
    siv: Siv<C, M>,
}

/// SIV AEAD modes based on CMAC
pub type CmacSivAead<BlockCipher> = SivAead<Ctr128<BlockCipher>, Cmac<BlockCipher>>;

/// SIV AEAD modes based on PMAC
pub type PmacSivAead<BlockCipher> = SivAead<Ctr128<BlockCipher>, Pmac<BlockCipher>>;

/// AES-CMAC-SIV in AEAD mode with 256-bit key size (128-bit security)
pub type Aes128SivAead = CmacSivAead<Aes128>;

/// AES-CMAC-SIV in AEAD mode with 512-bit key size (256-bit security)
pub type Aes256SivAead = CmacSivAead<Aes256>;

/// AES-PMAC-SIV in AEAD mode with 256-bit key size (128-bit security)
pub type Aes128PmacSivAead = PmacSivAead<Aes128>;

/// AES-PMAC-SIV in AEAD mode with 512-bit key size (256-bit security)
pub type Aes256PmacSivAead = PmacSivAead<Aes256>;

impl<C, M> Aead for SivAead<C, M>
where
    C: NewStreamCipher<NonceSize = U16> + SyncStreamCipher,
    M: Mac<OutputSize = U16>,
{
    type KeySize = <C as NewStreamCipher>::KeySize;
    type TagSize = U16;

    fn new(key: &[u8]) -> Self {
        Self { siv: Siv::new(key) }
    }

    fn seal_in_place(&mut self, nonce: &[u8], associated_data: &[u8], buffer: &mut [u8]) {
        self.siv.seal_in_place(&[associated_data, nonce], buffer)
    }

    fn open_in_place<'a>(
        &mut self,
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        self.siv.open_in_place(&[associated_data, nonce], buffer)
    }
}
