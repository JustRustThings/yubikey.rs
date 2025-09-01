//! Management Key (MGM) for authenticating to the YubiKey management applet

// Adapted from yubico-piv-tool:
// <https://github.com/Yubico/yubico-piv-tool/>
//
// Copyright (c) 2014-2016 Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//   * Redistributions in binary form must reproduce the above
//     copyright notice, this list of conditions and the following
//     disclaimer in the documentation and/or other materials provided
//     with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::{Error, Result};
use log::error;
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "untested")]
use crate::{
    consts::{TAG_ADMIN_FLAGS_1, TAG_ADMIN_SALT, TAG_PROTECTED_MGM},
    metadata::{AdminData, ProtectedData},
    piv::{SlotId, ManagementAlgorithmId, ManagementSlotId},
    transaction::Transaction,
};
use crate::yubikey::{Version, YubiKey};
use des::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, Key, KeyInit, KeySizeUser, Unsigned},
    TdesEde3,
};
#[cfg(feature = "untested")]
use {pbkdf2::pbkdf2_hmac, sha1::Sha1};

/// YubiKey MGMT Applet Name
#[cfg(feature = "untested")]
pub(crate) const APPLET_NAME: &str = "YubiKey MGMT";

/// MGMT Applet ID.
///
/// <https://developers.yubico.com/PIV/Introduction/Admin_access.html>
#[cfg(feature = "untested")]
pub(crate) const APPLET_ID: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

/// Size of a DES key
const DES_LEN_DES: usize = 8;

/// Size of a 3DES key
pub(super) const DES_LEN_3DES: usize = DES_LEN_DES * 3;

pub(crate) const ADMIN_FLAGS_1_PROTECTED_MGM: u8 = 0x02;

#[cfg(feature = "untested")]
const CB_ADMIN_SALT: usize = 16;

/// The default MGM key loaded for both Triple-DES and AES keys
const DEFAULT_MGM_KEY: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

/// Number of PBKDF2 iterations to use when deriving from a password
#[cfg(feature = "untested")]
const ITER_MGM_PBKDF2: u32 = 10000;

/// Management Key (MGM) key types (manual/derived/protected).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MgmType {
    /// Manual
    Manual = 0,

    /// Derived
    Derived = 1,

    /// Protected
    Protected = 2,
}

/// Management key algorithm identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmAlgorithmId {
    /// Triple DES (3DES) in EDE mode
    ThreeDes,
    /// AES-128
    Aes128,
    /// AES-192
    Aes192,
    /// AES-256
    Aes256,
}

impl TryFrom<u8> for MgmAlgorithmId {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x03 => Ok(MgmAlgorithmId::ThreeDes),
            0x08 => Ok(MgmAlgorithmId::Aes128),
            0x0a => Ok(MgmAlgorithmId::Aes192),
            0x0c => Ok(MgmAlgorithmId::Aes256),
            _ => Err(Error::AlgorithmError),
        }
    }
}

impl From<MgmAlgorithmId> for u8 {
    fn from(id: MgmAlgorithmId) -> u8 {
        match id {
            MgmAlgorithmId::ThreeDes => 0x03,
            MgmAlgorithmId::Aes128 => 0x08,
            MgmAlgorithmId::Aes192 => 0x0a,
            MgmAlgorithmId::Aes256 => 0x0c,
        }
    }
}

impl MgmAlgorithmId {
    /// Looks up the algorithm for the given Yubikey's current management key.
    #[cfg(feature = "untested")]
    fn query(txn: &Transaction<'_>) -> Result<Self> {
        match txn.get_metadata(SlotId::Management(crate::piv::ManagementSlotId::Management)) {
            Ok(metadata) => match metadata.algorithm {
                ManagementAlgorithmId::ThreeDes => Ok(MgmAlgorithmId::ThreeDes),
                ManagementAlgorithmId::Aes128 => Ok(MgmAlgorithmId::Aes128),
                ManagementAlgorithmId::Aes192 => Ok(MgmAlgorithmId::Aes192),
                ManagementAlgorithmId::Aes256 => Ok(MgmAlgorithmId::Aes256),
                // We specifically queried the management key slot; getting a known
                // non-management algorithm back from the Yubikey is invalid.
                _ => Err(Error::InvalidObject),
            },
            // Firmware versions without `GET METADATA` only support 3DES.
            Err(Error::NotSupported) => Ok(MgmAlgorithmId::ThreeDes),
            // `Error::AlgorithmError` only occurs when a new algorithm is encountered.
            Err(Error::AlgorithmError) => Err(Error::NotSupported),
            // Raise other errors as-is.
            Err(e) => Err(e),
        }
    }
}

/// Management Key (MGM).
///
/// This key is used to authenticate to the management applet running on
/// a YubiKey in order to perform administrative functions.
///
/// The only supported algorithm for MGM keys are 3DES and AES.
#[derive(Clone)]
pub struct MgmKey(MgmKeyKind);

#[derive(Clone)]
enum MgmKeyKind {
    Tdes(Key<des::TdesEde3>),
    Aes128(Key<aes::Aes128>),
    Aes192(Key<aes::Aes192>),
    Aes256(Key<aes::Aes256>),
}

impl MgmKey {
     /// Generate a random 3DES MGM key
     pub fn generate() -> Self {
         Self::generate_alg(MgmAlgorithmId::ThreeDes, &mut OsRng)
     }

    /// Generates a random MGM key for the given algorithm.
    pub fn generate_alg(alg: MgmAlgorithmId, rng: &mut impl RngCore) -> Self {
        match alg {
            MgmAlgorithmId::ThreeDes => {
                let mut key_bytes = [0u8; DES_LEN_3DES];
                rng.fill_bytes(&mut key_bytes);
                Self(MgmKeyKind::Tdes(key_bytes.into()))
            }
            MgmAlgorithmId::Aes128 => {
                let mut key_bytes = [0u8; <aes::Aes128 as KeySizeUser>::KeySize::USIZE];
                rng.fill_bytes(&mut key_bytes);
                Self(MgmKeyKind::Aes128(key_bytes.into()))
            }
            MgmAlgorithmId::Aes192 => {
                let mut key_bytes = [0u8; <aes::Aes192 as KeySizeUser>::KeySize::USIZE];
                rng.fill_bytes(&mut key_bytes);
                Self(MgmKeyKind::Aes192(key_bytes.into()))
            }
            MgmAlgorithmId::Aes256 => {
                let mut key_bytes = [0u8; <aes::Aes256 as KeySizeUser>::KeySize::USIZE];
                rng.fill_bytes(&mut key_bytes);
                Self(MgmKeyKind::Aes256(key_bytes.into()))
            }
        }
    }

    /// Generates a random MGM key using the preferred algorithm for the given Yubikey's
    /// firmware version.
    pub fn generate_for(yubikey: &YubiKey, rng: &mut impl RngCore) -> Result<Self> {
        match yubikey.version() {
            // Initial firmware versions default to 3DES.
            Version { major: ..=4, .. }
            | Version {
                major: 5,
                minor: ..=6,
                ..
            } => Ok(Self::generate_alg(MgmAlgorithmId::ThreeDes, rng)),
            // Firmware 5.7.0 and above default to AES-192.
            Version {
                major: 5,
                minor: 7..,
                ..
            }
            | Version { major: 6.., .. } => Ok(Self::generate_alg(MgmAlgorithmId::Aes192, rng)),
        }
    }

    /// Create a 3DES MGM key from the given byte array.
    ///
    /// Returns an error if the key is weak.
    pub fn new(key_bytes: [u8; DES_LEN_3DES]) -> Result<Self> {
       Self::from_bytes(key_bytes, None)
    }

    /// Parses an MGM key from the given byte slice.
    ///
    /// Returns an error if the slice is an invalid size or the key is weak.
    ///
    /// If `alg` is `None`, the algorithm will be selected based on the length of the
    /// slice, returning an error if there is not a unique match.
    pub fn from_bytes(bytes: impl AsRef<[u8]>, alg: Option<MgmAlgorithmId>) -> Result<Self> {
        match alg {
            Some(alg) => Self::parse_key(alg, bytes),
            None => match bytes.as_ref().len() {
                DES_LEN_3DES => Self::parse_key(MgmAlgorithmId::ThreeDes, bytes),
                _ => Err(Error::ParseError),
            },
        }
    }

    /// Gets the default management key for the given Yubikey's firmware version.
    ///
    /// Returns an error if the Yubikey's default algorithm is unsupported.
    pub fn get_default(yubikey: &YubiKey) -> Result<Self> {
        match yubikey.version() {
            // Initial firmware versions default to 3DES.
            Version { major: ..=4, .. }
            | Version {
                major: 5,
                minor: ..=6,
                ..
            } => Ok(Self(MgmKeyKind::Tdes(DEFAULT_MGM_KEY.into()))),
            // Firmware 5.7.0 and above default to AES-192.
            Version {
                major: 5,
                minor: 7..,
                ..
            }
            | Version { major: 6.., .. } => Ok(Self(MgmKeyKind::Aes192(DEFAULT_MGM_KEY.into()))),
        }
    }

    /// Resets the management key for the given YubiKey to the default value for that
    /// Yubikey's firmware version.
    ///
    /// This will wipe any metadata related to derived and PIN-protected management keys.
    #[cfg(feature = "untested")]
    pub fn set_default(yubikey: &mut YubiKey) -> Result<()> {
        Self::get_default(yubikey)?.set_manual(yubikey, false)
    }

    /// Derives a 3DES management key (MGM) from a stored salt.
    ///
    /// # Security
    ///
    /// Warning: PIN-derived mode is not secure. You should not use this technique. It is
    /// offered only for backwards compatibility.
    #[cfg(feature = "untested")]
    pub fn get_derived(yubikey: &mut YubiKey, pin: &[u8]) -> Result<Self> {
        let txn = yubikey.begin_transaction()?;

        // recover management key
        let admin_data = AdminData::read(&txn)?;
        let salt = admin_data.get_item(TAG_ADMIN_SALT)?;

        if salt.len() != CB_ADMIN_SALT {
            error!(
                "derived MGM salt exists, but is incorrect size: {} (expected {})",
                salt.len(),
                CB_ADMIN_SALT
            );

            return Err(Error::GenericError);
        }

        let mut mgm = Key::<des::TdesEde3>::default();
        pbkdf2_hmac::<Sha1>(pin, salt, ITER_MGM_PBKDF2, &mut mgm);
        is_weak_key(&mgm).then(|| ()).ok_or(Error::KeyError)?;
        Ok(Self(MgmKeyKind::Tdes(mgm.into())))
    }

    /// Get protected management key (MGM)
    #[cfg(feature = "untested")]
    pub fn get_protected(yubikey: &mut YubiKey) -> Result<Self> {
        let txn = yubikey.begin_transaction()?;

        let alg = MgmAlgorithmId::query(&txn)?;

        let protected_data = ProtectedData::read(&txn).map_err(|e| {
            error!("could not read protected data (err: {:?})", e);
            e
        })?;

        let item = protected_data.get_item(TAG_PROTECTED_MGM).map_err(|e| {
            error!("could not read protected MGM from metadata (err: {:?})", e);
            e
        })?;

        Self::parse_key(alg, item).map_err(|e| match e {
            Error::SizeError => {
                error!(
                    "protected data contains MGM, but is the wrong size: {} (expected {:?})",
                    item.len(),
                    alg,
                );
                Error::AuthenticationError
            }
            _ => e,
        })
    }

    /// Configures the given YubiKey to use this management key.
    ///
    /// The management key must be stored by the user, and provided when performing key
    /// management operations.
    ///
    /// This will wipe any metadata related to derived and PIN-protected management keys.
    #[cfg(feature = "untested")]
    pub fn set_manual(&self, yubikey: &mut YubiKey, require_touch: bool) -> Result<()> {
        let txn = yubikey.begin_transaction()?;

        txn.set_mgm_key(self, require_touch).map_err(|e| {
            // Log a warning, since the device mgm key is corrupt or we're in a state
            // where we can't set the mgm key.
            error!("could not set new derived mgm key, err = {}", e);
            e
        })?;

        // After this point, we've set the mgm key, so the function should succeed,
        // regardless of being able to set the metadata.

        if let Ok(mut admin_data) = AdminData::read(&txn) {
            // Clear the protected mgm key bit.
            if let Ok(item) = admin_data.get_item(TAG_ADMIN_FLAGS_1) {
                let mut flags_1 = [0u8; 1];
                if item.len() == flags_1.len() {
                    flags_1.copy_from_slice(item);
                    flags_1[0] &= !ADMIN_FLAGS_1_PROTECTED_MGM;

                    if let Err(e) = admin_data.set_item(TAG_ADMIN_FLAGS_1, &flags_1) {
                        error!("could not set admin flags item, err = {}", e);
                    }
                } else {
                    error!(
                        "admin data flags are an incorrect size: {} (expected {})",
                        item.len(),
                        flags_1.len()
                    );
                }
            }

            // Remove any existing salt for a derived mgm key.
            if let Err(e) = admin_data.set_item(TAG_ADMIN_SALT, &[]) {
                error!("could not unset derived mgm salt (err = {})", e)
            }

            if let Err(e) = admin_data.write(&txn) {
                error!("could not write admin data, err = {}", e);
            }
        }

        // Clear any prior mgm key from protected data.
        if let Ok(mut protected_data) = ProtectedData::read(&txn) {
            if let Err(e) = protected_data.set_item(TAG_PROTECTED_MGM, &[]) {
                error!("could not clear protected mgm item, err = {:?}", e);
            } else if let Err(e) = protected_data.write(&txn) {
                error!("could not write protected data, err = {:?}", e);
            }
        }

        Ok(())
    }

    /// Configures the given YubiKey to use this as a PIN-protected management key.
    ///
    /// This enables key management operations to be performed with access to the PIN.
    #[cfg(feature = "untested")]
    pub fn set_protected(&self, yubikey: &mut YubiKey) -> Result<()> {
        let txn = yubikey.begin_transaction()?;

        txn.set_mgm_key(self, false).map_err(|e| {
            // log a warning, since the device mgm key is corrupt or we're in
            // a state where we can't set the mgm key
            error!("could not set new derived mgm key, err = {}", e);
            e
        })?;

        // after this point, we've set the mgm key, so the function should
        // succeed, regardless of being able to set the metadata

        // Fetch the current protected data, or start a blank metadata blob.
        let mut protected_data = ProtectedData::read(&txn).unwrap_or_default();

        // Set the new mgm key in protected data.
        if let Err(e) = protected_data.set_item(TAG_PROTECTED_MGM, self.as_ref()) {
            error!("could not set protected mgm item, err = {:?}", e);
        } else {
            protected_data.write(&txn).map_err(|e| {
                error!("could not write protected data, err = {:?}", e);
                e
            })?;
        }

        // set the protected mgm flag in admin data

        let mut flags_1 = [0u8; 1];

        let mut admin_data = if let Ok(mut admin_data) = AdminData::read(&txn) {
            if let Ok(item) = admin_data.get_item(TAG_ADMIN_FLAGS_1) {
                if item.len() == flags_1.len() {
                    flags_1.copy_from_slice(item);
                } else {
                    error!(
                        "admin data flags are an incorrect size: {} (expected {})",
                        item.len(),
                        flags_1.len()
                    );
                }
            } else {
                // flags are not set
                error!("admin data exists, but flags are not present");
            }

            // remove any existing salt
            if let Err(e) = admin_data.set_item(TAG_ADMIN_SALT, &[]) {
                error!("could not unset derived mgm salt (err = {})", e)
            }

            admin_data
        } else {
            AdminData::default()
        };

        flags_1[0] |= ADMIN_FLAGS_1_PROTECTED_MGM;

        if let Err(e) = admin_data.set_item(TAG_ADMIN_FLAGS_1, &flags_1) {
            error!("could not set admin flags item, err = {}", e);
        } else if let Err(e) = admin_data.write(&txn) {
            error!("could not write admin data, err = {}", e);
        }

        Ok(())
    }

    /// Returns the ID used to identify the key algorithm with APDU packets.
    pub(crate) fn algorithm_id(&self) -> MgmAlgorithmId {
        match &self.0 {
            MgmKeyKind::Tdes(_) => MgmAlgorithmId::ThreeDes,
            MgmKeyKind::Aes128(_) => MgmAlgorithmId::Aes128,
            MgmKeyKind::Aes192(_) => MgmAlgorithmId::Aes192,
            MgmKeyKind::Aes256(_) => MgmAlgorithmId::Aes256,
        }
    }

    /// Returns the key size in bytes.
    pub(crate) fn key_size(&self) -> u8 {
        match &self.0 {
            MgmKeyKind::Tdes(_) => <des::TdesEde3 as KeySizeUser>::KeySize::U8,
            MgmKeyKind::Aes128(_) => <aes::Aes128 as KeySizeUser>::KeySize::U8,
            MgmKeyKind::Aes192(_) => <aes::Aes192 as KeySizeUser>::KeySize::U8,
            MgmKeyKind::Aes256(_) => <aes::Aes256 as KeySizeUser>::KeySize::U8,
        }
    }

    /// Parses an MGM key from the given byte slice.
    ///
    /// Returns an error if the algorithm is unsupported, or the slice is the wrong size,
    /// or the key is weak.
    fn parse_key(alg: MgmAlgorithmId, bytes: impl AsRef<[u8]>) -> Result<Self> {
        match alg {
            MgmAlgorithmId::ThreeDes => {
                let key_size = <des::TdesEde3 as KeySizeUser>::KeySize::USIZE;
                if key_size != bytes.as_ref().len() {
                    return Err(Error::SizeError)
                }
                let key = Key::<des::TdesEde3>::from_slice(bytes.as_ref());
                is_weak_key(&key).then(|| ()).ok_or(Error::KeyError)?;
                Ok(MgmKeyKind::Tdes((*key).into()))
            }
            MgmAlgorithmId::Aes128 => {
                let key_size = <aes::Aes128 as KeySizeUser>::KeySize::USIZE;
                if key_size != bytes.as_ref().len() {
                    return Err(Error::SizeError)
                }
                let key = Key::<aes::Aes128>::from_slice(bytes.as_ref());
                Ok(MgmKeyKind::Aes128(*key))
            }
            MgmAlgorithmId::Aes192 => {
                let key_size = <aes::Aes192 as KeySizeUser>::KeySize::USIZE;
                if key_size != bytes.as_ref().len() {
                    return Err(Error::SizeError)
                }
                let key = Key::<aes::Aes192>::from_slice(bytes.as_ref());
                Ok(MgmKeyKind::Aes192(*key))
            }
            MgmAlgorithmId::Aes256 => {
                let key_size = <aes::Aes256 as KeySizeUser>::KeySize::USIZE;
                if key_size != bytes.as_ref().len() {
                    return Err(Error::SizeError)
                }
                let key = Key::<aes::Aes256>::from_slice(bytes.as_ref());
                Ok(MgmKeyKind::Aes256(*key))
            }
        }
        .map(Self)
    }

    /// Encrypts a block with this key.
    ///
    /// Returns an error if the block is the wrong size.
    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        match &self.0 {
            MgmKeyKind::Tdes(k) => {
                des::TdesEde3::new(k.into()).encrypt_block(block.try_into().map_err(|_| Error::SizeError)?)
            }
            MgmKeyKind::Aes128(k) => {
                aes::Aes128::new(k).encrypt_block(block.try_into().map_err(|_| Error::SizeError)?)
            }
            MgmKeyKind::Aes192(k) => {
                aes::Aes192::new(k).encrypt_block(block.try_into().map_err(|_| Error::SizeError)?)
            }
            MgmKeyKind::Aes256(k) => {
                aes::Aes256::new(k).encrypt_block(block.try_into().map_err(|_| Error::SizeError)?)
            }
        }
        Ok(())
    }

    /// Decrypts a block with this key.
    ///
    /// Returns an error if the block is the wrong size.
    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        match &self.0 {
            MgmKeyKind::Tdes(k) => {
                des::TdesEde3::new(k.into()).decrypt_block(block.try_into().map_err(|_| Error::SizeError)?)
            }
            MgmKeyKind::Aes128(k) => {
                aes::Aes128::new(k).decrypt_block(block.try_into().map_err(|_| Error::SizeError)?)
            }
            MgmKeyKind::Aes192(k) => {
                aes::Aes192::new(k).decrypt_block(block.try_into().map_err(|_| Error::SizeError)?)
            }
            MgmKeyKind::Aes256(k) => {
                aes::Aes256::new(k).decrypt_block(block.try_into().map_err(|_| Error::SizeError)?)
            }
        }
        Ok(())
    }

    /// Given a challenge from a card, decrypts it and return the value
    pub(crate) fn card_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>> {
        let mut output = challenge.to_owned();
        self.decrypt_block(output.as_mut_slice())?;
        Ok(output)
    }

    /// Checks the authentication matches the challenge and auth data
    pub(crate) fn check_challenge(&self, challenge: &[u8], auth_data: &[u8]) -> Result<()> {
        let mut response = challenge.to_owned();

        self.encrypt_block(response.as_mut_slice())?;

        use subtle::ConstantTimeEq;
        if response.ct_eq(auth_data).unwrap_u8() != 1 {
            return Err(Error::AuthenticationError);
        }

        Ok(())
    }
}

/// Default MGM key configured on all YubiKeys
impl Default for MgmKey {
    fn default() -> Self {
        MgmKey(MgmKeyKind::Tdes(DEFAULT_MGM_KEY.into()))
    }
}

impl AsRef<[u8]> for MgmKey {
    fn as_ref(&self) -> &[u8] {
        match &self.0 {
            MgmKeyKind::Tdes(k) => k.as_ref(),
            MgmKeyKind::Aes128(k) => k.as_ref(),
            MgmKeyKind::Aes192(k) => k.as_ref(),
            MgmKeyKind::Aes256(k) => k.as_ref(),
        }
    }
}

/// Weak and semi weak DES keys as taken from:
/// %A D.W. Davies
/// %A W.L. Price
/// %T Security for Computer Networks
/// %I John Wiley & Sons
/// %D 1984
const WEAK_DES_KEYS: &[[u8; DES_LEN_DES]] = &[
    // weak keys
    [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
    [0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE],
    [0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E],
    [0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1],
    // semi-weak keys
    [0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE],
    [0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01],
    [0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1],
    [0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E],
    [0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1],
    [0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01],
    [0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE],
    [0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E],
    [0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E],
    [0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01],
    [0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE],
    [0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1],
];

/// Is this 3DES key weak?
///
/// This check is performed automatically when the key is instantiated to
/// ensure no such keys are used.
fn is_weak_key(key: &Key::<des::TdesEde3>) -> bool {
    // set odd parity of key
    let mut tmp = Zeroizing::new([0u8; DES_LEN_3DES]);

    for i in 0..DES_LEN_3DES {
        // count number of set bits in byte, excluding the low-order bit - SWAR method
        let mut c = key[i] & 0xFE;

        c = (c & 0x55) + ((c >> 1) & 0x55);
        c = (c & 0x33) + ((c >> 2) & 0x33);
        c = (c & 0x0F) + ((c >> 4) & 0x0F);

        // if count is even, set low key bit to 1, otherwise 0
        tmp[i] = (key[i] & 0xFE) | u8::from(c & 0x01 != 0x01);
    }

    // check odd parity key against table by DES key block
    let mut is_weak = false;

    for weak_key in WEAK_DES_KEYS.iter() {
        if weak_key == &tmp[0..DES_LEN_DES]
            || weak_key == &tmp[DES_LEN_DES..2 * DES_LEN_DES]
            || weak_key == &tmp[2 * DES_LEN_DES..3 * DES_LEN_DES]
        {
            is_weak = true;
            break;
        }
    }

    is_weak
}
