//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::collections::HashMap;

use byteorder::{BigEndian, WriteBytesExt};
use cds_api::entities::*;
use rand::Rng;
use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, UnboundKey};
use ring::error::Unspecified;
use uuid::Uuid;

use crate::error::CdsClientError;

pub mod error;

#[derive(Clone)]
pub struct Client {
    client_privkey: x25519_dalek::StaticSecret,
    client_pubkey:  x25519_dalek::PublicKey,
}

#[derive(Default, Debug)]
pub struct RequestNegotiation {
    pub server_ephemeral_pubkey:      [u8; 32],
    pub server_static_pubkey:         [u8; 32],
    pub encrypted_pending_request_id: EncryptedMessage,
}

pub struct EncryptedRequest {
    pub pending_request_id: Vec<u8>,
    pub encrypted_message:  EncryptedMessage,
}

#[derive(Default, Debug)]
pub struct EncryptedMessage {
    pub iv:   [u8; 12],
    pub mac:  [u8; 16],
    pub data: Vec<u8>,
}

#[derive(Default, Clone)]
pub struct FixedNonce {
    pub iv: [u8; 12],
}

impl From<[u8; 12]> for FixedNonce {
    fn from(iv: [u8; 12]) -> Self {
        Self { iv }
    }
}

pub struct FixedSealingKey {
    sealing_key: ring::aead::SealingKey<FixedNonce>,
}

impl FixedSealingKey {
    fn new(key: &[u8; 32], iv: &[u8; 12]) -> Result<Self, CdsClientError> {
        let nonce: FixedNonce = iv.clone().into();
        let unbound_key = UnboundKey::new(&ring::aead::AES_256_GCM, key).map_err(|_| CdsClientError::CreateEncryptionKeyError)?;
        Ok(Self {
            sealing_key: ring::aead::SealingKey::new(unbound_key, nonce),
        })
    }

    fn seal_in_place(&mut self, aad: &[u8], encrypted_message: &mut EncryptedMessage) -> Result<(), CdsClientError> {
        self.sealing_key
            .seal_in_place_separate_tag(Aad::from(aad), &mut encrypted_message.data)
            .map(|mac| encrypted_message.mac.copy_from_slice(mac.as_ref()))
            .map_err(|_| CdsClientError::EncryptionError)?;
        Ok(())
    }
}

pub struct FixedOpeningKey {
    opening_key: ring::aead::OpeningKey<FixedNonce>,
}

impl FixedOpeningKey {
    fn new(key: &[u8; 32], iv: &[u8; 12]) -> Result<Self, CdsClientError> {
        let unbound_key = UnboundKey::new(&ring::aead::AES_256_GCM, key).map_err(|_| CdsClientError::CreateDecryptionKeyError)?;
        Ok(Self {
            opening_key: ring::aead::OpeningKey::new(unbound_key, iv.clone().into()),
        })
    }

    fn open_in_place(&mut self, aad: &[u8], cyphertext: &mut [u8]) -> Result<(), CdsClientError> {
        self.opening_key
            .open_in_place(Aad::from(aad), cyphertext)
            .map_err(|_| CdsClientError::DecryptionError)?;
        Ok(())
    }
}

impl NonceSequence for FixedNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Ok(ring::aead::Nonce::assume_unique_for_key(self.iv))
    }
}

impl Client {
    pub fn new(random: &mut (impl rand::RngCore + rand::CryptoRng)) -> Self {
        let client_privkey = x25519_dalek::StaticSecret::new(random);
        let client_pubkey = x25519_dalek::PublicKey::from(&client_privkey);
        Self {
            client_privkey,
            client_pubkey,
        }
    }

    pub fn client_pubkey(&self) -> &[u8; 32] {
        self.client_pubkey.as_bytes()
    }

    fn encrypt_data(
        random: &mut (impl rand::RngCore + rand::CryptoRng),
        key: &[u8; 32],
        data: &[u8],
        aad: &[u8],
    ) -> Result<EncryptedMessage, CdsClientError>
    {
        let mut encrypted_message = EncryptedMessage {
            iv:   [0; 12],
            mac:  [0; 16],
            data: Vec::from(data),
        };

        random.fill(&mut encrypted_message.iv);
        let mut encrypt_key = FixedSealingKey::new(key, &encrypted_message.iv)?;
        encrypt_key.seal_in_place(aad, &mut encrypted_message)?;
        Ok(encrypted_message)
    }

    pub fn attestation_request(&self) -> RemoteAttestationRequest {
        RemoteAttestationRequest {
            clientPublic: *self.client_pubkey(),
        }
    }

    pub fn discovery_request(
        &self,
        random: &mut (impl rand::RngCore + rand::CryptoRng),
        attestation_key: &str,
        negotiation: RequestNegotiation,
        phone_list: &[u64],
    ) -> Result<([u8; 32], DiscoveryRequest), CdsClientError>
    {
        let (client_key, server_key) = key_agreement(
            &self.client_privkey,
            &self.client_pubkey,
            &negotiation.server_ephemeral_pubkey,
            &negotiation.server_static_pubkey,
        )?;

        let mut ring_server_key = FixedOpeningKey::new(&server_key, &negotiation.encrypted_pending_request_id.iv)?;

        let pending_request_id_len = negotiation.encrypted_pending_request_id.data.len();
        let mut pending_request_id = negotiation.encrypted_pending_request_id.data;

        pending_request_id.extend_from_slice(&negotiation.encrypted_pending_request_id.mac);
        ring_server_key.open_in_place(&[], &mut pending_request_id)?;
        pending_request_id.truncate(pending_request_id_len);

        let mut query_nonce: [u8; 32] = [0; 32];
        random.fill(&mut query_nonce);

        let mut be_phone_data: Vec<u8> = Vec::with_capacity(std::mem::size_of::<u64>() * phone_list.len());
        for number in phone_list {
            be_phone_data
                .write_u64::<BigEndian>(*number)
                .map_err(|_| CdsClientError::U64u8SliceConversionError)?;
        }

        let mut query_data_vec: Vec<u8> = Vec::new();
        query_data_vec.extend_from_slice(&query_nonce);
        query_data_vec.extend_from_slice(be_phone_data.as_slice());
        let query_data = query_data_vec.as_mut_slice();
        let digest = ring::digest::digest(&ring::digest::SHA256, query_data);
        let mut commitment: [u8; 32] = [0; 32];
        commitment.copy_from_slice(digest.as_ref());

        // create random query data key
        let mut query_data_key_entropy: [u8; 32] = [0; 32];
        random.fill(&mut query_data_key_entropy);

        // encrypt query_data_key with client_key
        let envelope = Self::encrypt_data(random, &client_key, &query_data_key_entropy, &pending_request_id)?;
        let discovery_envelope = DiscoveryRequestEnvelope {
            requestId: RequestId(pending_request_id),
            data:      envelope.data,
            iv:        envelope.iv,
            mac:       envelope.mac,
        };

        // encrypt query_data with the query_data_key
        let query_data_message = Self::encrypt_data(random, &query_data_key_entropy, query_data, &[])?;

        let mut envelopes = HashMap::new();
        let _ = envelopes.insert(attestation_key.to_owned(), discovery_envelope);

        let discovery_request = DiscoveryRequest {
            addressCount: phone_list.len() as u32,
            commitment,
            data: query_data_message.data,
            iv: query_data_message.iv,
            mac: query_data_message.mac,
            envelopes,
        };

        Ok((server_key, discovery_request))
    }

    pub fn decode_discovery_response(server_key: [u8; 32], response: DiscoveryResponse) -> Result<Vec<Uuid>, CdsClientError> {
        let uuid_array_len = response.data.len();
        let mut uuid_array = response.data;

        uuid_array.extend_from_slice(&response.mac);
        let mut ring_server_key = FixedOpeningKey::new(&server_key, &response.iv)?;
        ring_server_key.open_in_place(&[], &mut uuid_array)?;
        uuid_array.truncate(uuid_array_len);

        // process the array in 16-byte chunks
        let mut uuids = Vec::new();
        for uuid_bytes in uuid_array.chunks_exact(std::mem::size_of::<Uuid>()) {
            uuids.push(Uuid::from_slice(uuid_bytes).map_err(|_| CdsClientError::U8UuidConverionError)?);
        }
        Ok(uuids)
    }
}

pub struct PendingRequest {
    server_key: [u8; 32],
}

impl PendingRequest {
    pub fn decrypt_reply(self, mut reply: EncryptedMessage) -> Result<(), CdsClientError> {
        reply.data.extend_from_slice(&reply.mac);
        let mut ring_server_key = FixedOpeningKey::new(&self.server_key, &reply.iv)?;
        ring_server_key.open_in_place(&[], &mut reply.data)?;

        Ok(())
    }
}

struct CdsHkdfKeyType {}
impl ring::hkdf::KeyType for CdsHkdfKeyType {
    fn len(&self) -> usize {
        64
    }
}

fn key_agreement(
    client_privkey: &x25519_dalek::StaticSecret,
    client_pubkey: &x25519_dalek::PublicKey,
    server_ephemeral_pubkey: &[u8; 32],
    server_static_pubkey: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), CdsClientError>
{
    let server_ephemeral_pubkey = x25519_dalek::PublicKey::from(*server_ephemeral_pubkey);
    let server_static_pubkey = x25519_dalek::PublicKey::from(*server_static_pubkey);
    let hkdf_secret = {
        let mut hkdf_secret: [u8; 64] = [0; 64];
        let ephemeral_dh_key = client_privkey.diffie_hellman(&server_ephemeral_pubkey);
        let static_dh_key = client_privkey.diffie_hellman(&server_static_pubkey);
        hkdf_secret[0..32].copy_from_slice(ephemeral_dh_key.as_bytes());
        hkdf_secret[32..64].copy_from_slice(static_dh_key.as_bytes());
        hkdf_secret
    };
    let hkdf_salt = {
        let mut hkdf_salt_bytes: [u8; 96] = [0; 96];
        hkdf_salt_bytes[0..32].copy_from_slice(client_pubkey.as_bytes());
        hkdf_salt_bytes[32..64].copy_from_slice(server_ephemeral_pubkey.as_bytes());
        hkdf_salt_bytes[64..96].copy_from_slice(server_static_pubkey.as_bytes());
        ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &hkdf_salt_bytes)
    };

    let mut keys: [u8; 64] = [0; 64];
    let mut client_key: [u8; 32] = [0; 32];
    let mut server_key: [u8; 32] = [0; 32];

    let prk = hkdf_salt.extract(&hkdf_secret);
    let key_type = CdsHkdfKeyType {};
    let okm = prk.expand(&[&[0u8; 0]], key_type).unwrap();
    okm.fill(keys.as_mut()).map_err(|_| CdsClientError::ExtractHkdfError)?;
    client_key.copy_from_slice(&keys[0..32]);
    server_key.copy_from_slice(&keys[32..64]);
    Ok((client_key, server_key))
}
