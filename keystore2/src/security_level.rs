// Copyright 2020, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This crate implements the IKeystoreSecurityLevel interface.

use crate::attestation_key_utils::{get_attest_key_info, AttestationKeyInfo};
use crate::audit_log::{
    log_key_deleted, log_key_generated, log_key_imported, log_key_integrity_violation,
};
#[allow(unused_imports)]
use crate::database::{BlobInfo, CertificateInfo, KeyIdGuard, EC_PRIVATE_KEY, CERTIFICATE_1, CERTIFICATE_2, CERTIFICATE_3};
use crate::error::{
    self, into_logged_binder, map_km_error, wrapped_rkpd_error_to_ks_error, Error, ErrorCode,
};
use crate::globals::{
    get_remotely_provisioned_component_name, DB, ENFORCEMENTS, LEGACY_IMPORTER, SUPER_KEY,
};
use crate::key_parameter::KeyParameter as KsKeyParam;
use crate::key_parameter::KeyParameterValue as KsKeyParamValue;
use crate::ks_err;
use crate::metrics_store::log_key_creation_event_stats;
use crate::remote_provisioning::RemProvState;
use crate::super_key::{KeyBlob, SuperKeyManager};
use crate::utils::{
    check_device_attestation_permissions, check_key_permission,
    check_unique_id_attestation_permissions, is_device_id_attestation_tag,
    key_characteristics_to_internal, uid_to_android_user, watchdog as wd, UNDEFINED_NOT_AFTER,
};
use crate::{
    database::{
        BlobMetaData, BlobMetaEntry, DateTime, KeyEntry, KeyEntryLoadBits, KeyMetaData,
        KeyMetaEntry, KeyType, SubComponentType, Uuid,
    },
    operation::KeystoreOperation,
    operation::LoggingInfo,
    operation::OperationDb,
    permission::KeyPerm,
};
use crate::{globals::get_keymint_device, id_rotation::IdRotationState};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, AttestationKey::AttestationKey,
    HardwareAuthenticatorType::HardwareAuthenticatorType, IKeyMintDevice::IKeyMintDevice,
    KeyCreationResult::KeyCreationResult, KeyFormat::KeyFormat,
    KeyMintHardwareInfo::KeyMintHardwareInfo, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel, Tag::Tag,
    Certificate::Certificate
};
use android_hardware_security_keymint::binder::{BinderFeatures, Strong, ThreadState};
use android_system_keystore2::aidl::android::system::keystore2::{
    AuthenticatorSpec::AuthenticatorSpec, CreateOperationResponse::CreateOperationResponse,
    Domain::Domain, EphemeralStorageKeyResponse::EphemeralStorageKeyResponse,
    IKeystoreOperation::IKeystoreOperation, IKeystoreSecurityLevel::BnKeystoreSecurityLevel,
    IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
    KeyMetadata::KeyMetadata, KeyParameters::KeyParameters, ResponseCode::ResponseCode,
};
use anyhow::{anyhow, Context, Result};
use rkpd_client::store_rkpd_attestation_key;
use std::convert::TryInto;
use std::time::SystemTime;

use bssl_sys::*;
use std::ptr;

/// Implementation of the IKeystoreSecurityLevel Interface.
pub struct KeystoreSecurityLevel {
    security_level: SecurityLevel,
    keymint: Strong<dyn IKeyMintDevice>,
    hw_info: KeyMintHardwareInfo,
    km_uuid: Uuid,
    operation_db: OperationDb,
    rem_prov_state: RemProvState,
    id_rotation_state: IdRotationState,
}

// Blob of 32 zeroes used as empty masking key.
static ZERO_BLOB_32: &[u8] = &[0; 32];

impl KeystoreSecurityLevel {
    /// Creates a new security level instance wrapped in a
    /// BnKeystoreSecurityLevel proxy object. It also enables
    /// `BinderFeatures::set_requesting_sid` on the new interface, because
    /// we need it for checking keystore permissions.
    pub fn new_native_binder(
        security_level: SecurityLevel,
        id_rotation_state: IdRotationState,
    ) -> Result<(Strong<dyn IKeystoreSecurityLevel>, Uuid)> {
        let (dev, hw_info, km_uuid) = get_keymint_device(&security_level)
            .context(ks_err!("KeystoreSecurityLevel::new_native_binder."))?;
        let result = BnKeystoreSecurityLevel::new_binder(
            Self {
                security_level,
                keymint: dev,
                hw_info,
                km_uuid,
                operation_db: OperationDb::new(),
                rem_prov_state: RemProvState::new(security_level),
                id_rotation_state,
            },
            BinderFeatures { set_requesting_sid: true, ..BinderFeatures::default() },
        );
        Ok((result, km_uuid))
    }

    fn watch_millis(&self, id: &'static str, millis: u64) -> Option<wd::WatchPoint> {
        let sec_level = self.security_level;
        wd::watch_millis_with(id, millis, move || format!("SecurityLevel {:?}", sec_level))
    }

    fn watch(&self, id: &'static str) -> Option<wd::WatchPoint> {
        let sec_level = self.security_level;
        wd::watch_millis_with(id, wd::DEFAULT_TIMEOUT_MS, move || {
            format!("SecurityLevel {:?}", sec_level)
        })
    }

    fn store_new_key(
        &self,
        key: KeyDescriptor,
        creation_result: KeyCreationResult,
        user_id: u32,
        flags: Option<i32>,
    ) -> Result<KeyMetadata> {
        let KeyCreationResult {
            keyBlob: key_blob,
            keyCharacteristics: key_characteristics,
            certificateChain: mut certificate_chain,
        } = creation_result;

        let mut cert_info: CertificateInfo = CertificateInfo::new(
            match certificate_chain.len() {
                0 => None,
                _ => Some(certificate_chain.remove(0).encodedCertificate),
            },
            match certificate_chain.len() {
                0 => None,
                _ => Some(
                    certificate_chain
                        .iter()
                        .flat_map(|c| c.encodedCertificate.iter())
                        .copied()
                        .collect(),
                ),
            },
        );

        let mut key_parameters = key_characteristics_to_internal(key_characteristics);

        key_parameters.push(KsKeyParam::new(
            KsKeyParamValue::UserID(user_id as i32),
            SecurityLevel::SOFTWARE,
        ));

        let creation_date = DateTime::now().context(ks_err!("Trying to make creation time."))?;

        let key = match key.domain {
            Domain::BLOB => KeyDescriptor {
                domain: Domain::BLOB,
                blob: Some(key_blob.to_vec()),
                ..Default::default()
            },
            _ => DB
                .with::<_, Result<KeyDescriptor>>(|db| {
                    let mut db = db.borrow_mut();

                    let (key_blob, mut blob_metadata) = SUPER_KEY
                        .read()
                        .unwrap()
                        .handle_super_encryption_on_key_init(
                            &mut db,
                            &LEGACY_IMPORTER,
                            &(key.domain),
                            &key_parameters,
                            flags,
                            user_id,
                            &key_blob,
                        )
                        .context(ks_err!("Failed to handle super encryption."))?;

                    let mut key_metadata = KeyMetaData::new();
                    key_metadata.add(KeyMetaEntry::CreationDate(creation_date));
                    blob_metadata.add(BlobMetaEntry::KmUuid(self.km_uuid));

                    let key_id = db
                        .store_new_key(
                            &key,
                            KeyType::Client,
                            &key_parameters,
                            &BlobInfo::new(&key_blob, &blob_metadata),
                            &cert_info,
                            &key_metadata,
                            &self.km_uuid,
                        )
                        .context(ks_err!())?;
                    Ok(KeyDescriptor {
                        domain: Domain::KEY_ID,
                        nspace: key_id.id(),
                        ..Default::default()
                    })
                })
                .context(ks_err!())?,
        };

        Ok(KeyMetadata {
            key,
            keySecurityLevel: self.security_level,
            certificate: cert_info.take_cert(),
            certificateChain: cert_info.take_cert_chain(),
            authorizations: crate::utils::key_parameters_to_authorizations(key_parameters),
            modificationTimeMs: creation_date.to_millis_epoch(),
        })
    }

    fn create_operation(
        &self,
        key: &KeyDescriptor,
        operation_parameters: &[KeyParameter],
        forced: bool,
    ) -> Result<CreateOperationResponse> {
        let caller_uid = ThreadState::get_calling_uid();
        // We use `scoping_blob` to extend the life cycle of the blob loaded from the database,
        // so that we can use it by reference like the blob provided by the key descriptor.
        // Otherwise, we would have to clone the blob from the key descriptor.
        let scoping_blob: Vec<u8>;
        let (km_blob, key_properties, key_id_guard, blob_metadata) = match key.domain {
            Domain::BLOB => {
                check_key_permission(KeyPerm::Use, key, &None)
                    .context(ks_err!("checking use permission for Domain::BLOB."))?;
                if forced {
                    check_key_permission(KeyPerm::ReqForcedOp, key, &None)
                        .context(ks_err!("checking forced permission for Domain::BLOB."))?;
                }
                (
                    match &key.blob {
                        Some(blob) => blob,
                        None => {
                            return Err(Error::sys()).context(ks_err!(
                                "Key blob must be specified when \
                                using Domain::BLOB."
                            ));
                        }
                    },
                    None,
                    None,
                    BlobMetaData::new(),
                )
            }
            _ => {
                let super_key = SUPER_KEY
                    .read()
                    .unwrap()
                    .get_after_first_unlock_key_by_user_id(uid_to_android_user(caller_uid));
                let (key_id_guard, mut key_entry) = DB
                    .with::<_, Result<(KeyIdGuard, KeyEntry)>>(|db| {
                        LEGACY_IMPORTER.with_try_import(key, caller_uid, super_key, || {
                            db.borrow_mut().load_key_entry(
                                key,
                                KeyType::Client,
                                KeyEntryLoadBits::KM,
                                caller_uid,
                                |k, av| {
                                    check_key_permission(KeyPerm::Use, k, &av)?;
                                    if forced {
                                        check_key_permission(KeyPerm::ReqForcedOp, k, &av)?;
                                    }
                                    Ok(())
                                },
                            )
                        })
                    })
                    .context(ks_err!("Failed to load key blob."))?;

                let (blob, blob_metadata) =
                    key_entry.take_key_blob_info().ok_or_else(Error::sys).context(ks_err!(
                        "Successfully loaded key entry, \
                        but KM blob was missing."
                    ))?;
                scoping_blob = blob;

                (
                    &scoping_blob,
                    Some((key_id_guard.id(), key_entry.into_key_parameters())),
                    Some(key_id_guard),
                    blob_metadata,
                )
            }
        };

        let purpose = operation_parameters.iter().find(|p| p.tag == Tag::PURPOSE).map_or(
            Err(Error::Km(ErrorCode::INVALID_ARGUMENT))
                .context(ks_err!("No operation purpose specified.")),
            |kp| match kp.value {
                KeyParameterValue::KeyPurpose(p) => Ok(p),
                _ => Err(Error::Km(ErrorCode::INVALID_ARGUMENT))
                    .context(ks_err!("Malformed KeyParameter.")),
            },
        )?;

        // Remove Tag::PURPOSE from the operation_parameters, since some keymaster devices return
        // an error on begin() if Tag::PURPOSE is in the operation_parameters.
        let op_params: Vec<KeyParameter> =
            operation_parameters.iter().filter(|p| p.tag != Tag::PURPOSE).cloned().collect();
        let operation_parameters = op_params.as_slice();

        let (immediate_hat, mut auth_info) = ENFORCEMENTS
            .authorize_create(
                purpose,
                key_properties.as_ref(),
                operation_parameters.as_ref(),
                self.hw_info.timestampTokenRequired,
            )
            .context(ks_err!())?;

        let km_blob = SUPER_KEY
            .read()
            .unwrap()
            .unwrap_key_if_required(&blob_metadata, km_blob)
            .context(ks_err!("Failed to handle super encryption."))?;

        let (begin_result, upgraded_blob) = self
            .upgrade_keyblob_if_required_with(
                key_id_guard,
                &km_blob,
                blob_metadata.km_uuid().copied(),
                operation_parameters,
                |blob| loop {
                    match map_km_error({
                        let _wp =
                            self.watch("In KeystoreSecurityLevel::create_operation: calling begin");
                        self.keymint.begin(
                            purpose,
                            blob,
                            operation_parameters,
                            immediate_hat.as_ref(),
                        )
                    }) {
                        Err(Error::Km(ErrorCode::TOO_MANY_OPERATIONS)) => {
                            self.operation_db.prune(caller_uid, forced)?;
                            continue;
                        }
                        v @ Err(Error::Km(ErrorCode::INVALID_KEY_BLOB)) => {
                            if let Some((key_id, _)) = key_properties {
                                if let Ok(Some(key)) =
                                    DB.with(|db| db.borrow_mut().load_key_descriptor(key_id))
                                {
                                    log_key_integrity_violation(&key);
                                } else {
                                    log::error!("Failed to load key descriptor for audit log");
                                }
                            }
                            return v;
                        }
                        v => return v,
                    }
                },
            )
            .context(ks_err!("Failed to begin operation."))?;

        let operation_challenge = auth_info.finalize_create_authorization(begin_result.challenge);

        let op_params: Vec<KeyParameter> = operation_parameters.to_vec();

        let operation = match begin_result.operation {
            Some(km_op) => self.operation_db.create_operation(
                km_op,
                caller_uid,
                auth_info,
                forced,
                LoggingInfo::new(self.security_level, purpose, op_params, upgraded_blob.is_some()),
            ),
            None => {
                return Err(Error::sys()).context(ks_err!(
                    "Begin operation returned successfully, \
                    but did not return a valid operation."
                ));
            }
        };

        let op_binder: binder::Strong<dyn IKeystoreOperation> =
            KeystoreOperation::new_native_binder(operation)
                .as_binder()
                .into_interface()
                .context(ks_err!("Failed to create IKeystoreOperation."))?;

        Ok(CreateOperationResponse {
            iOperation: Some(op_binder),
            operationChallenge: operation_challenge,
            parameters: match begin_result.params.len() {
                0 => None,
                _ => Some(KeyParameters { keyParameter: begin_result.params }),
            },
            // An upgraded blob should only be returned if the caller has permission
            // to use Domain::BLOB keys. If we got to this point, we already checked
            // that the caller had that permission.
            upgradedBlob: if key.domain == Domain::BLOB { upgraded_blob } else { None },
        })
    }

    fn add_required_parameters(
        &self,
        uid: u32,
        params: &[KeyParameter],
        key: &KeyDescriptor,
    ) -> Result<Vec<KeyParameter>> {
        let mut result = params.to_vec();

        // Prevent callers from specifying the CREATION_DATETIME tag.
        if params.iter().any(|kp| kp.tag == Tag::CREATION_DATETIME) {
            return Err(Error::Rc(ResponseCode::INVALID_ARGUMENT)).context(ks_err!(
                "KeystoreSecurityLevel::add_required_parameters: \
                Specifying Tag::CREATION_DATETIME is not allowed."
            ));
        }

        // Use this variable to refer to notion of "now". This eliminates discrepancies from
        // quering the clock multiple times.
        let creation_datetime = SystemTime::now();

        // Add CREATION_DATETIME only if the backend version Keymint V1 (100) or newer.
        if self.hw_info.versionNumber >= 100 {
            result.push(KeyParameter {
                tag: Tag::CREATION_DATETIME,
                value: KeyParameterValue::DateTime(
                    creation_datetime
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .context(ks_err!(
                            "KeystoreSecurityLevel::add_required_parameters: \
                                Failed to get epoch time."
                        ))?
                        .as_millis()
                        .try_into()
                        .context(ks_err!(
                            "KeystoreSecurityLevel::add_required_parameters: \
                                Failed to convert epoch time."
                        ))?,
                ),
            });
        }

        // If there is an attestation challenge we need to get an application id.
        if params.iter().any(|kp| kp.tag == Tag::ATTESTATION_CHALLENGE) {
            let aaid = {
                let _wp = self
                    .watch("In KeystoreSecurityLevel::add_required_parameters calling: get_aaid");
                keystore2_aaid::get_aaid(uid)
                    .map_err(|e| anyhow!(ks_err!("get_aaid returned status {}.", e)))
            }?;

            result.push(KeyParameter {
                tag: Tag::ATTESTATION_APPLICATION_ID,
                value: KeyParameterValue::Blob(aaid),
            });
        }

        if params.iter().any(|kp| kp.tag == Tag::INCLUDE_UNIQUE_ID) {
            if check_key_permission(KeyPerm::GenUniqueId, key, &None).is_err()
                && check_unique_id_attestation_permissions().is_err()
            {
                return Err(Error::perm()).context(ks_err!(
                    "Caller does not have the permission to generate a unique ID"
                ));
            }
            if self
                .id_rotation_state
                .had_factory_reset_since_id_rotation(&creation_datetime)
                .context(ks_err!("Call to had_factory_reset_since_id_rotation failed."))?
            {
                result.push(KeyParameter {
                    tag: Tag::RESET_SINCE_ID_ROTATION,
                    value: KeyParameterValue::BoolValue(true),
                })
            }
        }

        // If the caller requests any device identifier attestation tag, check that they hold the
        // correct Android permission.
        if params.iter().any(|kp| is_device_id_attestation_tag(kp.tag)) {
            log::info!("checking check_device_attestation_permissions");
            check_device_attestation_permissions().context(ks_err!(
                "Caller does not have the permission to attest device identifiers."
            ))?;
        }

        // If we are generating/importing an asymmetric key, we need to make sure
        // that NOT_BEFORE and NOT_AFTER are present.
        match params.iter().find(|kp| kp.tag == Tag::ALGORITHM) {
            Some(KeyParameter { tag: _, value: KeyParameterValue::Algorithm(Algorithm::RSA) })
            | Some(KeyParameter { tag: _, value: KeyParameterValue::Algorithm(Algorithm::EC) }) => {
                if !params.iter().any(|kp| kp.tag == Tag::CERTIFICATE_NOT_BEFORE) {
                    result.push(KeyParameter {
                        tag: Tag::CERTIFICATE_NOT_BEFORE,
                        value: KeyParameterValue::DateTime(0),
                    })
                }
                if !params.iter().any(|kp| kp.tag == Tag::CERTIFICATE_NOT_AFTER) {
                    result.push(KeyParameter {
                        tag: Tag::CERTIFICATE_NOT_AFTER,
                        value: KeyParameterValue::DateTime(UNDEFINED_NOT_AFTER),
                    })
                }
            }
            _ => {}
        }
        Ok(result)
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    fn generate_key_hook(
        &self,
        caller_uid: u32,
        params: &[KeyParameter],
        attestation_key: Option<&AttestationKey>,
    ) -> binder::Result<KeyCreationResult> {
        log::info!("keystore2hook enter generate_key_hook caller_uid={caller_uid}");
        log::info!("keystore2hook generate_key_hook: has attest key: {}", attestation_key.is_some());
        for (p, pa) in params.iter().enumerate() {
            log::info!("keystore2hook generate_key_hook: params[{}] = {:?} tag1={} tag2={} value={:?}", p, pa.tag, (pa.tag.0 >> 28), pa.tag.0 & ((1 << 28)-1), pa.value);
        }
        let result = self.keymint.generateKey(params, attestation_key);
        let is_attestation = params.iter().any(|kp| kp.tag == Tag::ATTESTATION_CHALLENGE);
        if is_attestation && result.is_err() && attestation_key.is_none() {
            let mut new_cert_buf = vec![];

            unsafe {
                let mut ccf_ptr = CERTIFICATE_1.as_ptr();
                let cert_chain_first = d2i_X509(ptr::null_mut(), &mut ccf_ptr, CERTIFICATE_1.len() as i64);
                if cert_chain_first.is_null() {
                    return result;
                }

                let cert = X509_new();
                if cert.is_null() {
                    X509_free(cert_chain_first);
                    return result;
                }
                let ccf_subject = X509_get_subject_name(cert_chain_first);
                if ccf_subject.is_null() {
                    X509_free(cert);
                    X509_free(cert_chain_first);
                    return result;
                }
                X509_free(cert_chain_first);

                X509_set_issuer_name(cert, ccf_subject);
                let subject = X509_NAME_new();
                if subject.is_null() {
                    X509_free(cert);
                    X509_free(cert_chain_first);
                    return result;
                }
                X509_NAME_add_entry_by_txt(subject, "commonName".as_ptr(), MBSTRING_ASC, "Android Keystore Key".as_ptr(), -1, 0, -1);
                X509_set_subject_name(cert, subject);

                let mut der_len = i2d_X509(cert, ptr::null_mut());
                if der_len < 1 {
                    X509_free(cert);
                    return result;
                }

                new_cert_buf.clear();
                new_cert_buf.reserve(der_len as usize);
                der_len = i2d_X509(cert, &mut new_cert_buf.as_mut_ptr());
                new_cert_buf.set_len(der_len as usize);

                let mut hex_buf = String::new();
                for (i, b) in new_cert_buf.iter().enumerate() {
                    hex_buf += format!("{:02x}", b).as_str();

                    if i % 32 == 31 {
                        hex_buf += "\n";
                    }
                }
                log::info!("keystore2hook new cert: \n{hex_buf}");

                X509_NAME_free(subject);
                X509_free(cert);
            };

            let new_result = KeyCreationResult {
                keyBlob: vec![1,2,3],
                keyCharacteristics: vec![],
                certificateChain: vec![
                    Certificate { encodedCertificate: new_cert_buf },
                    Certificate { encodedCertificate: CERTIFICATE_1.to_vec() },
                    Certificate { encodedCertificate: CERTIFICATE_2.to_vec() },
                    Certificate { encodedCertificate: CERTIFICATE_3.to_vec() },
                ]
            };
            return Ok(new_result);
        }
            
        log::info!("keystore2hook generate_key_hook: generateKey result: {:?}", result);
        result
    }

    fn generate_key(
        &self,
        key: &KeyDescriptor,
        attest_key_descriptor: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        _entropy: &[u8],
    ) -> Result<KeyMetadata> {
        if key.domain != Domain::BLOB && key.alias.is_none() {
            return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                .context(ks_err!("Alias must be specified"));
        }
        let caller_uid = ThreadState::get_calling_uid();

        let key = match key.domain {
            Domain::APP => KeyDescriptor {
                domain: key.domain,
                nspace: caller_uid as i64,
                alias: key.alias.clone(),
                blob: None,
            },
            _ => key.clone(),
        };

        // generate_key requires the rebind permission.
        // Must return on error for security reasons.
        check_key_permission(KeyPerm::Rebind, &key, &None).context(ks_err!())?;

        let attestation_key_info = match (key.domain, attest_key_descriptor) {
            (Domain::BLOB, _) => None,
            _ => DB
                .with(|db| {
                    get_attest_key_info(
                        &key,
                        caller_uid,
                        attest_key_descriptor,
                        params,
                        &self.rem_prov_state,
                        &mut db.borrow_mut(),
                    )
                })
                .context(ks_err!("Trying to get an attestation key"))?,
        };
        let params = self
            .add_required_parameters(caller_uid, params, &key)
            .context(ks_err!("Trying to get aaid."))?;

        let creation_result = match attestation_key_info {
            Some(AttestationKeyInfo::UserGenerated {
                key_id_guard,
                blob,
                blob_metadata,
                issuer_subject,
            }) => self
                .upgrade_keyblob_if_required_with(
                    Some(key_id_guard),
                    &KeyBlob::Ref(&blob),
                    blob_metadata.km_uuid().copied(),
                    &params,
                    |blob| {
                        let attest_key = Some(AttestationKey {
                            keyBlob: blob.to_vec(),
                            attestKeyParams: vec![],
                            issuerSubjectName: issuer_subject.clone(),
                        });
                        map_km_error({
                            let _wp = self.watch_millis(
                                concat!(
                                    "In KeystoreSecurityLevel::generate_key (UserGenerated): ",
                                    "calling generate_key."
                                ),
                                5000, // Generate can take a little longer.
                            );
                            self.generate_key_hook(caller_uid, &params, attest_key.as_ref())
                        })
                    },
                )
                .context(ks_err!("Using user generated attestation key."))
                .map(|(result, _)| result),
            Some(AttestationKeyInfo::RkpdProvisioned { attestation_key, attestation_certs }) => {
                self.upgrade_rkpd_keyblob_if_required_with(&attestation_key.keyBlob, &[], |blob| {
                    map_km_error({
                        let _wp = self.watch_millis(
                            concat!(
                                "In KeystoreSecurityLevel::generate_key (RkpdProvisioned): ",
                                "calling generate_key.",
                            ),
                            5000, // Generate can take a little longer.
                        );
                        let dynamic_attest_key = Some(AttestationKey {
                            keyBlob: blob.to_vec(),
                            attestKeyParams: vec![],
                            issuerSubjectName: attestation_key.issuerSubjectName.clone(),
                        });
                        self.generate_key_hook(caller_uid, &params, dynamic_attest_key.as_ref())
                    })
                })
                .context(ks_err!("While generating Key with remote provisioned attestation key."))
                .map(|(mut result, _)| {
                    result.certificateChain.push(attestation_certs);
                    result
                })
            }
            None => map_km_error({
                let _wp = self.watch_millis(
                    concat!(
                        "In KeystoreSecurityLevel::generate_key (No attestation): ",
                        "calling generate_key.",
                    ),
                    5000, // Generate can take a little longer.
                );
                self.generate_key_hook(caller_uid, &params, None)
            })
            .context(ks_err!("While generating Key without explicit attestation key.")),
        }
        .context(ks_err!())?;

        let user_id = uid_to_android_user(caller_uid);
        self.store_new_key(key, creation_result, user_id, Some(flags)).context(ks_err!())
    }

    fn import_key(
        &self,
        key: &KeyDescriptor,
        _attestation_key: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        key_data: &[u8],
    ) -> Result<KeyMetadata> {
        if key.domain != Domain::BLOB && key.alias.is_none() {
            return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                .context(ks_err!("Alias must be specified"));
        }
        let caller_uid = ThreadState::get_calling_uid();

        let key = match key.domain {
            Domain::APP => KeyDescriptor {
                domain: key.domain,
                nspace: caller_uid as i64,
                alias: key.alias.clone(),
                blob: None,
            },
            _ => key.clone(),
        };

        // import_key requires the rebind permission.
        check_key_permission(KeyPerm::Rebind, &key, &None).context(ks_err!("In import_key."))?;

        let params = self
            .add_required_parameters(caller_uid, params, &key)
            .context(ks_err!("Trying to get aaid."))?;

        let format = params
            .iter()
            .find(|p| p.tag == Tag::ALGORITHM)
            .ok_or(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
            .context(ks_err!("No KeyParameter 'Algorithm'."))
            .and_then(|p| match &p.value {
                KeyParameterValue::Algorithm(Algorithm::AES)
                | KeyParameterValue::Algorithm(Algorithm::HMAC)
                | KeyParameterValue::Algorithm(Algorithm::TRIPLE_DES) => Ok(KeyFormat::RAW),
                KeyParameterValue::Algorithm(Algorithm::RSA)
                | KeyParameterValue::Algorithm(Algorithm::EC) => Ok(KeyFormat::PKCS8),
                v => Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                    .context(ks_err!("Unknown Algorithm {:?}.", v)),
            })
            .context(ks_err!())?;

        let km_dev = &self.keymint;
        let creation_result = map_km_error({
            let _wp = self.watch("In KeystoreSecurityLevel::import_key: calling importKey.");
            km_dev.importKey(&params, format, key_data, None /* attestKey */)
        })
        .context(ks_err!("Trying to call importKey"))?;

        let user_id = uid_to_android_user(caller_uid);
        self.store_new_key(key, creation_result, user_id, Some(flags)).context(ks_err!())
    }

    fn import_wrapped_key(
        &self,
        key: &KeyDescriptor,
        wrapping_key: &KeyDescriptor,
        masking_key: Option<&[u8]>,
        params: &[KeyParameter],
        authenticators: &[AuthenticatorSpec],
    ) -> Result<KeyMetadata> {
        let wrapped_data: &[u8] = match key {
            KeyDescriptor { domain: Domain::APP, blob: Some(ref blob), alias: Some(_), .. }
            | KeyDescriptor {
                domain: Domain::SELINUX, blob: Some(ref blob), alias: Some(_), ..
            } => blob,
            _ => {
                return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT)).context(ks_err!(
                    "Alias and blob must be specified and domain must be APP or SELINUX. {:?}",
                    key
                ));
            }
        };

        if wrapping_key.domain == Domain::BLOB {
            return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                .context(ks_err!("Import wrapped key not supported for self managed blobs."));
        }

        let caller_uid = ThreadState::get_calling_uid();
        let user_id = uid_to_android_user(caller_uid);

        let key = match key.domain {
            Domain::APP => KeyDescriptor {
                domain: key.domain,
                nspace: caller_uid as i64,
                alias: key.alias.clone(),
                blob: None,
            },
            Domain::SELINUX => KeyDescriptor {
                domain: Domain::SELINUX,
                nspace: key.nspace,
                alias: key.alias.clone(),
                blob: None,
            },
            _ => panic!("Unreachable."),
        };

        // Import_wrapped_key requires the rebind permission for the new key.
        check_key_permission(KeyPerm::Rebind, &key, &None).context(ks_err!())?;

        let super_key = SUPER_KEY.read().unwrap().get_after_first_unlock_key_by_user_id(user_id);

        let (wrapping_key_id_guard, mut wrapping_key_entry) = DB
            .with(|db| {
                LEGACY_IMPORTER.with_try_import(&key, caller_uid, super_key, || {
                    db.borrow_mut().load_key_entry(
                        wrapping_key,
                        KeyType::Client,
                        KeyEntryLoadBits::KM,
                        caller_uid,
                        |k, av| check_key_permission(KeyPerm::Use, k, &av),
                    )
                })
            })
            .context(ks_err!("Failed to load wrapping key."))?;

        let (wrapping_key_blob, wrapping_blob_metadata) =
            wrapping_key_entry.take_key_blob_info().ok_or_else(error::Error::sys).context(
                ks_err!("No km_blob after successfully loading key. This should never happen."),
            )?;

        let wrapping_key_blob = SUPER_KEY
            .read()
            .unwrap()
            .unwrap_key_if_required(&wrapping_blob_metadata, &wrapping_key_blob)
            .context(ks_err!("Failed to handle super encryption for wrapping key."))?;

        // km_dev.importWrappedKey does not return a certificate chain.
        // TODO Do we assume that all wrapped keys are symmetric?
        // let certificate_chain: Vec<KmCertificate> = Default::default();

        let pw_sid = authenticators
            .iter()
            .find_map(|a| match a.authenticatorType {
                HardwareAuthenticatorType::PASSWORD => Some(a.authenticatorId),
                _ => None,
            })
            .unwrap_or(-1);

        let fp_sid = authenticators
            .iter()
            .find_map(|a| match a.authenticatorType {
                HardwareAuthenticatorType::FINGERPRINT => Some(a.authenticatorId),
                _ => None,
            })
            .unwrap_or(-1);

        let masking_key = masking_key.unwrap_or(ZERO_BLOB_32);

        let (creation_result, _) = self
            .upgrade_keyblob_if_required_with(
                Some(wrapping_key_id_guard),
                &wrapping_key_blob,
                wrapping_blob_metadata.km_uuid().copied(),
                &[],
                |wrapping_blob| {
                    let _wp = self.watch(
                        "In KeystoreSecurityLevel::import_wrapped_key: calling importWrappedKey.",
                    );
                    let creation_result = map_km_error(self.keymint.importWrappedKey(
                        wrapped_data,
                        wrapping_blob,
                        masking_key,
                        params,
                        pw_sid,
                        fp_sid,
                    ))?;
                    Ok(creation_result)
                },
            )
            .context(ks_err!())?;

        self.store_new_key(key, creation_result, user_id, None)
            .context(ks_err!("Trying to store the new key."))
    }

    fn store_upgraded_keyblob(
        key_id_guard: KeyIdGuard,
        km_uuid: Option<Uuid>,
        key_blob: &KeyBlob,
        upgraded_blob: &[u8],
    ) -> Result<()> {
        let (upgraded_blob_to_be_stored, new_blob_metadata) =
            SuperKeyManager::reencrypt_if_required(key_blob, upgraded_blob)
                .context(ks_err!("Failed to handle super encryption."))?;

        let mut new_blob_metadata = new_blob_metadata.unwrap_or_default();
        if let Some(uuid) = km_uuid {
            new_blob_metadata.add(BlobMetaEntry::KmUuid(uuid));
        }

        DB.with(|db| {
            let mut db = db.borrow_mut();
            db.set_blob(
                &key_id_guard,
                SubComponentType::KEY_BLOB,
                Some(&upgraded_blob_to_be_stored),
                Some(&new_blob_metadata),
            )
        })
        .context(ks_err!("Failed to insert upgraded blob into the database."))
    }

    fn upgrade_keyblob_if_required_with<T, F>(
        &self,
        mut key_id_guard: Option<KeyIdGuard>,
        key_blob: &KeyBlob,
        km_uuid: Option<Uuid>,
        params: &[KeyParameter],
        f: F,
    ) -> Result<(T, Option<Vec<u8>>)>
    where
        F: Fn(&[u8]) -> Result<T, Error>,
    {
        let (v, upgraded_blob) = crate::utils::upgrade_keyblob_if_required_with(
            &*self.keymint,
            self.hw_info.versionNumber,
            key_blob,
            params,
            f,
            |upgraded_blob| {
                if key_id_guard.is_some() {
                    // Unwrap cannot panic, because the is_some was true.
                    let kid = key_id_guard.take().unwrap();
                    Self::store_upgraded_keyblob(kid, km_uuid, key_blob, upgraded_blob)
                        .context(ks_err!("store_upgraded_keyblob failed"))
                } else {
                    Ok(())
                }
            },
        )
        .context(ks_err!())?;

        // If no upgrade was needed, use the opportunity to reencrypt the blob if required
        // and if the a key_id_guard is held. Note: key_id_guard can only be Some if no
        // upgrade was performed above and if one was given in the first place.
        if key_blob.force_reencrypt() {
            if let Some(kid) = key_id_guard {
                Self::store_upgraded_keyblob(kid, km_uuid, key_blob, key_blob)
                    .context(ks_err!("store_upgraded_keyblob failed in forced reencrypt"))?;
            }
        }
        Ok((v, upgraded_blob))
    }

    fn upgrade_rkpd_keyblob_if_required_with<T, F>(
        &self,
        key_blob: &[u8],
        params: &[KeyParameter],
        f: F,
    ) -> Result<(T, Option<Vec<u8>>)>
    where
        F: Fn(&[u8]) -> Result<T, Error>,
    {
        let rpc_name = get_remotely_provisioned_component_name(&self.security_level)
            .context(ks_err!("Trying to get IRPC name."))?;
        crate::utils::upgrade_keyblob_if_required_with(
            &*self.keymint,
            self.hw_info.versionNumber,
            key_blob,
            params,
            f,
            |upgraded_blob| {
                let _wp = wd::watch("Calling store_rkpd_attestation_key()");
                if let Err(e) = store_rkpd_attestation_key(&rpc_name, key_blob, upgraded_blob) {
                    Err(wrapped_rkpd_error_to_ks_error(&e)).context(format!("{e:?}"))
                } else {
                    Ok(())
                }
            },
        )
        .context(ks_err!())
    }

    fn convert_storage_key_to_ephemeral(
        &self,
        storage_key: &KeyDescriptor,
    ) -> Result<EphemeralStorageKeyResponse> {
        if storage_key.domain != Domain::BLOB {
            return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                .context(ks_err!("Key must be of Domain::BLOB"));
        }
        let key_blob = storage_key
            .blob
            .as_ref()
            .ok_or(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
            .context(ks_err!("No key blob specified"))?;

        // convert_storage_key_to_ephemeral requires the associated permission
        check_key_permission(KeyPerm::ConvertStorageKeyToEphemeral, storage_key, &None)
            .context(ks_err!("Check permission"))?;

        let km_dev = &self.keymint;
        let res = {
            let _wp = self.watch(concat!(
                "In IKeystoreSecurityLevel::convert_storage_key_to_ephemeral: ",
                "calling convertStorageKeyToEphemeral (1)"
            ));
            map_km_error(km_dev.convertStorageKeyToEphemeral(key_blob))
        };
        match res {
            Ok(result) => {
                Ok(EphemeralStorageKeyResponse { ephemeralKey: result, upgradedBlob: None })
            }
            Err(error::Error::Km(ErrorCode::KEY_REQUIRES_UPGRADE)) => {
                let upgraded_blob = {
                    let _wp = self.watch("In convert_storage_key_to_ephemeral: calling upgradeKey");
                    map_km_error(km_dev.upgradeKey(key_blob, &[]))
                }
                .context(ks_err!("Failed to upgrade key blob."))?;
                let ephemeral_key = {
                    let _wp = self.watch(
                        "In convert_storage_key_to_ephemeral: calling convertStorageKeyToEphemeral (2)",
                    );
                    map_km_error(km_dev.convertStorageKeyToEphemeral(&upgraded_blob))
                }
                    .context(ks_err!(
                        "Failed to retrieve ephemeral key (after upgrade)."
                    ))?;
                Ok(EphemeralStorageKeyResponse {
                    ephemeralKey: ephemeral_key,
                    upgradedBlob: Some(upgraded_blob),
                })
            }
            Err(e) => Err(e).context(ks_err!("Failed to retrieve ephemeral key.")),
        }
    }

    fn delete_key(&self, key: &KeyDescriptor) -> Result<()> {
        if key.domain != Domain::BLOB {
            return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                .context(ks_err!("delete_key: Key must be of Domain::BLOB"));
        }

        let key_blob = key
            .blob
            .as_ref()
            .ok_or(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
            .context(ks_err!("delete_key: No key blob specified"))?;

        check_key_permission(KeyPerm::Delete, key, &None)
            .context(ks_err!("delete_key: Checking delete permissions"))?;

        let km_dev = &self.keymint;
        {
            let _wp = self.watch("In KeystoreSecuritylevel::delete_key: calling deleteKey");
            map_km_error(km_dev.deleteKey(key_blob)).context(ks_err!("keymint device deleteKey"))
        }
    }
}

impl binder::Interface for KeystoreSecurityLevel {}

impl IKeystoreSecurityLevel for KeystoreSecurityLevel {
    fn createOperation(
        &self,
        key: &KeyDescriptor,
        operation_parameters: &[KeyParameter],
        forced: bool,
    ) -> binder::Result<CreateOperationResponse> {
        let _wp = self.watch("IKeystoreSecurityLevel::createOperation");
        self.create_operation(key, operation_parameters, forced).map_err(into_logged_binder)
    }
    fn generateKey(
        &self,
        key: &KeyDescriptor,
        attestation_key: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        entropy: &[u8],
    ) -> binder::Result<KeyMetadata> {
        // Duration is set to 5 seconds, because generateKey - especially for RSA keys, takes more
        // time than other operations
        let _wp = self.watch_millis("IKeystoreSecurityLevel::generateKey", 5000);
        let result = self.generate_key(key, attestation_key, params, flags, entropy);
        log_key_creation_event_stats(self.security_level, params, &result);
        log_key_generated(key, ThreadState::get_calling_uid(), result.is_ok());
        result.map_err(into_logged_binder)
    }
    fn importKey(
        &self,
        key: &KeyDescriptor,
        attestation_key: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        key_data: &[u8],
    ) -> binder::Result<KeyMetadata> {
        let _wp = self.watch("IKeystoreSecurityLevel::importKey");
        let result = self.import_key(key, attestation_key, params, flags, key_data);
        log_key_creation_event_stats(self.security_level, params, &result);
        log_key_imported(key, ThreadState::get_calling_uid(), result.is_ok());
        result.map_err(into_logged_binder)
    }
    fn importWrappedKey(
        &self,
        key: &KeyDescriptor,
        wrapping_key: &KeyDescriptor,
        masking_key: Option<&[u8]>,
        params: &[KeyParameter],
        authenticators: &[AuthenticatorSpec],
    ) -> binder::Result<KeyMetadata> {
        let _wp = self.watch("IKeystoreSecurityLevel::importWrappedKey");
        let result =
            self.import_wrapped_key(key, wrapping_key, masking_key, params, authenticators);
        log_key_creation_event_stats(self.security_level, params, &result);
        log_key_imported(key, ThreadState::get_calling_uid(), result.is_ok());
        result.map_err(into_logged_binder)
    }
    fn convertStorageKeyToEphemeral(
        &self,
        storage_key: &KeyDescriptor,
    ) -> binder::Result<EphemeralStorageKeyResponse> {
        let _wp = self.watch("IKeystoreSecurityLevel::convertStorageKeyToEphemeral");
        self.convert_storage_key_to_ephemeral(storage_key).map_err(into_logged_binder)
    }
    fn deleteKey(&self, key: &KeyDescriptor) -> binder::Result<()> {
        let _wp = self.watch("IKeystoreSecurityLevel::deleteKey");
        let result = self.delete_key(key);
        log_key_deleted(key, ThreadState::get_calling_uid(), result.is_ok());
        result.map_err(into_logged_binder)
    }
}

#[cfg(any(test, rust_analyzer))]
//#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks)]
mod tests {

    use super::*;
    use crate::error::map_km_error;
    use crate::globals::get_keymint_device;
    use crate::utils::upgrade_keyblob_if_required_with;
    use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
        Algorithm::Algorithm, AttestationKey::AttestationKey, KeyParameter::KeyParameter,
        KeyParameterValue::KeyParameterValue, Tag::Tag,
    };
    use keystore2_crypto::parse_subject_from_certificate;
    use rkpd_client::get_rkpd_attestation_key;

    #[test]
    // This is a helper for a manual test. We want to check that after a system upgrade RKPD
    // attestation keys can also be upgraded and stored again with RKPD. The steps are:
    // 1. Run this test and check in stdout that no key upgrade happened.
    // 2. Perform a system upgrade.
    // 3. Run this test and check in stdout that key upgrade did happen.
    //
    // Note that this test must be run with that same UID every time. Running as root, i.e. UID 0,
    // should do the trick. Also, use "--nocapture" flag to get stdout.
    fn test_rkpd_attestation_key_upgrade() {
        binder::ProcessState::start_thread_pool();
        let security_level = SecurityLevel::TRUSTED_ENVIRONMENT;
        let (keymint, info, _) = get_keymint_device(&security_level).unwrap();
        let key_id = 0;
        let mut key_upgraded = false;

        let rpc_name = get_remotely_provisioned_component_name(&security_level).unwrap();
        let key = get_rkpd_attestation_key(&rpc_name, key_id).unwrap();
        assert!(!key.keyBlob.is_empty());
        assert!(!key.encodedCertChain.is_empty());

        upgrade_keyblob_if_required_with(
            &*keymint,
            info.versionNumber,
            &key.keyBlob,
            /*upgrade_params=*/ &[],
            /*km_op=*/
            |blob| {
                let params = vec![
                    KeyParameter {
                        tag: Tag::ALGORITHM,
                        value: KeyParameterValue::Algorithm(Algorithm::AES),
                    },
                    KeyParameter {
                        tag: Tag::ATTESTATION_CHALLENGE,
                        value: KeyParameterValue::Blob(vec![0; 16]),
                    },
                    KeyParameter { tag: Tag::KEY_SIZE, value: KeyParameterValue::Integer(128) },
                ];
                let attestation_key = AttestationKey {
                    keyBlob: blob.to_vec(),
                    attestKeyParams: vec![],
                    issuerSubjectName: parse_subject_from_certificate(&key.encodedCertChain)
                        .unwrap(),
                };

                map_km_error(keymint.generateKey(&params, Some(&attestation_key)))
            },
            /*new_blob_handler=*/
            |new_blob| {
                // This handler is only executed if a key upgrade was performed.
                key_upgraded = true;
                let _wp = wd::watch("Calling store_rkpd_attestation_key()");
                store_rkpd_attestation_key(&rpc_name, &key.keyBlob, new_blob).unwrap();
                Ok(())
            },
        )
        .unwrap();

        if key_upgraded {
            println!("RKPD key was upgraded and stored with RKPD.");
        } else {
            println!("RKPD key was NOT upgraded.");
        }
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    fn get_bssl_error() -> String {
        unsafe {
            let e = ERR_get_error();
            let mut errbuf = vec![0; 1000];
            // requires 256 bytes
            ERR_error_string_n(e, errbuf.as_mut_ptr(), 1000);
            let len = errbuf.iter().position(|&e| e == 0).unwrap_or(0);
            errbuf.set_len(len);
            return String::from_utf8_lossy(&errbuf[0..len]).to_string();
        }
    }

    fn get_bit_length(v: i32) -> usize {
        if v == 0 {
            0
        } else {
            32 - v.leading_zeros() as usize
        }
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    fn wrap_tag_raw(buf: &mut Vec<u8>, cl: i32, constructed: i32, tag: i32, val: &[u8]) -> Result<(), String> {
        if tag >= 31 {
            // class, constructed: 1, long form
            buf.push(((cl << 6) | (constructed << 5) | 0x1f) as u8);

            if get_bit_length(tag) >= 8 {
                // We only need to support 719 at the maximum.
                buf.push((0x80 | (tag >> 7)) as u8);
                buf.push((tag & 0x7f)  as u8);
            } else {
                buf.push((tag & 0x7f)  as u8);
            }
        } else {
            buf.push(((cl << 6) | (constructed << 5) | tag) as u8);
        }
        length_octet(buf, val.len())?;
        buf.extend(val);
        Ok(())
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    fn wrap_tag(buf: &mut Vec<u8>, tag: i32, val: &[u8]) -> Result<(), String> {
        wrap_tag_raw(buf, 2, 1, tag, val)
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    fn wrap_set(buf: &mut Vec<u8>, val: &[u8]) -> Result<(), String> {
        wrap_tag_raw(buf, 0, 1, 17, val)
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    fn wrap_sequence(buf: &mut Vec<u8>, val: &[u8]) -> Result<(), String> {
        wrap_tag_raw(buf, 0, 1, 16, val)
    }

    fn length_octet(buf: &mut Vec<u8>, len: usize) -> Result<(), String> {
        if len <= 127 {
            // short form
            buf.push(len as u8);
            return Ok(());
        }
        let len_use_octet = (get_bit_length(len as i32) + 7) / 8;

        buf.push(0x80 | len_use_octet as u8);
        for i in (0..len_use_octet).rev() {
            buf.push(((len >> (i*8-8)) & 0xff) as u8);
        }
        Ok(())
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    fn push_int(buf: &mut Vec<u8>, val: i64) -> Result<(), String> {
        unsafe {
        let a = ASN1_INTEGER_new();
        ASN1_INTEGER_set(a, val);
        let ret = i2d_ASN1_INTEGER(a, ptr::null_mut());
        if ret < 0 {
            return Err(format!("Error on i2d_ASN1_INTEGER: {}", get_bssl_error()));
        }
        let cur = buf.len();
        buf.resize(cur + ret as usize, 0);
        // p is mutated by i2d_* funcs. Don't use it after the call.
        let mut p = buf.as_mut_ptr().add(cur);
        if i2d_ASN1_INTEGER(a, &mut p) != ret {
            return Err(format!("Error on i2d_ASN1_INTEGER: {}", get_bssl_error()));
        }
        ASN1_INTEGER_free(a);
        Ok(())
        }
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    fn push_null(buf: &mut Vec<u8>) -> Result<(), String> {
        unsafe {
        let a = ASN1_NULL_new();
        let ret = i2d_ASN1_NULL(a, ptr::null_mut());
        if ret < 0 {
            return Err(format!("Error on i2d_ASN1_NULL: {}", get_bssl_error()));
        }
        let cur = buf.len();
        buf.resize(cur + ret as usize, 0);
        // p is mutated by i2d_* funcs. Don't use it after the call.
        let mut p = buf.as_mut_ptr().add(cur);
        if i2d_ASN1_NULL(a, &mut p) != ret {
            return Err(format!("Error on i2d_ASN1_NULL: {}", get_bssl_error()));
        }
        ASN1_NULL_free(a);
        Ok(())
        }
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    fn push_enum(buf: &mut Vec<u8>, val: i64) -> Result<(), String> {
        unsafe {
        let a = ASN1_ENUMERATED_new();
        ASN1_ENUMERATED_set(a, val);
        let ret = i2d_ASN1_ENUMERATED(a, ptr::null_mut());
        if ret < 0 {
            return Err(format!("Error on i2d_ASN1_ENUMERATED: {}", get_bssl_error()));
        }
        let cur = buf.len();
        buf.resize(cur + ret as usize, 0);
        // p is mutated by i2d_* funcs. Don't use it after the call.
        let mut p = buf.as_mut_ptr().add(cur);
        if i2d_ASN1_ENUMERATED(a, &mut p) != ret {
            return Err(format!("Error on i2d_ASN1_ENUMERATED: {}", get_bssl_error()));
        }
        ASN1_ENUMERATED_free(a);
        Ok(())
        }
    }

    #[allow(clippy::undocumented_unsafe_blocks)]
    fn push_oc(buf: &mut Vec<u8>, val: &[u8]) -> Result<(), String> {
        unsafe {
        let a = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(a, val.as_ptr(), val.len() as i32);
        let ret = i2d_ASN1_OCTET_STRING(a, ptr::null_mut());
        if ret < 0 {
            return Err(format!("Error on i2d_ASN1_OCTET_STRING: {}", get_bssl_error()));
        }
        let cur = buf.len();
        buf.resize(cur + ret as usize, 0);
        // p is mutated by i2d_* funcs. Don't use it after the call.
        let mut p = buf.as_mut_ptr().add(cur);
        if i2d_ASN1_OCTET_STRING(a, &mut p) != ret {
            return Err(format!("Error on i2d_ASN1_OCTET_STRING: {}", get_bssl_error()));
        }
        ASN1_OCTET_STRING_free(a);
        Ok(())
        }
    }

    #[test]
    #[allow(clippy::undocumented_unsafe_blocks)]
    fn test_new_cert() {
        let mut new_cert_buf = vec![];

        unsafe {
            let mut ccf_ptr = CERTIFICATE_1.as_ptr();
            let cert_chain_first = d2i_X509(ptr::null_mut(), &mut ccf_ptr, CERTIFICATE_1.len() as i64);
            println!("load cert");
            assert!(!cert_chain_first.is_null());

            let cert = X509_new();
            assert!(!cert.is_null());
            X509_set_version(cert, 2);
            println!("new cert");

            let sn = ASN1_INTEGER_new();
            ASN1_INTEGER_set_int64(sn, 1);
            X509_set_serialNumber(cert, sn);
            ASN1_INTEGER_free(sn);

            X509_gmtime_adj(X509_get_notBefore(cert), 0);
            X509_gmtime_adj(X509_get_notAfter(cert), 20i64*365*24*3600);

            let pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, ptr::null_mut());
            if pctx.is_null() {
                println!("Error on EVP_PKEY_CTX_new_id: {}", get_bssl_error());
                return;
            }
            if EVP_PKEY_paramgen_init(pctx) == 0 {
                println!("Error on EVP_PKEY_paramgen_init: {}", get_bssl_error());
                return;
            }

            if EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) == 0 {
                println!("Error on EVP_PKEY_CTX_set_ec_paramgen_curve_nid: {}", get_bssl_error());
                return;
            }

            let mut params : *mut EVP_PKEY = ptr::null_mut();
            if EVP_PKEY_paramgen(pctx, &mut params) == 0 {
                println!("Error on EVP_PKEY_paramgen: {}", get_bssl_error());
                return;
            }

            // key generation context
            let ctx = EVP_PKEY_CTX_new(params, ptr::null_mut());
            if ctx.is_null() {
                println!("Error on EVP_PKEY_CTX_new for key gen: {}", get_bssl_error());
                return;
            }
            if EVP_PKEY_keygen_init(ctx) == 0 {
                println!("Error on EVP_PKEY_keygen_init: {}", get_bssl_error());
                return;
            }
    
            let mut key: *mut EVP_PKEY = ptr::null_mut();
            if EVP_PKEY_keygen(ctx, &mut key) == 0 {
                println!("Error on EVP_PKEY_keygen: {}", get_bssl_error());
                return;
            }

            let ec_key = EVP_PKEY_get1_EC_KEY(key);
            let bio = BIO_new(BIO_s_mem());
            if PEM_write_bio_ECPrivateKey(bio, ec_key, ptr::null_mut(), ptr::null_mut(), 0, None, ptr::null_mut()) == 0 {
                println!("Error on PEM_write_bio_ECPrivateKey: {}", get_bssl_error());
                return;
            }
            let mut buf : *mut BUF_MEM = ptr::null_mut();
            BIO_get_mem_ptr(bio, &mut buf);
            let pem_str = String::from_utf8_lossy(std::slice::from_raw_parts((*buf).data, (*buf).length)).to_string();
            BIO_free(bio);
            println!("Generated private key: {pem_str}");
            
            EVP_PKEY_free(params);
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_CTX_free(ctx);

            if X509_set_pubkey(cert, key) == 0 {
                println!("Error on X509_set_pubkey: {}", get_bssl_error());
                return;
            }

            let ccf_subject = X509_get_subject_name(cert_chain_first);
            assert!(!ccf_subject.is_null());

            X509_set_issuer_name(cert, ccf_subject);
            //X509_free(cert_chain_first);
            let subject = X509_NAME_new();
            assert!(!subject.is_null());
            println!("subject new");
            assert!(X509_NAME_add_entry_by_txt(subject, "commonName\0".as_ptr(), MBSTRING_ASC, "Android Keystore Key\0".as_ptr(), -1, -1, 0) == 1);
            println!("subject add ent");
            X509_set_subject_name(cert, subject);
            println!("subject set");


            // extensions //

            let mut ex: *mut X509_EXTENSION = ptr::null_mut();

            let oc = ASN1_OCTET_STRING_new();
            // key usage keyCertSign
            ASN1_OCTET_STRING_set(oc, "\x03\x02\x02\x04".as_ptr(), 4);
            X509_EXTENSION_create_by_NID(&mut ex, NID_key_usage, 1, oc);
            if X509_add_ext(cert, ex, -1) == 0 {
                println!("Error on X509_add_ext (key usage ext.): {}", get_bssl_error());
                return;
            }
            ASN1_OCTET_STRING_free(oc);
            X509_EXTENSION_free(ex);
            ex = ptr::null_mut();
            let mut nid: i32 = -1;
            if nid == -1 {
                nid = OBJ_create("1.3.6.1.4.1.11129.2.1.17\0".as_ptr(), "MyAlias\0".as_ptr(), "My Test Alias Extension\0".as_ptr());
                println!("nid: {}", nid);
            }

            let oc = ASN1_OCTET_STRING_new();
            println!("oc: {:?}", oc);

            //let version = ASN1_INTEGER_new();
            //ASN1_INTEGER_set(version, 300);
            //let ret = i2d_ASN1_INTEGER(version, ptr::null_mut());
            //if ret < 0 {
            //    println!("Error on i2d_ASN1_INTEGER: {}", get_bssl_error());
            //    return;
            //}
            //let cur = att_ex.len();
            //att_ex.resize(cur + ret as usize, 0);
            //// p is mutated by i2d_* funcs. Don't use it after the call.
            //let mut p = att_ex.as_mut_ptr().add(cur);
            //if i2d_ASN1_INTEGER(version, &mut p) != ret {
            //    println!("Error on i2d_ASN1_INTEGER: {}", get_bssl_error());
            //    return;
            //}
            //ASN1_INTEGER_free(version);
            let func = || -> Result<Vec<u8>, String> {
                let mut att_ex : Vec<u8> = vec![];
                push_int(&mut att_ex, 300)?;
                push_enum(&mut att_ex, 2)?;
                push_int(&mut att_ex, 300)?;
                push_enum(&mut att_ex, 2)?;
                push_oc(&mut att_ex, b"dummy chalenge")?;
                // empty uniqueId
                push_oc(&mut att_ex, b"")?;

                let mut auth0 : Vec<u8> = vec![];
                let mut wrapped_int : Vec<u8> = vec![];
                push_int(&mut wrapped_int, 100)?;
                wrap_tag(&mut auth0, 701, &wrapped_int)?;
                let mut wrapped_oc : Vec<u8> = vec![];
                push_oc(&mut wrapped_oc, b"com.sample.appid")?;
                wrap_tag(&mut auth0, 709, &wrapped_oc)?;

                wrap_sequence(&mut att_ex, &auth0)?;

                let mut auth1 : Vec<u8> = vec![];

                // purpose
                let mut wrapped_int : Vec<u8> = vec![];
                push_int(&mut wrapped_int, 2)?;
                let mut wrapped_set : Vec<u8> = vec![];
                wrap_set(&mut wrapped_set, &wrapped_int)?;
                wrap_tag(&mut auth1, 1, &wrapped_set)?;

                // algo
                let mut wrapped_int : Vec<u8> = vec![];
                push_int(&mut wrapped_int, 2)?;
                wrap_tag(&mut auth1, 2, &wrapped_int)?;

                // key size
                let mut wrapped_int : Vec<u8> = vec![];
                push_int(&mut wrapped_int, 256)?;
                wrap_tag(&mut auth1, 3, &wrapped_int)?;

                // digest
                let mut wrapped_int : Vec<u8> = vec![];
                push_int(&mut wrapped_int, 4)?;
                let mut wrapped_set : Vec<u8> = vec![];
                wrap_set(&mut wrapped_set, &wrapped_int)?;
                wrap_tag(&mut auth1, 5, &wrapped_set)?;

                // ecCurve
                let mut wrapped_int : Vec<u8> = vec![];
                push_int(&mut wrapped_int, 1)?;
                wrap_tag(&mut auth1, 10, &wrapped_in)?;

                // noAuthRequired
                let mut wrapped_null : Vec<u8> = vec![];
                push_null(&mut wrapped_null)?;
                wrap_tag(&mut auth1, 503, &wrapped_null)?;

                // origin                      [702] EXPLICIT INTEGER OPTIONAL,
                let mut wrapped_int : Vec<u8> = vec![];
                push_int(&mut wrapped_int, 0)?;
                wrap_tag(&mut auth1, 702, &wrapped_int)?;

                wrap_sequence(&mut att_ex, &auth1)?;

                let mut att_ex_seq_buf = vec![];

                wrap_sequence(&mut att_ex_seq_buf, &att_ex)?;
                Ok(att_ex_seq_buf)
            };
            let att_ex_seq_buf = match func() {
                Ok(s) => s,
                Err(s) => {
                    println!("{}", s);
                    return;
                }
            };


            println!("new oc: {} {:?}", att_ex_seq_buf.len(), att_ex_seq_buf);
            if ASN1_OCTET_STRING_set(oc, att_ex_seq_buf.as_ptr(), att_ex_seq_buf.len() as i32) == 0 {
                println!("Error on ASN1_OCTET_STRING_set: {}", get_bssl_error());
                return;
            }
            X509_EXTENSION_create_by_NID(&mut ex, nid, 0, oc);
            if ex.is_null() {
                println!("Error on X509_EXTENSION_create_by_NID: {}", get_bssl_error());
                return;
            }
            if X509_add_ext(cert, ex, -1) == 0 {
                println!("Error on X509_add_ext (attest ext.): {}", get_bssl_error());
                return;
            }
            ASN1_OCTET_STRING_free(oc);
            X509_EXTENSION_free(ex);

            // load private key //

            let mut key_ptr = EC_PRIVATE_KEY.as_ptr();
            let ec_key2 = d2i_ECPrivateKey(ptr::null_mut(), &mut key_ptr, EC_PRIVATE_KEY.len() as i64);
            if ec_key2.is_null() {
                println!("Error on d2i_ECPrivateKey: {}", get_bssl_error());
                return;
            }

            let key2 = EVP_PKEY_new();
            if key2.is_null() {
                println!("Error on EVP_PKEY_new: {}", get_bssl_error());
                return;
            }

            if EVP_PKEY_set1_EC_KEY(key2, ec_key2) == 0 {
                println!("Error on EVP_PKEY_set1_EC_KEY: {}", get_bssl_error());
                return;
            }

            // sign //

            if X509_sign(cert, key2, EVP_sha256()) == 0 {
                println!("failed on X509_sign");
                X509_free(cert);
                return;
            }

            EVP_PKEY_free(key2);

            // dump //

            let mut der_len = i2d_X509(cert, ptr::null_mut());
            if der_len < 1 {
                let e = ERR_get_error();
                let mut errbuf = Vec::with_capacity(1000);
                ERR_error_string(e, errbuf.as_mut_ptr());
                errbuf.set_len(130);
                let s = String::from_utf8(errbuf).expect("Our bytes should be valid utf8");
                println!("error der_len: {der_len}  err: {} {}", ERR_get_error(), s);
                X509_free(cert);
                return;
            }

            new_cert_buf.clear();
            new_cert_buf.reserve(der_len as usize);
            der_len = i2d_X509(cert, &mut new_cert_buf.as_mut_ptr());
            new_cert_buf.set_len(der_len as usize);

            let mut hex_buf = String::new();
            for (i, b) in new_cert_buf.iter().enumerate() {
                hex_buf += format!("{:02x}", b).as_str();

                if i % 32 == 31 {
                    hex_buf += "\n";
                }
            }
            log::info!("keystore2hook new cert: \n{hex_buf}");
            println!("hex_buf_len: {}", hex_buf.len());
            println!("hex_buf: \n{hex_buf}");

            EVP_PKEY_free(key);
            X509_NAME_free(subject);
            X509_free(cert);
        };
    }
}
