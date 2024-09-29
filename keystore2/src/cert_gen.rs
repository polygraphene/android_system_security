//! Generate certificate for attestation on behalf of (broken) TEE keymint.
//! 
#[allow(unused_imports)]
use crate::database::{BlobInfo, CertificateInfo, KeyIdGuard, EC_PRIVATE_KEY, CERTIFICATE_1, CERTIFICATE_2, CERTIFICATE_3};
#[allow(unused_imports)]
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, AttestationKey::AttestationKey,
    HardwareAuthenticatorType::HardwareAuthenticatorType, IKeyMintDevice::IKeyMintDevice,
    KeyCreationResult::KeyCreationResult, KeyFormat::KeyFormat,
    KeyMintHardwareInfo::KeyMintHardwareInfo, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel, Tag::Tag,
    Certificate::Certificate, KeyCharacteristics::KeyCharacteristics
};
#[allow(unused_imports)]
use crate::key_parameter::{
    KeyPurpose, EcCurve, Digest
};

#[allow(unused_imports)]
use anyhow::{anyhow, Context, Result};
#[allow(unused_imports)]
use bssl_sys::*;
#[allow(unused_imports)]
use std::ptr;
use std::sync::OnceLock;

static NID : OnceLock<i32> = OnceLock::new();

#[allow(clippy::undocumented_unsafe_blocks)]
fn get_bssl_error(context: &str) -> String {
    unsafe {
        let e = ERR_get_error();
        let mut errbuf = vec![0; 1000];
        // requires 256 bytes
        ERR_error_string_n(e, errbuf.as_mut_ptr(), 1000);
        let len = errbuf.iter().position(|&e| e == 0).unwrap_or(0);
        errbuf.set_len(len);
        return context.to_string() + " : " + &String::from_utf8_lossy(&errbuf[0..len]);
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
        buf.push(((len >> (i*8)) & 0xff) as u8);
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
            return Err(get_bssl_error("i2d_ASN1_INTEGER"));
        }
        let cur = buf.len();
        buf.resize(cur + ret as usize, 0);
        // p is mutated by i2d_* funcs. Don't use it after the call.
        let mut p = buf.as_mut_ptr().add(cur);
        if i2d_ASN1_INTEGER(a, &mut p) != ret {
            return Err(get_bssl_error("i2d_ASN1_INTEGER"));
        }
        ASN1_INTEGER_free(a);
        Ok(())
    }
}

#[allow(clippy::undocumented_unsafe_blocks)]
fn push_bool(buf: &mut Vec<u8>, val: bool) -> Result<(), String> {
    unsafe {
        let a = if val { ASN1_BOOLEAN_TRUE } else { ASN1_BOOLEAN_FALSE };
        let ret = i2d_ASN1_BOOLEAN(a, ptr::null_mut());
        if ret < 0 {
            return Err(get_bssl_error("i2d_ASN1_BOOLEAN"));
        }
        let cur = buf.len();
        buf.resize(cur + ret as usize, 0);
        // p is mutated by i2d_* funcs. Don't use it after the call.
        let mut p = buf.as_mut_ptr().add(cur);
        if i2d_ASN1_BOOLEAN(a, &mut p) != ret {
            return Err(get_bssl_error("i2d_ASN1_BOOLEAN"));
        }
        Ok(())
    }
}

#[allow(clippy::undocumented_unsafe_blocks)]
fn push_null(buf: &mut Vec<u8>) -> Result<(), String> {
    unsafe {
        let a = ASN1_NULL_new();
        let ret = i2d_ASN1_NULL(a, ptr::null_mut());
        if ret < 0 {
            return Err(get_bssl_error("i2d_ASN1_NULL"));
        }
        let cur = buf.len();
        buf.resize(cur + ret as usize, 0);
        // p is mutated by i2d_* funcs. Don't use it after the call.
        let mut p = buf.as_mut_ptr().add(cur);
        if i2d_ASN1_NULL(a, &mut p) != ret {
            return Err(get_bssl_error("i2d_ASN1_NULL"));
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
            return Err(get_bssl_error("i2d_ASN1_ENUMERATED"));
        }
        let cur = buf.len();
        buf.resize(cur + ret as usize, 0);
        // p is mutated by i2d_* funcs. Don't use it after the call.
        let mut p = buf.as_mut_ptr().add(cur);
        if i2d_ASN1_ENUMERATED(a, &mut p) != ret {
            return Err(get_bssl_error("i2d_ASN1_ENUMERATED"));
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
            return Err(get_bssl_error("i2d_ASN1_OCTET_STRING"));
        }
        let cur = buf.len();
        buf.resize(cur + ret as usize, 0);
        // p is mutated by i2d_* funcs. Don't use it after the call.
        let mut p = buf.as_mut_ptr().add(cur);
        if i2d_ASN1_OCTET_STRING(a, &mut p) != ret {
            return Err(get_bssl_error("i2d_ASN1_OCTET_STRING"));
        }
        ASN1_OCTET_STRING_free(a);
        Ok(())
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let mut hex_buf = String::new();
    for (i, b) in buf.iter().enumerate() {
        hex_buf += format!("{:02x}", b).as_str();

        if i % 32 == 31 {
            hex_buf += "\n";
        }
    }
    hex_buf
}

/// Genearate certificate from [KeyParameter]
#[allow(clippy::undocumented_unsafe_blocks)]
pub fn gen_new_cert(params: &[KeyParameter]) -> Result<(Vec<u8>, Vec<KeyCharacteristics>), String> {
    //let algorithm = Algorithm::EC.0;
    //match params.iter().find(|kp| kp.tag == Tag::ALGORITHM) {
    //    Some(KeyParameter{tag: _, value: KeyParameterValue::Algorithm(Algorithm::EC)}) => {},
    //    _ => return Err("Not supported algorithm".to_owned())
    //}
    //match params.iter().find(|kp| kp.tag == Tag::KEY_SIZE) {
    //    Some(KeyParameter{tag: _, value: KeyParameterValue::Integer(256)}) => {},
    //    _ => return Err("Not supported keySize".to_owned())
    //}
    //match params.iter().find(|kp| kp.tag == Tag::PURPOSE) {
    //    Some(KeyParameter{tag: _, value: KeyParameterValue::KeyPurpose(KeyPurpose::SIGN)}) => {},
    //    _ => return Err("Not supported keyPurpose".to_owned())
    //}
    //match params.iter().find(|kp| kp.tag == Tag::EC_CURVE) {
    //    Some(KeyParameter{tag: _, value: KeyParameterValue::EcCurve(EcCurve::P_256)}) => {},
    //    _ => return Err("Not supported EcCurve".to_owned())
    //}
    //let digest = match params.iter().find(|kp| kp.tag == Tag::DIGEST) {
    //    Some(KeyParameter{tag: _, value: KeyParameterValue::Digest(digest)}) => {
    //        if *digest != Digest::SHA_2_256 && *digest != Digest::SHA_2_512 {
    //            return Err(format!("Not supported Digest: {:?}", digest));
    //        }
    //        *digest
    //    },
    //    _ => return Err("No Digest specified".to_owned())
    //};
    unsafe {
        let mut ccf_ptr = CERTIFICATE_1.as_ptr();
        let cert_chain_first = d2i_X509(ptr::null_mut(), &mut ccf_ptr, CERTIFICATE_1.len() as i64);
        if cert_chain_first.is_null() {
            return Err(get_bssl_error("d2i_X509"));
        }

        let cert = X509_new();
        X509_set_version(cert, 2);

        let sn = ASN1_INTEGER_new();
        ASN1_INTEGER_set_int64(sn, 1);
        X509_set_serialNumber(cert, sn);
        ASN1_INTEGER_free(sn);

        let not_before = *match params.iter().find(|kp| kp.tag == Tag::CERTIFICATE_NOT_BEFORE) {
            Some(KeyParameter{tag: _, value: KeyParameterValue::DateTime(b)}) => b,
            _ => {
                return Err("Tag::CERTIFICATE_NOT_BEFORE is not found".to_owned());
            }
        };
        let not_after = *match params.iter().find(|kp| kp.tag == Tag::CERTIFICATE_NOT_AFTER) {
            Some(KeyParameter{tag: _, value: KeyParameterValue::DateTime(b)}) => b,
            _ => {
                return Err("Tag::CERTIFICATE_NOT_AFTER is not found".to_owned());
            }
        };
        let zero_time = 0;
        if X509_time_adj(X509_get_notBefore(cert), not_before / 1000, &zero_time).is_null() {
            return Err(get_bssl_error("X509_time_adj"));
        }
        if X509_time_adj(X509_get_notAfter(cert), not_after / 1000, &zero_time).is_null() {
            return Err(get_bssl_error("X509_time_adj (not after)"));
        }
        //X509_gmtime_adj(X509_get_notBefore(cert), 0);
        //X509_gmtime_adj(X509_get_notAfter(cert), 20i64*365*24*3600);

        let pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, ptr::null_mut());
        if pctx.is_null() {
            return Err(get_bssl_error("EVP_PKEY_CTX_new_id"));
        }
        if EVP_PKEY_paramgen_init(pctx) == 0 {
            return Err(get_bssl_error(""));
        }

        if EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) == 0 {
            return Err(get_bssl_error(""));
        }

        let mut params2 : *mut EVP_PKEY = ptr::null_mut();
        if EVP_PKEY_paramgen(pctx, &mut params2) == 0 {
            return Err(get_bssl_error(""));
        }

        // key generation context
        let ctx = EVP_PKEY_CTX_new(params2, ptr::null_mut());
        if ctx.is_null() {
            return Err(get_bssl_error(""));
        }
        if EVP_PKEY_keygen_init(ctx) == 0 {
            return Err(get_bssl_error(""));
        }

        let mut key: *mut EVP_PKEY = ptr::null_mut();
        if EVP_PKEY_keygen(ctx, &mut key) == 0 {
            return Err(get_bssl_error(""));
        }

        //let ec_key = EVP_PKEY_get1_EC_KEY(key);
        //let bio = BIO_new(BIO_s_mem());
        //if PEM_write_bio_ECPrivateKey(bio, ec_key, ptr::null_mut(), ptr::null_mut(), 0, None, ptr::null_mut()) == 0 {
        //    return Err(get_bssl_error(""));
        //}
        //let mut buf : *mut BUF_MEM = ptr::null_mut();
        //BIO_get_mem_ptr(bio, &mut buf);
        //let pem_str = String::from_utf8_lossy(std::slice::from_raw_parts((*buf).data, (*buf).length)).to_string();
        //BIO_free(bio);

        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_CTX_free(ctx);

        if X509_set_pubkey(cert, key) == 0 {
            return Err(get_bssl_error(""));
        }

        // X509_get_subject_name returns internal pointer. Must not be freed.
        let ccf_subject = X509_get_subject_name(cert_chain_first);
        if ccf_subject.is_null() {
            return Err(get_bssl_error(""));
        }

        X509_set_issuer_name(cert, ccf_subject);
        X509_free(cert_chain_first);

        let subject_der = match params.iter().find(|kp| kp.tag == Tag::CERTIFICATE_SUBJECT) {
            Some(KeyParameter{tag: _, value: KeyParameterValue::Blob(b)}) => b,
            _ => {
                return Err("Tag::CERTIFICATE_SUBJECT is not found".to_owned());
            }
        };
        if true {
            let mut p = subject_der[..].as_ptr();
            let subject = d2i_X509_NAME(ptr::null_mut(), &mut p, subject_der.len() as i64);
            if subject.is_null() {
                return Err(get_bssl_error(""));
            }
            X509_set_subject_name(cert, subject);
            X509_NAME_free(subject);
        }else {
            let subject = X509_NAME_new();
            assert!(!subject.is_null());
            log::info!("keystore2hook subject new");
            if X509_NAME_add_entry_by_txt(subject, "commonName\0".as_ptr(), MBSTRING_ASC, "Android Keystore Key\0".as_ptr(), -1, -1, 0) == 0 {
                log::info!("keystore2hook X509_NAME_add_entry_by_txt failed");
            }
            X509_set_subject_name(cert, subject);
            X509_NAME_free(subject);
        }

        // extensions //

        let mut ex: *mut X509_EXTENSION = ptr::null_mut();

        let oc = ASN1_OCTET_STRING_new();
        // key usage keyCertSign
        ASN1_OCTET_STRING_set(oc, "\x03\x02\x02\x04".as_ptr(), 4);
        X509_EXTENSION_create_by_NID(&mut ex, NID_key_usage, 1, oc);
        if X509_add_ext(cert, ex, -1) == 0 {
            return Err(get_bssl_error(""));
        }
        ASN1_OCTET_STRING_free(oc);
        X509_EXTENSION_free(ex);
        ex = ptr::null_mut();

        // OBJ_create can only be called once.
        let nid = *NID.get_or_init(|| {
            OBJ_create("1.3.6.1.4.1.11129.2.1.17\0".as_ptr(), "MyAlias\0".as_ptr(), "My Test Alias Extension\0".as_ptr())
        });

        let mut att_ex : Vec<u8> = vec![];
        push_int(&mut att_ex, 300)?;
        push_enum(&mut att_ex, 2)?;
        push_int(&mut att_ex, 300)?;
        push_enum(&mut att_ex, 2)?;
        match params.iter().find(|kp| kp.tag == Tag::ATTESTATION_CHALLENGE) {
            Some(KeyParameter{tag: _, value: KeyParameterValue::Blob(b)}) => push_oc(&mut att_ex, b)?,
            _ => return Err("Tag::ATTESTATION_CHALLENGE is not found".to_owned()),
        };
        // empty uniqueId
        push_oc(&mut att_ex, b"")?;

        let mut software_chara = KeyCharacteristics { 
            securityLevel: SecurityLevel::SOFTWARE,
            authorizations: vec![]
        };

        // softwareEnforced           AuthorizationList,
        // creationDateTime            [701] EXPLICIT INTEGER OPTIONAL,
        let b = *match params.iter().find(|kp| kp.tag == Tag::CREATION_DATETIME) {
            Some(KeyParameter{tag: _, value: KeyParameterValue::DateTime(b)}) => b,
            _ => return Err("Tag::ATTESTATION_CHALLENGE is not found".to_owned()),
        };
        software_chara.authorizations.push(params.iter().find(|kp| kp.tag == Tag::CREATION_DATETIME).unwrap().clone());

        let mut auth0 : Vec<u8> = vec![];
        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, b)?;
        wrap_tag(&mut auth0, 701, &wrapped_int)?;

        // attestationApplicationId    [709] EXPLICIT OCTET_STRING OPTIONAL, # KM3
        let b = match params.iter().find(|kp| kp.tag == Tag::ATTESTATION_APPLICATION_ID) {
            Some(KeyParameter{tag: _, value: KeyParameterValue::Blob(b)}) => b,
            _ => return Err("Tag::ATTESTATION_APPLICATION_ID is not found".to_owned()),
        };
        software_chara.authorizations.push(params.iter().find(|kp| kp.tag == Tag::ATTESTATION_APPLICATION_ID).unwrap().clone());
        let mut wrapped_oc : Vec<u8> = vec![];
        push_oc(&mut wrapped_oc, b)?;
        wrap_tag(&mut auth0, 709, &wrapped_oc)?;

        wrap_sequence(&mut att_ex, &auth0)?;

        // teeEnforced                AuthorizationList,

        let mut auth1 : Vec<u8> = vec![];
        let mut tee_chara = KeyCharacteristics { 
            securityLevel: SecurityLevel::TRUSTED_ENVIRONMENT,
            authorizations: vec![]
        };

        let mut wrapped_purpose : Vec<u8> = vec![];
        let mut wrapped_algo : Vec<u8> = vec![];
        let mut wrapped_keysize : Vec<u8> = vec![];
        let mut wrapped_digest : Vec<u8> = vec![];
        let mut wrapped_eccurve : Vec<u8> = vec![];
        let mut wrapped_noauthrequired : Vec<u8> = vec![];
        for p in params.iter() {
            match p {
                KeyParameter { tag: Tag::PURPOSE, value : KeyParameterValue::KeyPurpose(p)} => {
                    push_int(&mut wrapped_purpose, p.0 as i64)?;
                },
                KeyParameter { tag: Tag::ALGORITHM, value : KeyParameterValue::Algorithm(p)} => {
                    push_int(&mut wrapped_algo, p.0 as i64)?;
                },
                KeyParameter { tag: Tag::KEY_SIZE, value : KeyParameterValue::Integer(p)} => {
                    push_int(&mut wrapped_keysize, p.0 as i64)?;
                },
                KeyParameter { tag: Tag::DIGEST, value : KeyParameterValue::Digest(p)} => {
                    push_int(&mut wrapped_digest, p.0 as i64)?;
                },
                KeyParameter { tag: Tag::EC_CURVE, value : KeyParameterValue::EcCurve(p)} => {
                    push_int(&mut wrapped_eccurve, p.0 as i64)?;
                },
                KeyParameter { tag: Tag::NO_AUTH_REQUIRED, value : KeyParameterValue::BoolValue(p)} => {
                    if p {
                        push_null(&mut wrapped_noauthrequired);
                    }
                },
                _ => {},
            }
        }
        // purpose
        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, 2)?;
        let mut wrapped_set : Vec<u8> = vec![];
        wrap_set(&mut wrapped_set, &wrapped_int)?;
        wrap_tag(&mut auth1, 1, &wrapped_set)?;

        // algo
        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, algorithm as i64)?;
        wrap_tag(&mut auth1, 2, &wrapped_int)?;
        tee_chara.authorizations.push(params.iter().find(|kp| kp.tag == Tag::ALGORITHM).unwrap().clone());

        // key size
        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, 256)?;
        wrap_tag(&mut auth1, 3, &wrapped_int)?;
        tee_chara.authorizations.push(params.iter().find(|kp| kp.tag == Tag::KEY_SIZE).unwrap().clone());

        // digest
        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, digest.0 as i64)?;
        let mut wrapped_set : Vec<u8> = vec![];
        wrap_set(&mut wrapped_set, &wrapped_int)?;
        wrap_tag(&mut auth1, 5, &wrapped_set)?;
        tee_chara.authorizations.push(params.iter().find(|kp| kp.tag == Tag::DIGEST).unwrap().clone());

        // ecCurve
        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, 1)?;
        wrap_tag(&mut auth1, 10, &wrapped_int)?;
        tee_chara.authorizations.push(params.iter().find(|kp| kp.tag == Tag::EC_CURVE).unwrap().clone());

        // noAuthRequired
        let mut wrapped_null : Vec<u8> = vec![];
        push_null(&mut wrapped_null)?;
        wrap_tag(&mut auth1, 503, &wrapped_null)?;
        if let Some(kp) = params.iter().find(|kp| kp.tag == Tag::NO_AUTH_REQUIRED) {
            tee_chara.authorizations.push(kp.clone());
        }

        // origin                      [702] EXPLICIT INTEGER OPTIONAL,
        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, 0)?;
        wrap_tag(&mut auth1, 702, &wrapped_int)?;

        // RootOfTrust ::= SEQUENCE {
        //   verifiedBootKey            OCTET_STRING,
        //   deviceLocked               BOOLEAN,
        //   verifiedBootState          VerifiedBootState,
        //   verifiedBootHash           OCTET_STRING, # KM4
        // }
        // 
        // VerifiedBootState ::= ENUMERATED {
        //   Verified                   (0),
        //   SelfSigned                 (1),
        //   Unverified                 (2),
        //   Failed                     (3),
        // }

        let mut root_of_trust : Vec<u8> = vec![];
        // randomly generated (hard-coded) value
        // verifiedBootKey
        push_oc(&mut root_of_trust, &[
            0x54, 0xfc, 0xb1, 0x77, 0xd3, 0x8f, 0x42, 0x20, 0xb9, 0x18, 0x3d, 0xa4,
            0x94, 0x29, 0x12, 0x0e, 0x01, 0x8c, 0x8f, 0x4d, 0x1e, 0xb2, 0x70, 0x13,
            0x89, 0x94, 0x4f, 0xb0, 0xbb, 0x44, 0x61, 0xc2
        ])?;
        // deviceLocked
        push_bool(&mut root_of_trust, true)?;
        // VerifiedBootState
        push_enum(&mut root_of_trust, 0)?;
        // randomly generated (hard-coded) value
        // verifiedBootHash
        push_oc(&mut root_of_trust, &[
            0x13, 0x28, 0x87, 0x93, 0x48, 0x1a, 0xa9, 0xef, 0xe6, 0x42, 0x24, 0x15,
            0x9e, 0x65, 0x6e, 0x8f, 0xa3, 0x01, 0x3c, 0xa6, 0xb6, 0xbe, 0x7f, 0xf7,
            0xe0, 0x44, 0x09, 0x11, 0x5b, 0x0c, 0xa4, 0x1a
        ])?;

        let mut root_of_trust_seq = vec![];
        wrap_sequence(&mut root_of_trust_seq, &root_of_trust)?;
        wrap_tag(&mut auth1, 704, &root_of_trust_seq)?;

        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, 150000)?;
        wrap_tag(&mut auth1, 705, &wrapped_int)?;

        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, 202409)?;
        wrap_tag(&mut auth1, 706, &wrapped_int)?;

        log::info!("keystore2hook check id attest");

        for tag in Tag::ATTESTATION_ID_BRAND.0..=Tag::ATTESTATION_ID_MODEL.0 {
            if let Some(KeyParameter{tag: _, value: KeyParameterValue::Blob(b)}) =
                params.iter().find(|kp| kp.tag.0 == tag) {
                    let mut wrapped_oc : Vec<u8> = vec![];

                    push_oc(&mut wrapped_oc, b)?;
                    wrap_tag(&mut auth1, tag & ((1 << 28) - 1),  &wrapped_oc)?;
            }
        }
        //                match params.iter().find(|kp| kp.tag == Tag::ATTESTATION_ID_DEVICE) {
        //                    Some(KeyParameter{tag: _, value: KeyParameterValue::Blob(b)}) => {
        //                        let mut wrapped_oc : Vec<u8> = vec![];
        //
        //                        push_oc(&mut wrapped_oc, b)?;
        //                        wrap_tag(&mut auth1, 711,  &wrapped_oc)?;
        //                    },
        //                    _ => {}
        //                };
        //                match params.iter().find(|kp| kp.tag == Tag::ATTESTATION_ID_PRODUCT) {
        //                    Some(KeyParameter{tag: _, value: KeyParameterValue::Blob(b)}) => {
        //                        let mut wrapped_oc : Vec<u8> = vec![];
        //
        //                        push_oc(&mut wrapped_oc, b)?;
        //                        wrap_tag(&mut auth1, 712,  &wrapped_oc)?;
        //                    },
        //                    _ => {}
        //                };
        //                match params.iter().find(|kp| kp.tag == Tag::ATTESTATION_ID_SERIAL) {
        //                    Some(KeyParameter{tag: _, value: KeyParameterValue::Blob(b)}) => {
        //                        let mut wrapped_oc : Vec<u8> = vec![];
        //
        //                        push_oc(&mut wrapped_oc, b)?;
        //                        wrap_tag(&mut auth1, 713,  &wrapped_oc)?;
        //                    },
        //                    _ => {}
        //                };
        //                match params.iter().find(|kp| kp.tag == Tag::ATTESTATION_ID_IMEI) {
        //                    Some(KeyParameter{tag: _, value: KeyParameterValue::Blob(b)}) => {
        //                        let mut wrapped_oc : Vec<u8> = vec![];
        //
        //                        push_oc(&mut wrapped_oc, b)?;
        //                        wrap_tag(&mut auth1, 714,  &wrapped_oc)?;
        //                    },
        //                    _ => {}
        //                };
        //                match params.iter().find(|kp| kp.tag == Tag::ATTESTATION_ID_MEID) {
        //                    Some(KeyParameter{tag: _, value: KeyParameterValue::Blob(b)}) => {
        //                        let mut wrapped_oc : Vec<u8> = vec![];
        //
        //                        push_oc(&mut wrapped_oc, b)?;
        //                        wrap_tag(&mut auth1, 715,  &wrapped_oc)?;
        //                    },
        //                    _ => {}
        //                };
        //                match params.iter().find(|kp| kp.tag == Tag::ATTESTATION_ID_MANUFACTURER) {
        //                    Some(KeyParameter{tag: _, value: KeyParameterValue::Blob(b)}) => {
        //                        let mut wrapped_oc : Vec<u8> = vec![];
        //
        //                        push_oc(&mut wrapped_oc, b)?;
        //                        wrap_tag(&mut auth1, 715,  &wrapped_oc)?;
        //                    },
        //                    _ => {}
        //                };
        //                match params.iter().find(|kp| kp.tag == Tag::ATTESTATION_ID_MODEL) {
        //                    Some(KeyParameter{tag: _, value: KeyParameterValue::Blob(b)}) => {
        //                        let mut wrapped_oc : Vec<u8> = vec![];
        //
        //                        push_oc(&mut wrapped_oc, b)?;
        //                        wrap_tag(&mut auth1, 715,  &wrapped_oc)?;
        //                    },
        //                    _ => {}
        //                };
        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, 202409)?;
        wrap_tag(&mut auth1, 718, &wrapped_int)?;

        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, 202409)?;
        wrap_tag(&mut auth1, 719, &wrapped_int)?;

        // End of teeEnforced                AuthorizationList,

        log::info!("keystore2hook a");
        wrap_sequence(&mut att_ex, &auth1)?;

        let mut att_ex_seq_buf = vec![];

        wrap_sequence(&mut att_ex_seq_buf, &att_ex)?;


        let oc = ASN1_OCTET_STRING_new();
        if ASN1_OCTET_STRING_set(oc, att_ex_seq_buf.as_ptr(), att_ex_seq_buf.len() as i32) == 0 {
            return Err(get_bssl_error(""));
        }
        X509_EXTENSION_create_by_NID(&mut ex, nid, 0, oc);
        if ex.is_null() {
            return Err(get_bssl_error(""));
        }
        if X509_add_ext(cert, ex, -1) == 0 {
            return Err(get_bssl_error("X509_add_ext"));
        }
        ASN1_OCTET_STRING_free(oc);
        X509_EXTENSION_free(ex);

        // load private key //

        let mut key_ptr = EC_PRIVATE_KEY.as_ptr();
        let ec_key2 = d2i_ECPrivateKey(ptr::null_mut(), &mut key_ptr, EC_PRIVATE_KEY.len() as i64);
        if ec_key2.is_null() {
            return Err(get_bssl_error("d2i_ECPrivateKey"));
        }

        let key2 = EVP_PKEY_new();
        if key2.is_null() {
            return Err(get_bssl_error("EVP_PKEY_new"));
        }

        if EVP_PKEY_set1_EC_KEY(key2, ec_key2) == 0 {
            return Err(get_bssl_error("EVP_PKEY_set1_EC_KEY"));
        }

        // sign //

        if X509_sign(cert, key2, if digest == Digest::SHA_2_256 { EVP_sha256() } else { EVP_sha512() }) == 0 {
            return Err(get_bssl_error("X509_sign"));
        }

        EVP_PKEY_free(key2);

        // dump //

        let der_len = i2d_X509(cert, ptr::null_mut());
        if der_len < 1 {
            return Err(get_bssl_error("i2d_X509"));
        }

        let mut new_cert_buf = vec![0; der_len as usize];
        i2d_X509(cert, &mut new_cert_buf.as_mut_ptr());

        let hex_buf = hex_dump(&new_cert_buf);
        log::info!("keystore2hook new cert: \n{hex_buf}");

        EVP_PKEY_free(key);
        X509_free(cert);
        EVP_PKEY_free(params2);
        Ok((new_cert_buf, vec![software_chara, tee_chara]))
    }
}
