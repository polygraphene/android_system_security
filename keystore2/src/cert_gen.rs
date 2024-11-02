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
    Certificate::Certificate, KeyCharacteristics::KeyCharacteristics,
    ErrorCode::ErrorCode
};
use keystore2_selinux::Deref;
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
use serde::{Deserialize, Serialize};
use serde_cbor;
use binder::Status;

static NID : OnceLock<i32> = OnceLock::new();

static CERT_GEN_BLOB_MAGIC : &[u8] = &[
0x94, 0x23, 0x73, 0xbe, 0x23, 0x0d, 0x4c, 0x26, 0x09, 0x7d, 0x75, 0xb1,
0x42, 0x15, 0x83, 0x27, 0x5a, 0xd0, 0x21, 0xf5, 0x82, 0xaf, 0x18, 0xaf,
0x05, 0x03, 0x5b, 0xac, 0xe2, 0x87, 0x81, 0xb1, 0xc8, 0x9d, 0x32, 0x13,
0xb5, 0x1b, 0x2f, 0x2d, 0xcc, 0xf7, 0xef, 0xc0, 0x24, 0xf1, 0xea, 0xe9,
0x2c, 0x52, 0x0f, 0x8a, 0x53, 0xd4, 0xcd, 0xc7, 0x7d, 0x81, 0x33, 0x53,
0x2d, 0x03, 0x66, 0x53
];

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

fn get_bssl_error_cert_gen(context: &str) -> GenNewCertErr {
    GenNewCertErr::Generic(get_bssl_error(context))
}

fn get_bit_length(v: i32) -> usize {
    if v == 0 {
        0
    } else {
        32 - v.leading_zeros() as usize
    }
}

#[allow(clippy::undocumented_unsafe_blocks)]
fn wrap_tag_raw(buf: &mut Vec<u8>, cl: i32, constructed: i32, tag: i32, val: &[u8]) -> Result<(), GenNewCertErr> {
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
fn wrap_tag(buf: &mut Vec<u8>, tag: i32, val: &[u8]) -> Result<(), GenNewCertErr> {
    wrap_tag_raw(buf, 2, 1, tag, val)
}

#[allow(clippy::undocumented_unsafe_blocks)]
fn wrap_set(buf: &mut Vec<u8>, val: &[u8]) -> Result<(), GenNewCertErr> {
    wrap_tag_raw(buf, 0, 1, 17, val)
}

#[allow(clippy::undocumented_unsafe_blocks)]
fn wrap_sequence(buf: &mut Vec<u8>, val: &[u8]) -> Result<(), GenNewCertErr> {
    wrap_tag_raw(buf, 0, 1, 16, val)
}

fn length_octet(buf: &mut Vec<u8>, len: usize) -> Result<(), GenNewCertErr> {
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
fn push_int(buf: &mut Vec<u8>, val: i64) -> Result<(), GenNewCertErr> {
    unsafe {
        let a = ASN1_INTEGER_new();
        ASN1_INTEGER_set(a, val);
        let ret = i2d_ASN1_INTEGER(a, ptr::null_mut());
        if ret < 0 {
            return generic_bssl_err("i2d_ASN1_INTEGER");
        }
        let cur = buf.len();
        buf.resize(cur + ret as usize, 0);
        // p is mutated by i2d_* funcs. Don't use it after the call.
        let mut p = buf.as_mut_ptr().add(cur);
        if i2d_ASN1_INTEGER(a, &mut p) != ret {
            return generic_bssl_err("i2d_ASN1_INTEGER");
        }
        ASN1_INTEGER_free(a);
        Ok(())
    }
}

#[allow(clippy::undocumented_unsafe_blocks)]
fn push_bool(buf: &mut Vec<u8>, val: bool) -> Result<(), GenNewCertErr> {
    unsafe {
        let a = if val { ASN1_BOOLEAN_TRUE } else { ASN1_BOOLEAN_FALSE };
        let ret = i2d_ASN1_BOOLEAN(a, ptr::null_mut());
        if ret < 0 {
            return generic_bssl_err("i2d_ASN1_BOOLEAN");
        }
        let cur = buf.len();
        buf.resize(cur + ret as usize, 0);
        // p is mutated by i2d_* funcs. Don't use it after the call.
        let mut p = buf.as_mut_ptr().add(cur);
        if i2d_ASN1_BOOLEAN(a, &mut p) != ret {
            return generic_bssl_err("i2d_ASN1_BOOLEAN");
        }
        Ok(())
    }
}

#[allow(clippy::undocumented_unsafe_blocks)]
fn push_null(buf: &mut Vec<u8>) -> Result<(), GenNewCertErr> {
    unsafe {
        let a = ASN1_NULL_new();
        let ret = i2d_ASN1_NULL(a, ptr::null_mut());
        if ret < 0 {
            return generic_bssl_err("i2d_ASN1_NULL");
        }
        let cur = buf.len();
        buf.resize(cur + ret as usize, 0);
        // p is mutated by i2d_* funcs. Don't use it after the call.
        let mut p = buf.as_mut_ptr().add(cur);
        if i2d_ASN1_NULL(a, &mut p) != ret {
            return generic_bssl_err("i2d_ASN1_NULL");
        }
        ASN1_NULL_free(a);
        Ok(())
    }
}

#[allow(clippy::undocumented_unsafe_blocks)]
fn push_enum(buf: &mut Vec<u8>, val: i64) -> Result<(), GenNewCertErr> {
    unsafe {
        let a = ASN1_ENUMERATED_new();
        ASN1_ENUMERATED_set(a, val);
        let ret = i2d_ASN1_ENUMERATED(a, ptr::null_mut());
        if ret < 0 {
            return generic_bssl_err("i2d_ASN1_ENUMERATED");
        }
        let cur = buf.len();
        buf.resize(cur + ret as usize, 0);
        // p is mutated by i2d_* funcs. Don't use it after the call.
        let mut p = buf.as_mut_ptr().add(cur);
        if i2d_ASN1_ENUMERATED(a, &mut p) != ret {
            return generic_bssl_err("i2d_ASN1_ENUMERATED");
        }
        ASN1_ENUMERATED_free(a);
        Ok(())
    }
}

#[allow(clippy::undocumented_unsafe_blocks)]
fn push_oc(buf: &mut Vec<u8>, val: &[u8]) -> Result<(), GenNewCertErr> {
    unsafe {
        let a = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(a, val.as_ptr(), val.len() as i32);
        let ret = i2d_ASN1_OCTET_STRING(a, ptr::null_mut());
        if ret < 0 {
            return generic_bssl_err("i2d_ASN1_OCTET_STRING");
        }
        let cur = buf.len();
        buf.resize(cur + ret as usize, 0);
        // p is mutated by i2d_* funcs. Don't use it after the call.
        let mut p = buf.as_mut_ptr().add(cur);
        if i2d_ASN1_OCTET_STRING(a, &mut p) != ret {
            return generic_bssl_err("i2d_ASN1_OCTET_STRING");
        }
        ASN1_OCTET_STRING_free(a);
        Ok(())
    }
}

#[allow(unused)]
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

struct X509Rs(*mut X509);

#[allow(clippy::undocumented_unsafe_blocks)]
impl X509Rs {
    fn new() -> Result<X509Rs, GenNewCertErr> {
        let p = unsafe { X509_new() };
        if p.is_null() {
            return Err(get_bssl_error_cert_gen("X509_new"));
        }
        Ok(X509Rs(p))
    }

    fn d2i(buf: &[u8]) -> Result<X509Rs, GenNewCertErr> {
        let mut pbuf = buf.as_ptr();
        let p = unsafe { d2i_X509(ptr::null_mut(), &mut pbuf, buf.len() as i64) };
        if p.is_null() {
            return Err(get_bssl_error_cert_gen("d2i_X509"));
        }
        Ok(X509Rs(p))
    }
}

#[allow(clippy::undocumented_unsafe_blocks)]
impl Drop for X509Rs {
    fn drop(&mut self) {
        unsafe { X509_free(self.0); }
    }
}

impl Deref for X509Rs {
    type Target = *mut X509;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct X509Name(*mut X509_NAME);

#[allow(clippy::undocumented_unsafe_blocks)]
impl X509Name {
    fn d2i(buf: &[u8]) -> Result<X509Name, GenNewCertErr> {
        let mut pbuf = buf.as_ptr();
        let p = unsafe { d2i_X509_NAME(ptr::null_mut(), &mut pbuf, buf.len() as i64) };
        if p.is_null() {
            return Err(get_bssl_error_cert_gen("d2i_X509_NAME"));
        }
        Ok(X509Name(p))
    }
}

#[allow(clippy::undocumented_unsafe_blocks)]
impl Drop for X509Name {
    fn drop(&mut self) {
        unsafe { X509_NAME_free(self.0); }
    }
}

impl Deref for X509Name {
    type Target = *mut X509_NAME;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct X509Extension(*mut X509_EXTENSION);

#[allow(clippy::undocumented_unsafe_blocks)]
impl X509Extension {
    fn wrap(p: *mut X509_EXTENSION) -> X509Extension {
        X509Extension(p)
    }
}

#[allow(clippy::undocumented_unsafe_blocks)]
impl Drop for X509Extension {
    fn drop(&mut self) {
        unsafe { X509_EXTENSION_free(self.0); }
    }
}

impl Deref for X509Extension {
    type Target = *mut X509_EXTENSION;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}


struct Asn1Integer(*mut ASN1_INTEGER);

#[allow(clippy::undocumented_unsafe_blocks)]
impl Asn1Integer {
    fn new() -> Result<Asn1Integer, GenNewCertErr> {
        let p = unsafe { ASN1_INTEGER_new() };
        if p.is_null() {
            return Err(get_bssl_error_cert_gen("ASN1_INTEGER_new"));
        }
        Ok(Asn1Integer(p))
    }
}

#[allow(clippy::undocumented_unsafe_blocks)]
impl Drop for Asn1Integer {
    fn drop(&mut self) {
        unsafe { ASN1_INTEGER_free(self.0); }
    }
}

impl Deref for Asn1Integer {
    type Target = *mut ASN1_INTEGER;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct Asn1OctetString(*mut ASN1_OCTET_STRING);

#[allow(clippy::undocumented_unsafe_blocks)]
impl Asn1OctetString {
    fn new() -> Result<Asn1OctetString, GenNewCertErr> {
        let p = unsafe { ASN1_OCTET_STRING_new() };
        if p.is_null() {
            return Err(get_bssl_error_cert_gen("ASN1_OCTET_STRING_new"));
        }
        Ok(Asn1OctetString(p))
    }
}

#[allow(clippy::undocumented_unsafe_blocks)]
impl Drop for Asn1OctetString {
    fn drop(&mut self) {
        unsafe { ASN1_OCTET_STRING_free(self.0); }
    }
}

impl Deref for Asn1OctetString {
    type Target = *mut ASN1_OCTET_STRING;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct EvpPkeyCtx(*mut EVP_PKEY_CTX);

impl EvpPkeyCtx {
    fn wrap(p: *mut EVP_PKEY_CTX) -> Result<EvpPkeyCtx, GenNewCertErr> {
        Ok(EvpPkeyCtx(p))
    }
}

#[allow(clippy::undocumented_unsafe_blocks)]
impl Drop for EvpPkeyCtx {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_CTX_free(self.0); }
    }
}

impl Deref for EvpPkeyCtx {
    type Target = *mut EVP_PKEY_CTX;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct EvpPkey(*mut EVP_PKEY);

#[allow(clippy::undocumented_unsafe_blocks)]
impl EvpPkey {
    fn new() -> Result<EvpPkey, GenNewCertErr> {
        let p = unsafe { EVP_PKEY_new() };
        if p.is_null() {
            return Err(get_bssl_error_cert_gen("EVP_PKEY_new"));
        }
        Ok(EvpPkey(p))
    }

    fn wrap(p: *mut EVP_PKEY) -> Result<EvpPkey, GenNewCertErr> {
        Ok(EvpPkey(p))
    }

    fn i2d(&self) -> Result<Vec<u8>, GenNewCertErr> {
        let priv_len = unsafe { i2d_PrivateKey(self.0, ptr::null_mut()) as i64 };
        if priv_len < 1 {
            return Err(get_bssl_error_cert_gen("i2d_PrivateKey"));
        }

        let mut b = vec![0u8; priv_len as usize];

        let mut ptr = b.as_mut_ptr();
        if unsafe { i2d_PrivateKey(self.0, &mut ptr) } as i64 != priv_len {
            return Err(get_bssl_error_cert_gen("i2d_PrivateKey"));
        }

        Ok(b)
    }
}

#[allow(clippy::undocumented_unsafe_blocks)]
impl Drop for EvpPkey {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_free(self.0); }
    }
}

impl Deref for EvpPkey {
    type Target = *mut EVP_PKEY;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Inefficient serialize. serde is not good at serializing [u8] or Vec<u8>.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct CertGenKeyBlob {
    private_key: Vec<u8>,
    cert_chain: Vec<Vec<u8>>,
}

fn verify_key_parameters(
    params: &[KeyParameter], 
) -> Result<(), GenNewCertErr> {
    let mut has_attest_purpose = false;
    let mut has_other_purposes = false;
    for p in params.iter() {
        match p {
            KeyParameter { tag: Tag::PURPOSE, value : KeyParameterValue::KeyPurpose(KeyPurpose::ATTEST_KEY)} => {
                has_attest_purpose = true;
            },
            KeyParameter { tag: Tag::PURPOSE, value : KeyParameterValue::KeyPurpose(_)} => {
                has_other_purposes = true;
            },
            _ => {}
        }
    }
    if has_attest_purpose && has_other_purposes {
        return Err(GenNewCertErr::KeyMintErr(Status::new_service_specific_error(ErrorCode::INCOMPATIBLE_PURPOSE.0, None)));
    }
    Ok(())
}

/// Error for gen_new_cert
#[derive(Debug)]
pub enum GenNewCertErr {
    /// Generic string error
    Generic(String),
    /// Emulate key mint error
    KeyMintErr(Status)
}

impl From<String> for GenNewCertErr {
    fn from(value: String) -> Self {
        GenNewCertErr::Generic(value)
    }
}

fn generic_err<T>(v: &str) -> Result<T, GenNewCertErr> {
    Err(GenNewCertErr::Generic(v.to_string()))
}

fn generic_bssl_err<T>(v: &str) -> Result<T, GenNewCertErr> {
    Err(GenNewCertErr::Generic(get_bssl_error(v)))
}

/// Genearate key and certificate from [KeyParameter]
#[allow(clippy::undocumented_unsafe_blocks)]
pub fn gen_new_cert(
    params: &[KeyParameter], 
    attestation_key: Option<&AttestationKey>,
) -> Result<KeyCreationResult, GenNewCertErr> {
    unsafe {
        verify_key_parameters(params)?;

        let cert_gen_key_blob = match attestation_key {
            Some(AttestationKey{ keyBlob, attestKeyParams : _, issuerSubjectName : _}) if keyBlob.starts_with(CERT_GEN_BLOB_MAGIC) =>
                serde_cbor::from_slice(&keyBlob[CERT_GEN_BLOB_MAGIC.len()..]).map_err(|x| format!("Invalid blob. Deserialize error: {:?}", x))?,
            None => CertGenKeyBlob { private_key: EC_PRIVATE_KEY.to_vec(), cert_chain : vec![CERTIFICATE_1.to_vec(), CERTIFICATE_2.to_vec(), CERTIFICATE_3.to_vec()] },
            _ => return generic_err("Invalid blob")
        };
        let Some(cert_chain_first) = cert_gen_key_blob.cert_chain.first() else {
            return generic_err("Invalid blob")
        };
        let cert_chain_first = X509Rs::d2i(cert_chain_first)?;

        let cert = X509Rs::new()?;
        X509_set_version(*cert, 2);

        let sn = Asn1Integer::new()?;
        if ASN1_INTEGER_set_int64(*sn, 1) == 0 {
            return generic_bssl_err("ASN1_INTEGER_new");
        }
        X509_set_serialNumber(*cert, *sn);
        drop(sn);

        let not_before = *match params.iter().find(|kp| kp.tag == Tag::CERTIFICATE_NOT_BEFORE) {
            Some(KeyParameter{tag: _, value: KeyParameterValue::DateTime(b)}) => b,
            _ => {
                return generic_err("Tag::CERTIFICATE_NOT_BEFORE is not found");
            }
        };
        let not_after = *match params.iter().find(|kp| kp.tag == Tag::CERTIFICATE_NOT_AFTER) {
            Some(KeyParameter{tag: _, value: KeyParameterValue::DateTime(b)}) => b,
            _ => {
                return generic_err("Tag::CERTIFICATE_NOT_AFTER is not found");
            }
        };
        let zero_time = 0;
        if X509_time_adj(X509_get_notBefore(*cert), not_before / 1000, &zero_time).is_null() {
            return generic_bssl_err("X509_time_adj");
        }
        if X509_time_adj(X509_get_notAfter(*cert), not_after / 1000, &zero_time).is_null() {
            return generic_bssl_err("X509_time_adj (not after)");
        }
        //X509_gmtime_adj(X509_get_notBefore(*cert), 0);
        //X509_gmtime_adj(X509_get_notAfter(*cert), 20i64*365*24*3600);

        let pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, ptr::null_mut());
        if pctx.is_null() {
            return generic_bssl_err("EVP_PKEY_CTX_new_id");
        }
        let pctx = EvpPkeyCtx::wrap(pctx)?;
        if EVP_PKEY_paramgen_init(*pctx) == 0 {
            return generic_bssl_err("EVP_PKEY_paramgen_init");
        }

        if EVP_PKEY_CTX_set_ec_paramgen_curve_nid(*pctx, NID_X9_62_prime256v1) == 0 {
            return generic_bssl_err("EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
        }

        let mut params2 : *mut EVP_PKEY = ptr::null_mut();
        if EVP_PKEY_paramgen(*pctx, &mut params2) == 0 {
            return generic_bssl_err("EVP_PKEY_paramgen");
        }
        let params2 = EvpPkey::wrap(params2)?;

        // key generation context
        let ctx = EVP_PKEY_CTX_new(*params2, ptr::null_mut());
        if ctx.is_null() {
            return generic_bssl_err("EVP_PKEY_CTX_new");
        }
        let ctx = EvpPkeyCtx::wrap(ctx)?;
        if EVP_PKEY_keygen_init(*ctx) == 0 {
            return generic_bssl_err("EVP_PKEY_keygen_init");
        }

        let mut key: *mut EVP_PKEY = ptr::null_mut();
        if EVP_PKEY_keygen(*ctx, &mut key) == 0 {
            return generic_bssl_err("EVP_PKEY_keygen");
        }
        let key = EvpPkey::wrap(key)?;

        drop(params2);
        drop(pctx);
        drop(ctx);

        if X509_set_pubkey(*cert, *key) == 0 {
            return generic_bssl_err("X509_set_pubkey");
        }

        // X509_get_subject_name returns internal pointer. Must not be freed.
        let ccf_subject = X509_get_subject_name(*cert_chain_first);
        if ccf_subject.is_null() {
            return generic_bssl_err("X509_get_subject_name");
        }

        X509_set_issuer_name(*cert, ccf_subject);

        let subject= match params.iter().find(|kp| kp.tag == Tag::CERTIFICATE_SUBJECT) {
            Some(KeyParameter{tag: _, value: KeyParameterValue::Blob(b)}) => X509Name::d2i(b)?,
            _ => {
                return generic_err("Tag::CERTIFICATE_SUBJECT is not found");
            }
        };
        // The name parameter is copied internally and should be freed up when it is no longer needed.
        if X509_set_subject_name(*cert, *subject /* name */) == 0 {
            return generic_bssl_err("X509_set_subject_name");
        }
        drop(subject);

        // extensions //

        let mut ex: *mut X509_EXTENSION = ptr::null_mut();

        let oc = Asn1OctetString::new()?;
        // key usage keyCertSign
        if ASN1_OCTET_STRING_set(*oc, "\x03\x02\x02\x04".as_ptr(), 4) == 0 {
            return generic_bssl_err("ASN1_OCTET_STRING_set");
        }

        X509_EXTENSION_create_by_NID(&mut ex, NID_key_usage, 1, *oc);
        if ex.is_null() {
            return generic_bssl_err("X509_EXTENSION_create_by_NID");
        }
        let ex = X509Extension::wrap(ex);
        if X509_add_ext(*cert, *ex, -1) == 0 {
            return generic_bssl_err("X509_add_ext");
        }
        drop(oc);
        drop(ex);

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
            _ => return generic_err("Tag::ATTESTATION_CHALLENGE is not found"),
        };
        // empty uniqueId
        push_oc(&mut att_ex, b"")?;

        let mut sw_characteristics = KeyCharacteristics { 
            securityLevel: SecurityLevel::SOFTWARE,
            authorizations: vec![]
        };

        // softwareEnforced           AuthorizationList,
        // creationDateTime            [701] EXPLICIT INTEGER OPTIONAL,
        let b = *match params.iter().find(|kp| kp.tag == Tag::CREATION_DATETIME) {
            Some(KeyParameter{tag: _, value: KeyParameterValue::DateTime(b)}) => b,
            _ => return generic_err("Tag::ATTESTATION_CHALLENGE is not found"),
        };
        sw_characteristics.authorizations.push(params.iter().find(|kp| kp.tag == Tag::CREATION_DATETIME).unwrap().clone());

        let mut auth0 : Vec<u8> = vec![];
        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, b)?;
        wrap_tag(&mut auth0, 701, &wrapped_int)?;

        // attestationApplicationId    [709] EXPLICIT OCTET_STRING OPTIONAL, # KM3
        let b = match params.iter().find(|kp| kp.tag == Tag::ATTESTATION_APPLICATION_ID) {
            Some(KeyParameter{tag: _, value: KeyParameterValue::Blob(b)}) => b,
            _ => return generic_err("Tag::ATTESTATION_APPLICATION_ID is not found"),
        };
        sw_characteristics.authorizations.push(params.iter().find(|kp| kp.tag == Tag::ATTESTATION_APPLICATION_ID).unwrap().clone());
        let mut wrapped_oc : Vec<u8> = vec![];
        push_oc(&mut wrapped_oc, b)?;
        wrap_tag(&mut auth0, 709, &wrapped_oc)?;

        wrap_sequence(&mut att_ex, &auth0)?;

        // teeEnforced                AuthorizationList,

        let mut auth1 : Vec<u8> = vec![];
        let mut tee_characteristics = KeyCharacteristics { 
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
                    // KeyPurpose is a SET OF INTEGER. May appear multiple times.
                    push_int(&mut wrapped_purpose, p.0 as i64)?;
                },
                KeyParameter { tag: Tag::ALGORITHM, value : KeyParameterValue::Algorithm(p)} => {
                    wrapped_algo.clear();
                    push_int(&mut wrapped_algo, p.0 as i64)?;
                },
                KeyParameter { tag: Tag::KEY_SIZE, value : KeyParameterValue::Integer(p)} => {
                    wrapped_keysize.clear();
                    push_int(&mut wrapped_keysize, *p as i64)?;
                },
                KeyParameter { tag: Tag::DIGEST, value : KeyParameterValue::Digest(p)} => {
                    // Digest is a SET OF INTEGER. May appear multiple times.
                    push_int(&mut wrapped_digest, p.0 as i64)?;
                },
                KeyParameter { tag: Tag::EC_CURVE, value : KeyParameterValue::EcCurve(p)} => {
                    wrapped_eccurve.clear();
                    push_int(&mut wrapped_eccurve, p.0 as i64)?;
                },
                KeyParameter { tag: Tag::NO_AUTH_REQUIRED, value : KeyParameterValue::BoolValue(p)} => {
                    if *p {
                        wrapped_noauthrequired.clear();
                        push_null(&mut wrapped_noauthrequired)?;
                    }
                },
                // Dont push other tags to tee_chara here.
                _ => continue,
            }
            // Recognized tags
            tee_characteristics.authorizations.push(p.clone());
        }
        // purpose
        let mut wrapped_set : Vec<u8> = vec![];
        wrap_set(&mut wrapped_set, &wrapped_purpose)?;
        wrap_tag(&mut auth1, 1, &wrapped_set)?;
        // algo
        wrap_tag(&mut auth1, 2, &wrapped_algo)?;
        // key size
        wrap_tag(&mut auth1, 3, &wrapped_keysize)?;
        // digest
        let mut wrapped_set : Vec<u8> = vec![];
        wrap_set(&mut wrapped_set, &wrapped_digest)?;
        wrap_tag(&mut auth1, 5, &wrapped_set)?;
        // ecCurve
        wrap_tag(&mut auth1, 10, &wrapped_eccurve)?;
        // noAuthRequired
        if !wrapped_noauthrequired.is_empty() {
            wrap_tag(&mut auth1, 503, &wrapped_noauthrequired)?;
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

        // osVersion: 15.0.0 -> 150000
        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, 150000)?;
        wrap_tag(&mut auth1, 705, &wrapped_int)?;

        // osPatchLevel
        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, 202410)?;
        wrap_tag(&mut auth1, 706, &wrapped_int)?;

        for tag in Tag::ATTESTATION_ID_BRAND.0..=Tag::ATTESTATION_ID_MODEL.0 {
            if let Some(KeyParameter{tag: _, value: KeyParameterValue::Blob(b)}) =
                params.iter().find(|kp| kp.tag.0 == tag) {
                    let mut wrapped_oc : Vec<u8> = vec![];

                    push_oc(&mut wrapped_oc, b)?;
                    wrap_tag(&mut auth1, tag & ((1 << 28) - 1),  &wrapped_oc)?;
            }
        }
        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, 202410)?;
        wrap_tag(&mut auth1, 718, &wrapped_int)?;

        let mut wrapped_int : Vec<u8> = vec![];
        push_int(&mut wrapped_int, 202410)?;
        wrap_tag(&mut auth1, 719, &wrapped_int)?;

        // End of teeEnforced                AuthorizationList,

        wrap_sequence(&mut att_ex, &auth1)?;

        let mut att_ex_seq_buf = vec![];

        wrap_sequence(&mut att_ex_seq_buf, &att_ex)?;


        let oc = Asn1OctetString::new()?;
        if ASN1_OCTET_STRING_set(*oc, att_ex_seq_buf.as_ptr(), att_ex_seq_buf.len() as i32) == 0 {
            return generic_bssl_err("ASN1_OCTET_STRING_set");
        }
        let mut ex = ptr::null_mut();
        X509_EXTENSION_create_by_NID(&mut ex, nid, 0, *oc);
        if ex.is_null() {
            return generic_bssl_err("X509_EXTENSION_create_by_NID");
        }
        let ex = X509Extension::wrap(ex);
        if X509_add_ext(*cert, *ex, -1) == 0 {
            return generic_bssl_err("X509_add_ext");
        }
        drop(oc);
        drop(ex);

        // load private key //

        let mut key_ptr = cert_gen_key_blob.private_key.as_ptr();
        let ec_key2 = d2i_ECPrivateKey(ptr::null_mut(), (&mut key_ptr) as *mut *const u8, cert_gen_key_blob.private_key.len() as i64);
        if ec_key2.is_null() {
            return generic_bssl_err("d2i_ECPrivateKey");
        }

        let signer_key = EvpPkey::new()?;

        // This function assign ec key to internal pointer. ec key will be automatically freed when
        // freeing signer_key.
        if EVP_PKEY_assign_EC_KEY(*signer_key, ec_key2) == 0 {
            return generic_bssl_err("EVP_PKEY_set1_EC_KEY");
        }

        // sign //

        if X509_sign(*cert, *signer_key, EVP_sha256()) == 0 {
            return generic_bssl_err("X509_sign");
        }

        drop(signer_key);

        // dump //

        let der_len = i2d_X509(*cert, ptr::null_mut());
        if der_len < 1 {
            return generic_bssl_err("i2d_X509");
        }

        let mut new_cert_buf = vec![0; der_len as usize];
        i2d_X509(*cert, &mut new_cert_buf.as_mut_ptr());

        // Generate key blob //
        // Magic + cbor

        let mut blob = CERT_GEN_BLOB_MAGIC.to_vec();

        let mut chain = vec![new_cert_buf.clone()];
        // attestation_key is supplied: return only newly generated cert
        // attestation_key is not supplied: return full cert chain
        if attestation_key.is_none() {
            chain.extend(cert_gen_key_blob.cert_chain.clone());
        }

        // TODO: Blob should be encrypted?
        let blob_obj = CertGenKeyBlob { private_key: key.i2d()?, cert_chain: chain };
        let cbor_blob = serde_cbor::to_vec(&blob_obj).map_err(|x| format!("Error on serialize key blob: {:?}", x))?;
        blob.extend(&cbor_blob);

        let certificate_chain = blob_obj.cert_chain.into_iter().map(|x| {
            Certificate { encodedCertificate: x }
        }).collect();
        Ok(KeyCreationResult { keyBlob: blob, keyCharacteristics: vec![sw_characteristics, tee_characteristics], certificateChain: certificate_chain })
    }
}
