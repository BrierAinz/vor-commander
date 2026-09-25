// SPDX-License-Identifier: MPL-2.0

use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::pki_types::{
    CertificateDer, CertificateSigningRequestDer, PrivateKeyDer, PrivatePkcs8KeyDer,
};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::sync::Arc;
use thiserror::Error;
use time::{Duration as TimeDuration, OffsetDateTime};
use vor_secrets::{FileSecretStore, SecretError};

const DEVICE_CERT_DAYS: i64 = 90;
const SERVER_CERT_DAYS: i64 = 30;
const CA_CERT_DAYS: i64 = 3650;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEnrollment {
    pub device_id: String,
    pub csr_der: Vec<u8>,
}

pub struct IssuedCertificate {
    pub certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

impl IssuedCertificate {
    pub fn private_key_der(&self) -> &[u8] {
        &self.private_key_der
    }
}

impl std::fmt::Debug for IssuedCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedCertificate")
            .field("certificate_der_bytes", &self.certificate_der.len())
            .field("private_key_der", &"<redacted>")
            .finish()
    }
}
pub struct CertificateAuthority {
    certificate: Certificate,
    issuer: Issuer<'static, KeyPair>,
}

impl CertificateAuthority {
    pub fn new(common_name: &str) -> Result<Self, IdentityError> {
        validate_label(common_name)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name = distinguished_name(common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        apply_validity(&mut params, CA_CERT_DAYS)?;
        let key_pair = KeyPair::generate()?;
        let certificate = params.self_signed(&key_pair)?;
        let issuer = Issuer::new(params, key_pair);
        Ok(Self {
            certificate,
            issuer,
        })
    }

    pub fn certificate_der(&self) -> Vec<u8> {
        self.certificate.der().to_vec()
    }

    pub fn sign_device_csr(
        &self,
        authorized_device_id: &str,
        csr_der: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        validate_device_id(authorized_device_id)?;
        let csr_der = CertificateSigningRequestDer::from(csr_der.to_vec());
        let mut request = CertificateSigningRequestParams::from_der(&csr_der)?;
        request.params.distinguished_name = distinguished_name(authorized_device_id);
        request.params.subject_alt_names = vec![device_uri(authorized_device_id)?];
        request.params.is_ca = IsCa::NoCa;
        request.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        request.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        request.params.use_authority_key_identifier_extension = true;
        apply_validity(&mut request.params, DEVICE_CERT_DAYS)?;
        Ok(request.signed_by(&self.issuer)?.der().to_vec())
    }
}
impl CertificateAuthority {
    pub fn issue_server_certificate(
        &self,
        dns_name: &str,
    ) -> Result<IssuedCertificate, IdentityError> {
        validate_label(dns_name)?;
        let mut params = CertificateParams::new(vec![dns_name.to_owned()])?;
        params.distinguished_name = distinguished_name(dns_name);
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        apply_validity(&mut params, SERVER_CERT_DAYS)?;
        let key_pair = KeyPair::generate()?;
        let certificate = params.signed_by(&key_pair, &self.issuer)?;
        Ok(IssuedCertificate {
            certificate_der: certificate.der().to_vec(),
            private_key_der: key_pair.serialize_der(),
        })
    }
}

pub fn create_device_enrollment(
    store: &FileSecretStore,
    key_name: &str,
    device_id: &str,
) -> Result<DeviceEnrollment, IdentityError> {
    validate_device_id(device_id)?;
    if store.contains(key_name)? {
        return Err(IdentityError::KeyAlreadyExists);
    }
    let key_pair = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = distinguished_name(device_id);
    params.subject_alt_names = vec![device_uri(device_id)?];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let csr = params.serialize_request(&key_pair)?;
    store.put(key_name, &key_pair.serialize_der())?;
    Ok(DeviceEnrollment {
        device_id: device_id.to_owned(),
        csr_der: csr.der().to_vec(),
    })
}
pub fn load_device_private_key(
    store: &FileSecretStore,
    key_name: &str,
) -> Result<PrivateKeyDer<'static>, IdentityError> {
    let secret = store.get(key_name)?;
    let key = PrivatePkcs8KeyDer::from(secret.into_vec());
    Ok(PrivateKeyDer::Pkcs8(key))
}

pub fn client_tls_config(
    ca_der: &[u8],
    device_cert_der: &[u8],
    device_key: PrivateKeyDer<'static>,
) -> Result<Arc<ClientConfig>, IdentityError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .map_err(|error| IdentityError::Tls(error.to_string()))?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![CertificateDer::from(device_cert_der.to_vec())],
            device_key,
        )
        .map_err(|error| IdentityError::Tls(error.to_string()))?;
    Ok(Arc::new(config))
}

pub fn server_tls_config(
    ca_der: &[u8],
    server_cert_der: &[u8],
    server_key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, IdentityError> {
    let mut client_roots = RootCertStore::empty();
    client_roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .map_err(|error| IdentityError::Tls(error.to_string()))?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .map_err(|error| IdentityError::Tls(error.to_string()))?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(server_cert_der.to_vec())],
            server_key,
        )
        .map_err(|error| IdentityError::Tls(error.to_string()))?;
    Ok(Arc::new(config))
}
impl IssuedCertificate {
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.certificate_der, self.private_key_der)
    }
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name.push(DnType::OrganizationName, "Vör Commander");
    name
}

fn device_uri(device_id: &str) -> Result<SanType, IdentityError> {
    let value = format!("urn:vor:device:{device_id}");
    let value = Ia5String::try_from(value).map_err(|_| IdentityError::InvalidDeviceId)?;
    Ok(SanType::URI(value))
}

fn validate_device_id(value: &str) -> Result<(), IdentityError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(IdentityError::InvalidDeviceId);
    }
    Ok(())
}

fn validate_label(value: &str) -> Result<(), IdentityError> {
    if value.trim().is_empty() || value.len() > 253 || value.contains('\0') {
        return Err(IdentityError::InvalidLabel);
    }
    Ok(())
}

fn apply_validity(params: &mut CertificateParams, days: i64) -> Result<(), IdentityError> {
    let now = OffsetDateTime::now_utc();
    params.not_before = now
        .checked_sub(TimeDuration::minutes(5))
        .ok_or(IdentityError::Clock)?;
    params.not_after = now
        .checked_add(TimeDuration::days(days))
        .ok_or(IdentityError::Clock)?;
    Ok(())
}
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("device id is invalid")]
    InvalidDeviceId,
    #[error("certificate label is invalid")]
    InvalidLabel,
    #[error("device private key already exists")]
    KeyAlreadyExists,
    #[error("certificate validity window could not be created")]
    Clock,
    #[error("certificate operation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("secret store failed: {0}")]
    Secret(#[from] SecretError),
    #[error("TLS configuration failed: {0}")]
    Tls(String),
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::fs;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[test]
    fn enrollment_private_key_is_dpapi_protected_and_not_overwritten() {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::open(dir.path()).unwrap();
        let enrollment = create_device_enrollment(&store, "device-key", "device-1").unwrap();
        assert!(!enrollment.csr_der.is_empty());
        let key = store.get("device-key").unwrap();
        let disk = fs::read(dir.path().join("device-key.dpapi")).unwrap();
        assert!(
            !disk
                .windows(key.as_slice().len())
                .any(|window| window == key.as_slice())
        );
        assert!(matches!(
            create_device_enrollment(&store, "device-key", "device-1"),
            Err(IdentityError::KeyAlreadyExists)
        ));
    }
    #[tokio::test]
    async fn csr_signed_device_identity_completes_mutual_tls() {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::open(dir.path()).unwrap();
        let enrollment = create_device_enrollment(&store, "device-key", "claimed-device").unwrap();
        let ca = CertificateAuthority::new("Vör Test CA").unwrap();
        let ca_der = ca.certificate_der();

        // The issuer chooses the authorized identity; it does not trust the CSR label.
        let device_cert = ca
            .sign_device_csr("authorized-device", &enrollment.csr_der)
            .unwrap();
        let device_key = load_device_private_key(&store, "device-key").unwrap();
        let client_config = client_tls_config(&ca_der, &device_cert, device_key).unwrap();

        let server = ca.issue_server_certificate("localhost").unwrap();
        let (server_cert, server_key) = server.into_parts();
        let server_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key));
        let server_config = server_tls_config(&ca_der, &server_cert, server_key).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(server_config);
        let expected_device_cert = device_cert.clone();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            let peer = tls.get_ref().1.peer_certificates().unwrap();
            assert_eq!(peer[0].as_ref(), expected_device_cert.as_slice());
            let mut ping = [0u8; 4];
            tls.read_exact(&mut ping).await.unwrap();
            assert_eq!(&ping, b"ping");
            tls.write_all(b"pong").await.unwrap();
            tls.flush().await.unwrap();
        });
        let connector = TlsConnector::from(client_config);
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(server_name, stream).await.unwrap();
        tls.write_all(b"ping").await.unwrap();
        tls.flush().await.unwrap();
        let mut pong = [0u8; 4];
        tls.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
        server_task.await.unwrap();
    }

    #[test]
    fn issued_certificate_debug_does_not_print_private_key() {
        let ca = CertificateAuthority::new("Vör Test CA").unwrap();
        let issued = ca.issue_server_certificate("localhost").unwrap();
        let key_prefix = hex::encode(&issued.private_key_der()[..8]);
        assert!(!format!("{issued:?}").contains(&key_prefix));
    }
}

pub fn certificate_der_to_pem(certificate_der: &[u8]) -> String {
    pem_encode("CERTIFICATE", certificate_der)
}

pub fn private_key_der_to_pem(private_key_der: &[u8]) -> String {
    pem_encode("PRIVATE KEY", private_key_der)
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    let encoded = STANDARD.encode(der);
    let mut output = String::new();
    output.push_str("-----BEGIN ");
    output.push_str(label);
    output.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        output.push('\n');
    }
    output.push_str("-----END ");
    output.push_str(label);
    output.push_str("-----\n");
    output
}
