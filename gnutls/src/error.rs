#![allow(dead_code)]
use std::fmt;
use std::mem;

use gt::consts::*;
use gt::gen:: {
    gnutls_error_is_fatal
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Error {
    None = GNUTLS_E_SUCCESS,
    UknownComressionAlgorithm = GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM,
    UnknownCipherType = GNUTLS_E_UNKNOWN_CIPHER_TYPE,
    LargePacket = GNUTLS_E_LARGE_PACKET,
    UnsupportedVersionPacket = GNUTLS_E_UNSUPPORTED_VERSION_PACKET,
    UnexpectedPacketLength = GNUTLS_E_UNEXPECTED_PACKET_LENGTH,
    InvalidSession = GNUTLS_E_INVALID_SESSION,
    FatalAlertReceived = GNUTLS_E_FATAL_ALERT_RECEIVED,
    UnexpectedPacket = GNUTLS_E_UNEXPECTED_PACKET,
    WarningAlertReceived = GNUTLS_E_WARNING_ALERT_RECEIVED,
    ErrorInFinishedPacket = GNUTLS_E_ERROR_IN_FINISHED_PACKET,
    UnexpectedHandshakePacket = GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET,
    UnknownCipherSuite = GNUTLS_E_UNKNOWN_CIPHER_SUITE,
    UnwantedAlgorithm = GNUTLS_E_UNWANTED_ALGORITHM,
    MPIScanFailed = GNUTLS_E_MPI_SCAN_FAILED,
    DecryptionFailed = GNUTLS_E_DECRYPTION_FAILED,
    MemoryError = GNUTLS_E_MEMORY_ERROR,

    DecompressionFailed = GNUTLS_E_DECOMPRESSION_FAILED,
    CompressionFailed = GNUTLS_E_COMPRESSION_FAILED,
    Again = GNUTLS_E_AGAIN,
    Expired = GNUTLS_E_EXPIRED,
    DbError = GNUTLS_E_DB_ERROR,
    SRPPasswordError = GNUTLS_E_SRP_PWD_ERROR,
    InsufficientCredentials = GNUTLS_E_INSUFFICIENT_CREDENTIALS,
    HashFailed = GNUTLS_E_HASH_FAILED,
    Base64DecodingError = GNUTLS_E_BASE64_DECODING_ERROR,
    MPIPrintFailed = GNUTLS_E_MPI_PRINT_FAILED,
    Rehandshake = GNUTLS_E_REHANDSHAKE,
    GotApplicationData = GNUTLS_E_GOT_APPLICATION_DATA,
    RecordLimitReached = GNUTLS_E_RECORD_LIMIT_REACHED,
    EncryptionFailed = GNUTLS_E_ENCRYPTION_FAILED,
    PKEncryptionFailed = GNUTLS_E_PK_ENCRYPTION_FAILED,
    PKDecryptionFailed = GNUTLS_E_PK_DECRYPTION_FAILED,
    PKSignFailed = GNUTLS_E_PK_SIGN_FAILED,
    X509UnsupportedCriticalExtension = GNUTLS_E_X509_UNSUPPORTED_CRITICAL_EXTENSION,
    KeyUsageViolation = GNUTLS_E_KEY_USAGE_VIOLATION,
    NoCertificateFound = GNUTLS_E_NO_CERTIFICATE_FOUND,
    InvalidRequest = GNUTLS_E_INVALID_REQUEST,
    ShortMemoryBuffer = GNUTLS_E_SHORT_MEMORY_BUFFER,
    Interrupted = GNUTLS_E_INTERRUPTED,
    PushError = GNUTLS_E_PUSH_ERROR,
    PullError = GNUTLS_E_PULL_ERROR,
    ReceivedIllegalParameter = GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER,
    RequestedDataNotAvailable = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE,
    PKCS11WrongPad = GNUTLS_E_PKCS1_WRONG_PAD,
    ReceivedIllegalExtension = GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION,
    InternalError = GNUTLS_E_INTERNAL_ERROR,
    DHPrimeUnacceptable = GNUTLS_E_DH_PRIME_UNACCEPTABLE,
    FileError = GNUTLS_E_FILE_ERROR,
    TooManyEmptyPackets = GNUTLS_E_TOO_MANY_EMPTY_PACKETS,
    UnknownPKAlgorithm = GNUTLS_E_UNKNOWN_PK_ALGORITHM,
    TooManyHandshakePackets = GNUTLS_E_TOO_MANY_HANDSHAKE_PACKETS,
    NoTemporaryRSAParams = GNUTLS_E_NO_TEMPORARY_RSA_PARAMS,
    NoComressionAlgorithms = GNUTLS_E_NO_COMPRESSION_ALGORITHMS,
    NoCipherSuites = GNUTLS_E_NO_CIPHER_SUITES,
    OpenPGPGetKeyFailed = GNUTLS_E_OPENPGP_GETKEY_FAILED,
    PKSigVerifyFailed = GNUTLS_E_PK_SIG_VERIFY_FAILED,
    IllegalSRPUsername = GNUTLS_E_ILLEGAL_SRP_USERNAME,
    SRPPasswordParsingError = GNUTLS_E_SRP_PWD_PARSING_ERROR,
    NoTemporaryDHParams = GNUTLS_E_NO_TEMPORARY_DH_PARAMS,

    ASN1ElementNotFound = GNUTLS_E_ASN1_ELEMENT_NOT_FOUND,
    ASN1IdentifierNotFound = GNUTLS_E_ASN1_IDENTIFIER_NOT_FOUND,
    ASN1DERError = GNUTLS_E_ASN1_DER_ERROR,
    ASN1ValueNotFound = GNUTLS_E_ASN1_VALUE_NOT_FOUND,
    ASN1GenericError = GNUTLS_E_ASN1_GENERIC_ERROR,
    ASN1ValueNotValid = GNUTLS_E_ASN1_VALUE_NOT_VALID,
    ASN1TagError = GNUTLS_E_ASN1_TAG_ERROR,
    ASN1TagImplicit = GNUTLS_E_ASN1_TAG_IMPLICIT,
    ASN1TypeAnyError = GNUTLS_E_ASN1_TYPE_ANY_ERROR,
    ASN1SyntaxError = GNUTLS_E_ASN1_SYNTAX_ERROR,
    ASN1DEROverflow = GNUTLS_E_ASN1_DER_OVERFLOW,

    OpenPGPUIDRevoked = GNUTLS_E_OPENPGP_UID_REVOKED,

    CertificateError = GNUTLS_E_CERTIFICATE_ERROR,
    CertificateKeyMismatch = GNUTLS_E_CERTIFICATE_KEY_MISMATCH,
    UnsupportedCertificateType = GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE,
    X509UnknownSAN = GNUTLS_E_X509_UNKNOWN_SAN,
    OpenPGPFingerprintUnsupported = GNUTLS_E_OPENPGP_FINGERPRINT_UNSUPPORTED,
    X509UnsupportedAttribute = GNUTLS_E_X509_UNSUPPORTED_ATTRIBUTE,
    UnknownHashAlgorithm = GNUTLS_E_UNKNOWN_HASH_ALGORITHM,
    UnknownPKCSContentType = GNUTLS_E_UNKNOWN_PKCS_CONTENT_TYPE,
    UnknownPKCSBagType = GNUTLS_E_UNKNOWN_PKCS_BAG_TYPE,
    InvalidPassword = GNUTLS_E_INVALID_PASSWORD,
    MACVerifyFailed = GNUTLS_E_MAC_VERIFY_FAILED,
    ConstraintError = GNUTLS_E_CONSTRAINT_ERROR,
    WarningIAIPHFReceived = GNUTLS_E_WARNING_IA_IPHF_RECEIVED,
    WarningIAFPHFReceived = GNUTLS_E_WARNING_IA_FPHF_RECEIVED,
    IAVerifyFailed = GNUTLS_E_IA_VERIFY_FAILED,

    UnkownAlgorithm = GNUTLS_E_UNKNOWN_ALGORITHM,
    UnsupporteedSignatureAlgorithm = GNUTLS_E_UNSUPPORTED_SIGNATURE_ALGORITHM,
    SafeRenegotiationFailed = GNUTLS_E_SAFE_RENEGOTIATION_FAILED,
    UnsafeRenegotiationDenied = GNUTLS_E_UNSAFE_RENEGOTIATION_DENIED,
    UnknownSRPUsername = GNUTLS_E_UNKNOWN_SRP_USERNAME,
    PrematureTermination = GNUTLS_E_PREMATURE_TERMINATION,
    Base64EncodingError = GNUTLS_E_BASE64_ENCODING_ERROR,
    IncompatibleCryptoLibrary = GNUTLS_E_INCOMPATIBLE_CRYPTO_LIBRARY,
    IncompatibleLibASN1Library = GNUTLS_E_INCOMPATIBLE_LIBTASN1_LIBRARY,
    OpenPGPKeyringError = GNUTLS_E_OPENPGP_KEYRING_ERROR,
    X509UnsupportedOID = GNUTLS_E_X509_UNSUPPORTED_OID,
    RandomFailed = GNUTLS_E_RANDOM_FAILED,
    Base64UnexpectedHeaderError = GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR,
    OpenPGPSubkeyError = GNUTLS_E_OPENPGP_SUBKEY_ERROR,
    AlreadyRegistered = GNUTLS_E_ALREADY_REGISTERED,
    HandshakeTooLarge = GNUTLS_E_HANDSHAKE_TOO_LARGE,
    CryptoDevIOCTLError = GNUTLS_E_CRYPTODEV_IOCTL_ERROR,
    CryptoDevDeviceError = GNUTLS_E_CRYPTODEV_DEVICE_ERROR,
    ChannelBindingNotAvailable = GNUTLS_E_CHANNEL_BINDING_NOT_AVAILABLE,
    BadCookie = GNUTLS_E_BAD_COOKIE,
    PreferredKeyError = GNUTLS_E_OPENPGP_PREFERRED_KEY_ERROR,
    IncompatDSAKeyWithTLSProtocol = GNUTLS_E_INCOMPAT_DSA_KEY_WITH_TLS_PROTOCOL,
    InsufficientSecurity = GNUTLS_E_INSUFFICIENT_SECURITY,

    HeartbeatPongReceived = GNUTLS_E_HEARTBEAT_PONG_RECEIVED,
    HeartbeatPingReceived = GNUTLS_E_HEARTBEAT_PING_RECEIVED,
    ParsingError = GNUTLS_E_PARSING_ERROR,
    LockingError = GNUTLS_E_LOCKING_ERROR,

    PKCS11PinError = GNUTLS_E_PKCS11_PIN_ERROR,
    PKCS11SlotError = GNUTLS_E_PKCS11_SLOT_ERROR,
    PKCS11Error = GNUTLS_E_PKCS11_ERROR,
    PKCS11LoadError = GNUTLS_E_PKCS11_LOAD_ERROR,
    PKCS11AttributeError = GNUTLS_E_PKCS11_ATTRIBUTE_ERROR,
    PKCS11DeviceError = GNUTLS_E_PKCS11_DEVICE_ERROR,
    PKCS11DataError = GNUTLS_E_PKCS11_DATA_ERROR,
    PKCS11UnsupportedFeatureError = GNUTLS_E_PKCS11_UNSUPPORTED_FEATURE_ERROR,
    PKCS11KeyError = GNUTLS_E_PKCS11_KEY_ERROR,
    PKCS11PINExpired = GNUTLS_E_PKCS11_PIN_EXPIRED,
    PKCS11PINLocked = GNUTLS_E_PKCS11_PIN_LOCKED,
    PKCS11SessionError = GNUTLS_E_PKCS11_SESSION_ERROR,
    PKCS11SignatureError = GNUTLS_E_PKCS11_SIGNATURE_ERROR,
    PKCS11TokenError = GNUTLS_E_PKCS11_TOKEN_ERROR,
    PKCS11UserError = GNUTLS_E_PKCS11_USER_ERROR,

    SocketsInitError = GNUTLS_E_SOCKETS_INIT_ERROR,
    CryptoInitFailed = GNUTLS_E_CRYPTO_INIT_FAILED,

    Timeout = GNUTLS_E_TIMEDOUT,
    UserError = GNUTLS_E_USER_ERROR,
    ECCNoSupportedCurves = GNUTLS_E_ECC_NO_SUPPORTED_CURVES,
    ECCUnsupportedCurve = GNUTLS_E_ECC_UNSUPPORTED_CURVE,
    PKCS11RequestObjectNotAvailable = GNUTLS_E_PKCS11_REQUESTED_OBJECT_NOT_AVAILBLE,
    CertificateListUnsorted = GNUTLS_E_CERTIFICATE_LIST_UNSORTED,
    IllegalParameter = GNUTLS_E_ILLEGAL_PARAMETER,
    NoPrioritiesWereSet = GNUTLS_E_NO_PRIORITIES_WERE_SET,
    X509UnsupportedExtension = GNUTLS_E_X509_UNSUPPORTED_EXTENSION,
    SessionEOF = GNUTLS_E_SESSION_EOF,

    TPMError = GNUTLS_E_TPM_ERROR,
    TPMKeyPasswordError = GNUTLS_E_TPM_KEY_PASSWORD_ERROR,
    TPMSRKPasswordError = GNUTLS_E_TPM_SRK_PASSWORD_ERROR,
    TPMSessionError = GNUTLS_E_TPM_SESSION_ERROR,
    TPMKeyNotFound = GNUTLS_E_TPM_KEY_NOT_FOUND,
    TPMUninitialized = GNUTLS_E_TPM_UNINITIALIZED,
    TPMNoLib = GNUTLS_E_TPM_NO_LIB,

    NoCertificateStatus = GNUTLS_E_NO_CERTIFICATE_STATUS,
    OSCPResponseError = GNUTLS_E_OCSP_RESPONSE_ERROR,
    RandomDeviceError = GNUTLS_E_RANDOM_DEVICE_ERROR,
    AuthError = GNUTLS_E_AUTH_ERROR,
    NoApplicationProtocol = GNUTLS_E_NO_APPLICATION_PROTOCOL,

    KeyImportFailed = GNUTLS_E_KEY_IMPORT_FAILED,
    InappropriateFallback = GNUTLS_E_INAPPROPRIATE_FALLBACK,
    CertificateVerificationError = GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR,
    SelfTestError = GNUTLS_E_SELF_TEST_ERROR,
    NoSelfTest = GNUTLS_E_NO_SELF_TEST,
    LibInErrorState = GNUTLS_E_LIB_IN_ERROR_STATE,
    PKGenerationError = GNUTLS_E_PK_GENERATION_ERROR,
    IDNAError = GNUTLS_E_IDNA_ERROR,
    NeedFallback = GNUTLS_E_NEED_FALLBACK,
    UnimplementedFeature = GNUTLS_E_UNIMPLEMENTED_FEATURE,

    ApplicationErrorMax = GNUTLS_E_APPLICATION_ERROR_MAX,
    ApplicationErrorMin = GNUTLS_E_APPLICATION_ERROR_MIN
}

impl Error {
    /// Checks to see if an error code is fatal.
    pub fn is_fatal(err: Error) -> bool {
        unsafe {
            let res = gnutls_error_is_fatal(err as i32);
            res != 0
        }
    }
}

pub trait AsError {
    fn as_error(&self) -> Error;
}

impl AsError for i32 {
    fn as_error(&self) -> Error {
        unsafe {
            mem::transmute(*self)
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let val: i32 =  mem::transmute(*self);
            write!(fmt, "{}", val)
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let val: i32 =  mem::transmute(*self);
            write!(fmt, "{}", val)
        }
    }
}

#[test]
fn test_is_fatal() {
    assert_eq!(Error::is_fatal(Error::None), false);
    assert_eq!(Error::is_fatal(Error::FatalAlertReceived), true);
    assert_eq!(Error::None, 0.as_error());
    assert_eq!(Error::DecompressionFailed, (-26).as_error());
}
