#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]
extern crate libc;
use libc::{c_uchar, c_char, c_int, c_void, c_uint, size_t};

pub mod consts;

pub enum gnutls_session_t {}
pub enum gnutls_close_request_t {}

pub enum gnutls_alert_level_t {}
pub enum gnutls_alert_description_t {}
pub enum gnutls_datum_t {}
pub enum gnutls_anon_client_credentials_t {}
pub enum gnutls_anon_server_credentials_t {}

pub enum gnutls_param_types_t {}
pub enum gnutls_params_st {}
pub enum gnutls_dh_params_t {}

pub enum gnutls_pk_algorithm_t {}
pub enum gnutls_sec_param_t {}

pub enum gnutls_ecc_curve_t {}
pub enum gnutls_cipher_algorithm_t {}
pub enum gnutls_kx_algorithm_t {}
pub enum gnutls_mac_algorithm_t {}
pub enum gnutls_compression_method_t {}
pub enum gnutls_certificate_type_t {}
pub enum gnutls_sign_algorithm_t {}

pub enum gnutls_digest_algorithm_t {}
pub enum gnutls_protocol_t {}

pub enum gnutls_handshake_description_t {}

extern "C" {
    pub fn gnutls_init(session: gnutls_session_t, flags: c_uint) -> c_int;
    pub fn gnutls_deinit(session: gnutls_session_t) -> c_void;
    pub fn gnutls_bye(session: gnutls_session_t, how: gnutls_close_request_t) -> c_int;
    pub fn gnutls_handshake(session: gnutls_session_t) -> c_int;

    // #define GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT ((unsigned int)-1)
    pub fn gnutls_handshake_set_timeout(session: gnutls_session_t,
                                        ms: c_uint) -> c_void;

    pub fn gnutls_rehandshake(session: gnutls_session_t) -> c_int;
    pub fn gtls_alert_get(session: gnutls_session_t)
                          -> *mut gnutls_alert_description_t;

    pub fn gnutls_alert_send(session: gnutls_session_t,
                             level: gnutls_alert_level_t,
                             desc: gnutls_alert_description_t) -> c_int;

    pub fn gnutls_alert_send_appropriate(session: gnutls_session_t,
                                         err: c_int) -> c_int;

    pub fn gnutls_alert_get_name(alert: gnutls_alert_description_t)
                                 -> *const c_char;

    pub fn gnutls_alert_get_strname(alert: gnutls_alert_description_t)
                                    -> *const c_char;

    pub fn gnutls_pk_bits_to_sec_param(algo: gnutls_pk_algorithm_t,
                                       bits: c_uint) -> gnutls_sec_param_t;

    pub fn gnutls_sec_param_get_name(param: gnutls_sec_param_t) -> *const c_char;
    pub fn gnutls_sec_param_to_pk_bits(algo: gnutls_pk_algorithm_t,
                                       param: gnutls_sec_param_t) -> c_uint;

    pub fn gnutls_sec_param_to_symmetric_bits(param: gnutls_sec_param_t)
                                              -> c_uint;

    pub fn gnutls_ecc_curve_get_name(curve: gnutls_ecc_curve_t)
                                     -> *const c_char;

    pub fn gnutls_ecc_curve_get_oid(curve: gnutls_ecc_curve_t)
                                    -> *const c_char;

    pub fn gnutls_ecc_curve_get_size(curve: gnutls_ecc_curve_t)
                                     -> c_int;

    pub fn gnutls_ecc_curve_get(session: gnutls_session_t) -> gnutls_ecc_curve_t;
    pub fn gnutls_cipher_get(session: gnutls_session_t)
                             -> gnutls_cipher_algorithm_t;

    pub fn gnutls_kx_get(session: gnutls_session_t) -> gnutls_kx_algorithm_t;
    pub fn gnutls_mac_get(session: gnutls_session_t) -> gnutls_mac_algorithm_t;
    pub fn gnutls_compression_get(session: gnutls_session_t)
                                  -> gnutls_compression_method_t;

    pub fn gnutls_certificate_type_get(session: gnutls_session_t)
                                       -> gnutls_certificate_type_t;

    pub fn gnutls_sign_algorithm_get(session: gnutls_session_t) -> c_int;
    pub fn gnutls_sign_algorithm_get_client(session: gnutls_session_t) -> c_int;
    pub fn gnutls_sign_algorithm_get_requested(session: gnutls_session_t,
                                               indx: size_t,
                                               algo: *mut gnutls_sign_algorithm_t)
                                               -> c_int;

    pub fn gnutls_cipher_get_name(algorithm: gnutls_cipher_algorithm_t) -> *const c_char;
    pub fn gnutls_mac_get_name(algorithm: gnutls_mac_algorithm_t) -> *const c_char;
    pub fn gnutls_digest_get_name(algorithm: gnutls_digest_algorithm_t) -> *const c_char;
    pub fn gnutls_digest_get_oid(algorithm: gnutls_digest_algorithm_t) -> *const c_char;
    pub fn gnutls_compression_get_name(algorithm: gnutls_compression_method_t) -> *const c_char;
    pub fn gnutls_kx_get_name(algorithm: gnutls_kx_algorithm_t) -> *const c_char;
    pub fn gnutls_certificate_type_get_name(_type: gnutls_certificate_type_t) -> *const c_char;
    pub fn gnutls_pk_get_name(algorithm: gnutls_pk_algorithm_t) -> *const c_char;
    pub fn gnutls_pk_get_oid(algorithm: gnutls_pk_algorithm_t) -> *const c_char;
    pub fn gnutls_sign_get_name(algorithm: gnutls_sign_algorithm_t) -> *const c_char;
    pub fn gnutls_sign_get_oid(algorithm: gnutls_sign_algorithm_t) -> *const c_char;
    pub fn gnutls_cipher_get_key_size(algorithm: gnutls_cipher_algorithm_t) -> size_t;
    pub fn gnutls_mac_get_key_size(algorithm: gnutls_mac_algorithm_t) -> size_t;
    pub fn gnutls_sign_is_secure(algorithm: gnutls_sign_algorithm_t) -> c_int;
    pub fn gnutls_sign_get_hash_algorithm(sign: gnutls_sign_algorithm_t)
                                          -> gnutls_digest_algorithm_t;

    pub fn gnutls_sign_get_pk_algorithm(sign: gnutls_sign_algorithm_t)
                                        -> gnutls_pk_algorithm_t;

    pub fn gnutls_pk_to_sign(pk: gnutls_pk_algorithm_t,
                             hash: gnutls_digest_algorithm_t)
                             -> gnutls_sign_algorithm_t;

    // #define gnutls_sign_algorithm_get_name gnutls_sign_get_name

    pub fn gnutls_mac_get_id(name: *const c_char) -> gnutls_mac_algorithm_t;
    pub fn gnutls_digest_get_id(name: *const c_char) -> gnutls_digest_algorithm_t;
    pub fn gnutls_compression_get_id(name: *const c_char)
                                     -> gnutls_compression_method_t;

    pub fn gnutls_cipher_get_id(name: *const c_char) -> gnutls_cipher_algorithm_t;
    pub fn gnutls_kx_get_id(name: *const c_char) -> gnutls_kx_algorithm_t;
    pub fn gnutls_protocol_get_id(name: *const c_char) -> gnutls_protocol_t;
    pub fn gnutls_certificate_type_get_id(name: *const c_char)
                                          -> gnutls_certificate_type_t;

    pub fn gnutls_pk_get_id(name: *const c_char) -> gnutls_pk_algorithm_t;
    pub fn gnutls_sign_get_id(name: *const c_char) -> gnutls_sign_algorithm_t;
    pub fn gnutls_ecc_curve_get_id(name: *const c_char) -> gnutls_ecc_curve_t;
    pub fn gnutls_oid_to_digest(oid: *const c_char) -> gnutls_digest_algorithm_t;
    pub fn gnutls_oid_to_pk(oid: *const c_char) -> gnutls_pk_algorithm_t;
    pub fn gnutls_oid_to_sign(oid: *const c_char) -> gnutls_sign_algorithm_t;
    pub fn gnutls_oid_to_ecc_curve(oid: *const c_char) -> gnutls_ecc_curve_t;

    /* list supported algorithms */
    pub fn gnutls_ecc_curve_list() -> *const gnutls_ecc_curve_t;
    pub fn gnutls_cipher_list() -> *const gnutls_cipher_algorithm_t;
    pub fn gnutls_mac_list() -> *const gnutls_mac_algorithm_t;
    pub fn gnutls_digest_list() -> *const gnutls_digest_algorithm_t;
    pub fn gnutls_compression_list() -> *const gnutls_compression_method_t;

    pub fn gnutls_protocol_list() -> *const gnutls_protocol_t;
    pub fn gnutls_certificate_type_list() -> *const gnutls_certificate_type_t;
    pub fn gnutls_kx_list() -> *const gnutls_kx_algorithm_t;
    pub fn gnutls_pk_list() -> *const gnutls_pk_algorithm_t;
    pub fn gnutls_sign_list() -> *const gnutls_sign_algorithm_t;

    pub fn gnutls_cipher_suite_info(idx: size_t,
                                    cs_id: *mut c_uchar,
                                    kx: *mut gnutls_kx_algorithm_t,
                                    cipher: *mut gnutls_cipher_algorithm_t,
                                    mac: *mut gnutls_mac_algorithm_t,
                                    min_versoin: *mut gnutls_protocol_t)
                                    -> *const c_char;

    /* error functions */
    pub fn gnutls_error_is_fatal(error: c_int) -> c_int;
    pub fn gnutls_error_to_alert(err: c_int, level: *mut c_int) -> c_int;

    pub fn gnutls_perror(error: c_int) -> c_void;
    pub fn gnutls_strerror(error: c_int) -> *const c_char;
    pub fn gnutls_strerror_name(error: c_int) -> *const c_char;

    /* Semi-internal functions. */
    pub fn gnutls_handshake_set_private_extensions(session: gnutls_session_t,
                                                   allow: c_int) -> c_void;

    pub fn gnutls_handshake_set_random(session: gnutls_session_t,
                                       random: *const gnutls_datum_t) -> c_int;

    pub fn gnutls_handshake_get_last_out(session: gnutls_session_t)
                                         -> gnutls_handshake_description_t;

    pub fn gnutls_handshake_get_last_in(session: gnutls_session_t)
                                        -> gnutls_handshake_description_t;

    /* Record layer functions. */
    pub fn gnutls_heartbeat_ping(session: gnutls_session_t,
                                 data_size: size_t,
                                 max_tries: c_uint,
                                 flags: c_uint) -> c_int;

    pub fn gnutls_heartbeat_pong(session: gnutls_session_t,
                                 flags: c_uint) -> c_int;

    pub fn gnutls_record_set_timeout(session: gnutls_session_t,
                                     ms: c_uint) -> c_void;

    pub fn gnutls_record_disable_padding(session: gnutls_session_t) -> c_void;
    pub fn gnutls_record_cork(session: gnutls_session_t) -> c_void;
    pub fn gnutls_record_uncork(session: gnutls_session_t,
                                flags: c_uint) -> c_int;

    pub fn gnutls_record_discard_queued(session: gnutls_session_t) -> size_t;
    pub fn gnutls_record_get_state(session: gnutls_session_t,
                                   read: c_uint,
                                   mac_key: *mut gnutls_datum_t,
                                   IV: *mut gnutls_datum_t,
                                   cipher_key: *mut gnutls_datum_t,
                                   seq_number: [c_uchar; 8]) -> c_int;
}
