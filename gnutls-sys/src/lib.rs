#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]
extern crate libc;
use libc::{c_char, c_int, c_void, c_uint, size_t};

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

    // Do the rest at some point.

    pub fn gnutls_alpn_get_selected_protocol(session: *mut gnutls_session_t,
                                             protocol: *mut gnutls_datum_t)
                                             -> c_int;

    pub fn gnutls_alpn_set_protocols(session: gnutls_session_t,
                                     protocols: *const gnutls_datum_t,
                                     protocols_size: c_uint,
                                     flags: c_uint) -> c_int;

    pub fn gnutls_anon_allocate_client_credentials(sc: *mut gnutls_anon_client_credentials_t)
                                                   -> c_int;

    pub fn gnutls_anon_allocate_server_credentials(sc: *mut gnutls_anon_server_credentials_t)
                                                   -> c_int;

    pub fn gnutls_anon_free_client_credentials(sc: gnutls_anon_client_credentials_t)
                                               -> c_void;

    pub fn gnutls_anon_free_server_credentials(sc: gnutls_anon_server_credentials_t)
                                               -> c_void;

    pub fn gnutls_anon_set_params_function(res: gnutls_anon_server_credentials_t,
                                           func: extern fn(gnutls_session_t,
                                                           gnutls_param_types_t,
                                                           *mut gnutls_params_st))
                                           -> c_void;

    pub fn gnutls_anon_set_server_dh_params(res: gnutls_anon_server_credentials_t,
                                            db_params: gnutls_dh_params_t) -> c_void;

    pub fn gnutls_anon_set_server_params_function(res: gnutls_anon_server_credentials_t,
                                                  func: extern fn(gnutls_session_t,
                                                                  gnutls_param_types_t,
                                                                  *mut gnutls_params_st))
                                                  -> c_void;

    pub fn gnutls_error_is_fatal(error: c_int) -> c_int;

    pub fn gnutls_global_init() -> c_int;
    pub fn gnutls_global_deinit() -> c_int;

}
