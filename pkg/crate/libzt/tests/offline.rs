// Hermetic tests of the native bindings. No node is started and nothing is
// sent over the network.

use std::ffi::CStr;
use std::os::raw::c_char;

use libzt::*;

#[test]
fn identity_generation() {
    let mut key = [0 as c_char; ZTS_ID_STR_BUF_LEN as usize];
    let mut key_len = ZTS_ID_STR_BUF_LEN;
    unsafe {
        assert_eq!(zts_id_new(key.as_mut_ptr(), &mut key_len), zts_error_t_ZTS_ERR_OK);
        assert!(key_len > 0 && key_len < ZTS_ID_STR_BUF_LEN);
        assert_eq!(zts_id_pair_is_valid(key.as_ptr(), ZTS_ID_STR_BUF_LEN), 1);
    }
}

#[test]
fn address_computation() {
    unsafe {
        assert_eq!(zts_net_compute_adhoc_id(9000, 9100), 0xff2328238c000000);

        let mut buf = [0 as c_char; ZTS_IP_MAX_STR_LEN as usize];
        assert_eq!(
            zts_addr_compute_6plane_str(0xff07d00bb8000000, 0x75f3543094, buf.as_mut_ptr(), ZTS_IP_MAX_STR_LEN),
            zts_error_t_ZTS_ERR_OK
        );
        let addr = CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
        assert_eq!(addr, "FC47:7D0:B75:F354:3094::1");
    }
}

#[test]
fn init_settings_before_start() {
    unsafe {
        assert_eq!(zts_init_set_encrypted_hello(1), zts_error_t_ZTS_ERR_OK);
        assert_eq!(zts_init_set_encrypted_hello(0), zts_error_t_ZTS_ERR_OK);
        assert_eq!(zts_init_set_low_bandwidth_mode(1), zts_error_t_ZTS_ERR_OK);
        assert_eq!(zts_init_set_low_bandwidth_mode(0), zts_error_t_ZTS_ERR_OK);
    }
}
