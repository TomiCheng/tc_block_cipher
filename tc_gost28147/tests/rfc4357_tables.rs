//! The CryptoPro tables match their RFC 4357 encodings.
//!
//! RFC 4357 packs each table into 64 bytes: byte `4 * column + pair` holds row
//! `2 * pair` in its high nibble and row `2 * pair + 1` in its low nibble.

mod common;

use common::unhex;
use tc_gost28147::s_box::{self, BYTES, COLUMNS};

fn unpack(packed: &str) -> [u8; BYTES] {
    let bytes = unhex(packed);
    assert_eq!(bytes.len(), BYTES / 2);
    let mut table = [0; BYTES];
    for (index, byte) in bytes.iter().enumerate() {
        let (column, pair) = (index / 4, index % 4);
        table[2 * pair * COLUMNS + column] = byte >> 4;
        table[(2 * pair + 1) * COLUMNS + column] = byte & 0xf;
    }
    table
}

#[test]
fn the_encryption_tables_match_the_cryptopro_parameter_sets_of_section_11_1() {
    for (table, packed) in [
        (
            s_box::E_A,
            "93eeb31b67475ada3e6a1d2f292c9c9588bd8170ba31d2ac1fd3f06e70890b08\
             a5c0e78642f245c2e65b2943fca43459cb0fc8f104787f37dd15aebd519666e4",
        ),
        (
            s_box::E_B,
            "80e7285041c57324b200c2ab1aadf6be349b94985d265d1305d1aec79cb2bb31\
             29731c7ae75a4142a38c07d9cfffdf06db346a6f686e80fd7619e985fe4835ec",
        ),
        (
            s_box::E_C,
            "10838ca7b126d994c750bb602d0101859b4548dad49d5ee205fa122ff2a8240e\
             483b97fc5e7233368fc9c651ecd7e5bba96e6a4d7aeff019661cafc333b47d78",
        ),
        (
            s_box::E_D,
            "fb110831c6c5c00a23be8f66a40c93f86cfad21f4fe725eb5e60ae90025dbb24\
             77a671dc9dd23a83e84b64c5d084574915994cb7ba33e9ad897ffd523128167e",
        ),
    ] {
        assert_eq!(table, unpack(packed));
    }
}

#[test]
fn the_digest_table_matches_the_cryptopro_parameter_set_of_section_11_2() {
    assert_eq!(
        s_box::D_A,
        unpack(
            "a57477d14ffa66e354c7424a60ecb41982909d751d4fc90b3b122f547908a0af\
             d13e1a38c7b181c6e65605870325ebfe9c6df86d2eabde20ba893c92f8d353bc"
        )
    );
}
