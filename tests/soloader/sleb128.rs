use espframe::soloader::sleb128::Sleb128Decoder;

#[test]
fn sleb128_decodes_negative_values() {
    let mut decoder = Sleb128Decoder::new(&[0x7f]);
    assert_eq!(decoder.decode().unwrap(), -1);
}

#[test]
fn sleb128_rejects_overlong_shift() {
    let mut decoder = Sleb128Decoder::new(&[0x81; 11]);
    assert!(decoder.decode().is_err());
}
