use common::obf;

#[test]
fn obf_decrypts_to_original() {
    assert_eq!(obf!("NtOpenProcessToken"), "NtOpenProcessToken");
}
