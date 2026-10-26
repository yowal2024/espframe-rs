use espframe::soloader::carray::CStringArray;

#[test]
fn carray_adds_and_removes_strings() {
    let mut arr = CStringArray::with_capacity(1);
    assert!(arr.add("libone.so"));
    assert!(arr.add("libtwo.so"));
    assert!(arr.exists("libone.so"));
    assert!(arr.remove("libone.so"));
    assert!(!arr.exists("libone.so"));
    assert_eq!(arr.len(), 1);
}
