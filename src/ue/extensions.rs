#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FName {
    pub comparison_index: u32,
    pub number: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UClass {
    pub address: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TArrayHeader {
    pub data: u64,
    pub count: i32,
    pub capacity: i32,
}
