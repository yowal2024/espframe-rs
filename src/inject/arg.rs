#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteArg {
    Int(i64),
    Ptr(u64),
    Str(Vec<u8>),
    Bytes { data: Vec<u8>, fixups: Vec<Fixup> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fixup {
    pub offset: usize,
    pub data: Vec<u8>,
    pub nul_terminated: bool,
}
