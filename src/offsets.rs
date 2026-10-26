use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameArrayOffsets {
    pub blocks: u64,
    pub blocks_bit: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UObjectOffsets {
    pub class: u64,
    pub name: u64,
    pub index: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UStructOffsets {
    pub super_struct: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UeOffsets {
    pub g_names: u64,
    pub name_array: NameArrayOffsets,
    pub u_object: UObjectOffsets,
    pub u_struct: UStructOffsets,
}

/// Runtime offsets supplied by the host after it parses its authenticated JSON.
/// EspFrame deliberately carries no game-version defaults or JSON parser.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Offsets {
    pub ue: UeOffsets,
    pub game: BTreeMap<String, u64>,
}

impl Offsets {
    pub fn validate(&self) -> Result<(), crate::error::OffsetsError> {
        if self.ue.g_names == 0
            || self.ue.name_array.blocks == 0
            || self.ue.name_array.blocks_bit == 0
            || self.ue.name_array.blocks_bit >= 32
            || self.ue.u_object.class == 0
            || self.ue.u_object.name == 0
            || self.ue.u_object.index == 0
            || self.ue.u_struct.super_struct == 0
        {
            return Err(crate::error::OffsetsError);
        }
        Ok(())
    }

    pub fn game_offset(&self, name: &str) -> Option<u64> {
        self.game.get(name).copied()
    }

    pub fn with_game_offset(mut self, name: impl Into<String>, value: u64) -> Self {
        self.game.insert(name.into(), value);
        self
    }
}
