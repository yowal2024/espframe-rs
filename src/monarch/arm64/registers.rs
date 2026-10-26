const REGISTER_COUNT: usize = 31;
const VECTOR_REGISTER_COUNT: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuState {
    pub x: [u64; REGISTER_COUNT],
    pub sp: u64,
    pub pc: u64,
    pub nzcv: u32,
    pub fpcr: u32,
    pub fpsr: u32,
    pub v: [[u8; 16]; VECTOR_REGISTER_COUNT],
}

impl Default for CpuState {
    fn default() -> Self {
        Self {
            x: [0; REGISTER_COUNT],
            sp: 0,
            pc: 0,
            nzcv: 0,
            fpcr: 0,
            fpsr: 0,
            v: [[0; 16]; VECTOR_REGISTER_COUNT],
        }
    }
}

impl CpuState {
    pub fn X(&self, index: usize) -> Result<u64, RegisterError> {
        self.x
            .get(index)
            .copied()
            .ok_or(RegisterError::InvalidIndex(index))
    }

    pub fn SetX(&mut self, index: usize, value: u64) -> Result<(), RegisterError> {
        let target = self
            .x
            .get_mut(index)
            .ok_or(RegisterError::InvalidIndex(index))?;
        *target = value;
        Ok(())
    }

    pub fn V(&self, index: usize) -> Result<&[u8; 16], RegisterError> {
        self.v
            .get(index)
            .ok_or(RegisterError::InvalidVectorIndex(index))
    }

    pub fn SetV(&mut self, index: usize, value: &[u8]) -> Result<(), RegisterError> {
        if value.len() > 16 {
            return Err(RegisterError::InvalidVectorWidth(value.len()));
        }
        let target = self
            .v
            .get_mut(index)
            .ok_or(RegisterError::InvalidVectorIndex(index))?;
        *target = [0; 16];
        target[..value.len()].copy_from_slice(value);
        Ok(())
    }

    pub(crate) fn ReadRegister(&self, register: Register) -> Result<u64, RegisterError> {
        match register {
            Register::X(index) => self.X(index as usize),
            Register::W(index) => Ok(self.X(index as usize)? as u32 as u64),
            Register::Sp => Ok(self.sp),
            Register::Wsp => Ok(self.sp as u32 as u64),
            Register::Xzr | Register::Wzr => Ok(0),
            Register::Vector { index, width } => {
                let bytes = self.V(index as usize)?;
                let count = usize::from(width / 8).min(8);
                let mut value = [0; 8];
                value[..count].copy_from_slice(&bytes[..count]);
                Ok(u64::from_le_bytes(value))
            }
        }
    }

    pub(crate) fn WriteRegister(
        &mut self,
        register: Register,
        value: u64,
    ) -> Result<(), RegisterError> {
        match register {
            Register::X(index) => self.SetX(index as usize, value),
            Register::W(index) => self.SetX(index as usize, value as u32 as u64),
            Register::Sp => {
                self.sp = value;
                Ok(())
            }
            Register::Wsp => {
                self.sp = value as u32 as u64;
                Ok(())
            }
            Register::Xzr | Register::Wzr => Ok(()),
            Register::Vector { index, width } => {
                let target = self
                    .v
                    .get_mut(index as usize)
                    .ok_or(RegisterError::InvalidVectorIndex(index as usize))?;
                let count = usize::from(width / 8).min(8);
                target[..count].copy_from_slice(&value.to_le_bytes()[..count]);
                if width < 128 {
                    target[count..].fill(0);
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Register {
    X(u8),
    W(u8),
    Sp,
    Wsp,
    Xzr,
    Wzr,
    Vector { index: u8, width: u8 },
}

impl Register {
    pub fn Width(self) -> u8 {
        match self {
            Self::W(_) | Self::Wsp | Self::Wzr => 32,
            Self::Vector { width, .. } => width,
            _ => 64,
        }
    }

    pub fn VectorIndex(self) -> Option<usize> {
        match self {
            Self::Vector { index, .. } => Some(index as usize),
            _ => None,
        }
    }

    pub(crate) fn Parse(name: &str) -> Result<Self, RegisterError> {
        match name {
            "sp" => return Ok(Self::Sp),
            "wsp" => return Ok(Self::Wsp),
            "xzr" => return Ok(Self::Xzr),
            "wzr" => return Ok(Self::Wzr),
            "fp" => return Ok(Self::X(29)),
            "lr" => return Ok(Self::X(30)),
            _ => {}
        }
        let (prefix, digits) = name.split_at(1.min(name.len()));
        let index = digits
            .parse::<u8>()
            .map_err(|_| RegisterError::Unknown(name.to_owned()))?;
        match prefix {
            "x" if index <= 30 => Ok(Self::X(index)),
            "w" if index <= 30 => Ok(Self::W(index)),
            "v" | "q" if index <= 31 => Ok(Self::Vector { index, width: 128 }),
            "d" if index <= 31 => Ok(Self::Vector { index, width: 64 }),
            "s" if index <= 31 => Ok(Self::Vector { index, width: 32 }),
            "h" if index <= 31 => Ok(Self::Vector { index, width: 16 }),
            "b" if index <= 31 => Ok(Self::Vector { index, width: 8 }),
            _ => Err(RegisterError::Unknown(name.to_owned())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorArrangement {
    pub element_bits: u8,
    pub lanes: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    Eq,
    Ne,
    Hs,
    Lo,
    Mi,
    Pl,
    Vs,
    Vc,
    Hi,
    Ls,
    Ge,
    Lt,
    Gt,
    Le,
    Al,
    Nv,
    None,
}

impl Condition {
    pub(crate) fn Holds(self, nzcv: u32) -> bool {
        let n = nzcv & (1 << 31) != 0;
        let z = nzcv & (1 << 30) != 0;
        let c = nzcv & (1 << 29) != 0;
        let v = nzcv & (1 << 28) != 0;
        match self {
            Self::Eq => z,
            Self::Ne => !z,
            Self::Hs => c,
            Self::Lo => !c,
            Self::Mi => n,
            Self::Pl => !n,
            Self::Vs => v,
            Self::Vc => !v,
            Self::Hi => c && !z,
            Self::Ls => !c || z,
            Self::Ge => n == v,
            Self::Lt => n != v,
            Self::Gt => !z && n == v,
            Self::Le => z || n != v,
            Self::Al | Self::Nv | Self::None => true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegisterError {
    #[error("invalid general register index {0}")]
    InvalidIndex(usize),
    #[error("invalid vector register index {0}")]
    InvalidVectorIndex(usize),
    #[error("invalid vector width {0}")]
    InvalidVectorWidth(usize),
    #[error("unknown AArch64 register {0}")]
    Unknown(String),
}
