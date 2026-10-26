use capstone::arch::arm64::{
    ArchMode, Arm64CC, Arm64Extender, Arm64OperandType, Arm64Shift, Arm64Vas,
};
use capstone::prelude::*;

use super::{Condition, Register, RegisterError, VectorArrangement};

#[derive(Clone, Debug, PartialEq)]
pub struct DecodedInstruction {
    pub pc: u64,
    pub word: u32,
    pub mnemonic: Mnemonic,
    pub mnemonic_text: String,
    pub operand_text: String,
    pub operands: Vec<Operand>,
    pub condition: Condition,
    pub updates_flags: bool,
    pub writeback: bool,
    pub address_mode: AddressMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mnemonic {
    Add,
    Adds,
    Sub,
    Subs,
    Adc,
    Adcs,
    Sbc,
    Sbcs,
    Mov,
    Ins,
    Umov,
    Movk,
    Movn,
    Movz,
    Mvn,
    Neg,
    Sxtw,
    Bfm,
    Sbfm,
    Ubfm,
    Ubfiz,
    Ubfx,
    Bfi,
    Sbfx,
    Bfxil,
    Bfc,
    Sbfiz,
    And,
    Ands,
    Bic,
    Bics,
    Orr,
    Orn,
    Eor,
    Eon,
    Lsl,
    Lsr,
    Asr,
    Ror,
    Clz,
    Rbit,
    Rev,
    Rev16,
    Rev32,
    Extr,
    Madd,
    Msub,
    Mul,
    Umaddl,
    Umsubl,
    Smaddl,
    Smull,
    Umull,
    Smulh,
    Umulh,
    Smsubl,
    Udiv,
    Sdiv,
    Cmp,
    Cmn,
    Tst,
    Ccmp,
    Ccmn,
    Csel,
    Cset,
    Csinc,
    Csinv,
    Csneg,
    Adr,
    Adrp,
    B,
    Bl,
    Br,
    Blr,
    Ret,
    Braa,
    Brab,
    Blraa,
    Blrab,
    Retaa,
    Retab,
    Eretaa,
    Eretab,
    Cbz,
    Cbnz,
    Tbz,
    Tbnz,
    Addg,
    Subg,
    Gmi,
    Irg,
    Subp,
    Subps,
    Ldr,
    Ldurb,
    Ldur,
    Ldrb,
    Ldrh,
    Ldrsb,
    Ldrsh,
    Ldrsw,
    Str,
    Stur,
    Ldpsw,
    Ldurh,
    Ldursb,
    Ldursh,
    Ldursw,
    Ld1,
    Strb,
    Strh,
    Sturb,
    Sturh,
    Ldp,
    Stp,
    Ldxr,
    Ldaxr,
    Stxr,
    Stlxr,
    Cas,
    Casp,
    Ldraa,
    Ldrab,
    Ldadd,
    Ldclr,
    Ldeor,
    Ldset,
    Ldsmax,
    Ldsmin,
    Ldumax,
    Ldumin,
    Swp,
    Ldclrp,
    Ldsetp,
    Swpp,
    Rcwcas,
    Rcwscas,
    Rcwclr,
    Rcwsclr,
    Rcwset,
    Rcwsset,
    Rcwswp,
    Rcwsswp,
    Rcwcasp,
    Rcwscasp,
    Rcwclrp,
    Rcwsclrp,
    Rcwsetp,
    Rcwssetp,
    Rcwswpp,
    Rcwsswpp,
    Ldfadd,
    Ldfmax,
    Ldfmin,
    Ldfmaxnm,
    Ldfminnm,
    Ldbfadd,
    Ldbfmax,
    Ldbfmin,
    Ldbfmaxnm,
    Ldbfminnm,
    Ld64b,
    St64b,
    St64bv,
    St64bv0,
    Ldg,
    Ldgm,
    Stg,
    Stgm,
    Stgp,
    Stzg,
    Stzgm,
    St2g,
    Stz2g,
    MopsCopy,
    MopsSet,
    MopsSetg,
    MopsSetgo,
    Gcspopcx,
    Gcspopm,
    Gcspopx,
    Gcspushm,
    Gcspushx,
    Gcsss1,
    Gcsss2,
    Svc,
    Mrs,
    Msr,
    Pacga,
    Pacia,
    Pacib,
    Pacda,
    Pacdb,
    Autia,
    Autib,
    Autda,
    Autdb,
    Xpaci,
    Xpacd,
    PaciaSp,
    PacibSp,
    AutiaSp,
    AutibSp,
    Fmov,
    Ucvtf,
    Scvtf,
    Fcvtzu,
    Fcvtzs,
    Fabs,
    Fneg,
    Fsqrt,
    Fmax,
    Fmin,
    Fmaxnm,
    Fminnm,
    Fnmul,
    Fcmp,
    Fcmpe,
    Fcsel,
    Fadd,
    Fsub,
    Fmul,
    Fdiv,
    Fmadd,
    Fmsub,
    Fnmadd,
    Fnmsub,
    Fmla,
    Fmls,
    Movi,
    Bit,
    Bif,
    Bsl,
    Dup,
    Cmeq,
    Cmhs,
    Uzp1,
    Uzp2,
    Addv,
    Addp,
    Umaxp,
    Ushl,
    Xtn,
    Xtn2,
    Nop,
    Hint,
    Dmb,
    Dsb,
    Isb,
    Ic,
    Dc,
    Prfm,
    Clrex,
    Brk,
    Unsupported(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Operand {
    Register(RegisterOperand),
    Immediate(i64),
    Memory(MemoryOperand),
    SystemRegister(u32),
    FloatingImmediate(f64),
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterOperand {
    pub register: Register,
    pub shift: Shift,
    pub extend: Extend,
    pub arrangement: Option<VectorArrangement>,
    pub lane: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryOperand {
    pub base: Register,
    pub index: Option<Register>,
    pub displacement: i64,
    pub shift: Shift,
    pub extend: Extend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Shift {
    #[default]
    None,
    Lsl(u32),
    Lsr(u32),
    Asr(u32),
    Ror(u32),
    Msl(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Extend {
    #[default]
    None,
    Uxtb,
    Uxth,
    Uxtw,
    Uxtx,
    Sxtb,
    Sxth,
    Sxtw,
    Sxtx,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AddressMode {
    #[default]
    Offset,
    PreIndex,
    PostIndex,
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("failed to initialize Capstone ARM64 decoder: {0}")]
    Initialize(String),
    #[error("invalid AArch64 instruction 0x{word:08X} at 0x{pc:X}")]
    Invalid { pc: u64, word: u32 },
    #[error("failed to decode AArch64 instruction 0x{word:08X} at 0x{pc:X}: {message}")]
    Capstone { pc: u64, word: u32, message: String },
    #[error(transparent)]
    Register(#[from] RegisterError),
}

pub struct Decoder {
    capstone: Capstone,
}

impl Decoder {
    pub fn New() -> Result<Self, DecodeError> {
        let capstone = Capstone::new()
            .arm64()
            .mode(ArchMode::Arm)
            .detail(true)
            .build()
            .map_err(|error| DecodeError::Initialize(error.to_string()))?;
        Ok(Self { capstone })
    }

    pub fn Decode(&self, pc: u64, word: u32) -> Result<DecodedInstruction, DecodeError> {
        let bytes = word.to_le_bytes();
        let instructions =
            self.capstone
                .disasm_count(&bytes, pc, 1)
                .map_err(|error| DecodeError::Capstone {
                    pc,
                    word,
                    message: error.to_string(),
                })?;
        let Some(instruction) = instructions.iter().next() else {
            return DecodeMissingInstruction(pc, word).ok_or(DecodeError::Invalid { pc, word });
        };
        if instruction.bytes().len() != 4 {
            return Err(DecodeError::Invalid { pc, word });
        }
        let detail =
            self.capstone
                .insn_detail(instruction)
                .map_err(|error| DecodeError::Capstone {
                    pc,
                    word,
                    message: error.to_string(),
                })?;
        let arch_detail = detail.arch_detail();
        let arm64 = arch_detail.arm64().ok_or(DecodeError::Capstone {
            pc,
            word,
            message: "decoder returned non-ARM64 detail".to_owned(),
        })?;
        let mnemonic_text = instruction
            .mnemonic()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let operand_text = instruction.op_str().unwrap_or_default().to_owned();
        let mut operands = Vec::new();
        for operand in arm64.operands() {
            let shift = MapShift(operand.shift);
            let extend = MapExtend(operand.ext);
            let mapped = match operand.op_type {
                Arm64OperandType::Reg(id) => {
                    let name = self.capstone.reg_name(id).unwrap_or_default();
                    Operand::Register(RegisterOperand {
                        register: Register::Parse(&name)?,
                        shift,
                        extend,
                        arrangement: MapArrangement(operand.vas),
                        lane: operand.vector_index,
                    })
                }
                Arm64OperandType::Imm(value) | Arm64OperandType::Cimm(value) => {
                    Operand::Immediate(value)
                }
                Arm64OperandType::Mem(memory) => {
                    let base_name = self.capstone.reg_name(memory.base()).unwrap_or_default();
                    let index_name = self.capstone.reg_name(memory.index()).unwrap_or_default();
                    Operand::Memory(MemoryOperand {
                        base: Register::Parse(&base_name)?,
                        index: (!index_name.is_empty() && index_name != "invalid")
                            .then(|| Register::Parse(&index_name))
                            .transpose()?,
                        displacement: i64::from(memory.disp()),
                        shift,
                        extend,
                    })
                }
                Arm64OperandType::RegMrs(value) | Arm64OperandType::RegMsr(value) => {
                    Operand::SystemRegister(value as u32)
                }
                Arm64OperandType::Fp(value) => Operand::FloatingImmediate(value),
                _ => Operand::Other,
            };
            operands.push(mapped);
        }

        let address_mode = if arm64.writeback() && operand_text.contains("],") {
            AddressMode::PostIndex
        } else if arm64.writeback() {
            AddressMode::PreIndex
        } else {
            AddressMode::Offset
        };
        let mut decoded = DecodedInstruction {
            pc,
            word,
            mnemonic: MapMnemonic(&mnemonic_text),
            mnemonic_text,
            operand_text,
            operands,
            condition: MapCondition(arm64.cc()),
            updates_flags: arm64.update_flags(),
            writeback: arm64.writeback(),
            address_mode,
        };
        RemapSpecialInstruction(&mut decoded);
        Ok(decoded)
    }
}

fn MapMnemonic(value: &str) -> Mnemonic {
    use Mnemonic::*;
    match value {
        "add" => Add,
        "adds" => Adds,
        "sub" => Sub,
        "subs" => Subs,
        "adc" => Adc,
        "adcs" => Adcs,
        "sbc" => Sbc,
        "sbcs" => Sbcs,
        "mov" => Mov,
        "ins" => Ins,
        "umov" => Umov,
        "movk" => Movk,
        "movn" => Movn,
        "movz" => Movz,
        "mvn" => Mvn,
        "and" => And,
        "ands" => Ands,
        "bic" => Bic,
        "bics" => Bics,
        "orr" => Orr,
        "orn" => Orn,
        "eor" => Eor,
        "eon" => Eon,
        "lsl" | "lslv" => Lsl,
        "lsr" | "lsrv" => Lsr,
        "asr" | "asrv" => Asr,
        "ror" | "rorv" => Ror,
        "clz" => Clz,
        "rbit" => Rbit,
        "rev" => Rev,
        "rev16" => Rev16,
        "rev32" => Rev32,
        "extr" => Extr,
        "madd" => Madd,
        "msub" => Msub,
        "mul" => Mul,
        "umaddl" => Umaddl,
        "umsubl" => Umsubl,
        "smaddl" => Smaddl,
        "smull" => Smull,
        "umull" => Umull,
        "smulh" => Smulh,
        "umulh" => Umulh,
        "smsubl" => Smsubl,
        "udiv" => Udiv,
        "sdiv" => Sdiv,
        "cmp" => Cmp,
        "cmn" => Cmn,
        "tst" => Tst,
        "ccmp" => Ccmp,
        "ccmn" => Ccmn,
        "csel" => Csel,
        "cset" => Cset,
        "csinc" | "cinc" => Csinc,
        "csinv" => Csinv,
        "csneg" | "cneg" => Csneg,
        "neg" => Neg,
        "sxtw" => Sxtw,
        "bfm" => Bfm,
        "sbfm" => Sbfm,
        "ubfm" => Ubfm,
        "ubfiz" => Ubfiz,
        "ubfx" => Ubfx,
        "bfi" => Bfi,
        "sbfx" => Sbfx,
        "bfxil" => Bfxil,
        "bfc" => Bfc,
        "sbfiz" => Sbfiz,
        "adr" => Adr,
        "adrp" => Adrp,
        "b" | "b.eq" | "b.ne" | "b.hs" | "b.lo" | "b.mi" | "b.pl" | "b.vs" | "b.vc" | "b.hi"
        | "b.ls" | "b.ge" | "b.lt" | "b.gt" | "b.le" => B,
        "bl" => Bl,
        "br" => Br,
        "blr" => Blr,
        "ret" => Ret,
        "braa" | "braaz" => Braa,
        "brab" | "brabz" => Brab,
        "blraa" | "blraaz" => Blraa,
        "blrab" | "blrabz" => Blrab,
        "retaa" => Retaa,
        "retab" => Retab,
        "eretaa" => Eretaa,
        "eretab" => Eretab,
        "cbz" => Cbz,
        "cbnz" => Cbnz,
        "tbz" => Tbz,
        "tbnz" => Tbnz,
        "ldraa" => Ldraa,
        "ldrab" => Ldrab,
        "ldr" => Ldr,
        "ldur" => Ldur,
        "ldurb" => Ldurb,
        "ldrb" => Ldrb,
        "ldrh" => Ldrh,
        "ldrsb" => Ldrsb,
        "ldrsh" => Ldrsh,
        "ldrsw" => Ldrsw,
        "str" => Str,
        "stur" => Stur,
        "ldpsw" => Ldpsw,
        "ldurh" => Ldurh,
        "ldursb" => Ldursb,
        "ldursh" => Ldursh,
        "ldursw" => Ldursw,
        "ld1" => Ld1,
        "strb" => Strb,
        "strh" => Strh,
        "sturb" => Sturb,
        "sturh" => Sturh,
        "ldp" => Ldp,
        "stp" => Stp,
        "ldxr" | "ldxp" => Ldxr,
        "ldaxr" | "ldaxp" => Ldaxr,
        "stxr" | "stxp" => Stxr,
        "stlxr" | "stlxp" => Stlxr,
        "cas" | "casa" | "casal" | "casl" | "casb" | "cash" | "casab" | "casah" | "casalb"
        | "casalh" | "caslb" | "caslh" => Cas,
        "casp" | "caspa" | "caspal" | "caspl" => Casp,
        "ldadd" | "ldadda" | "ldaddal" | "ldaddl" | "ldaddb" | "ldaddh" | "ldaddab" | "ldaddah"
        | "ldaddalb" | "ldaddalh" | "ldaddlb" | "ldaddlh" => Ldadd,
        "ldclr" | "ldclra" | "ldclral" | "ldclrl" | "ldclrb" | "ldclrh" | "ldclrab" | "ldclrah"
        | "ldclralb" | "ldclralh" | "ldclrlb" | "ldclrlh" => Ldclr,
        "ldeor" | "ldeora" | "ldeoral" | "ldeorl" | "ldeorb" | "ldeorh" | "ldeorab" | "ldeorah"
        | "ldeoralb" | "ldeoralh" | "ldeorlb" | "ldeorlh" => Ldeor,
        "ldset" | "ldseta" | "ldsetal" | "ldsetl" | "ldsetb" | "ldseth" | "ldsetab" | "ldsetah"
        | "ldsetalb" | "ldsetalh" | "ldsetlb" | "ldsetlh" => Ldset,
        "ldsmax" | "ldsmaxa" | "ldsmaxal" | "ldsmaxl" | "ldsmaxb" | "ldsmaxh" | "ldsmaxab"
        | "ldsmaxah" | "ldsmaxalb" | "ldsmaxalh" | "ldsmaxlb" | "ldsmaxlh" => Ldsmax,
        "ldsmin" | "ldsmina" | "ldsminal" | "ldsminl" | "ldsminb" | "ldsminh" | "ldsminab"
        | "ldsminah" | "ldsminalb" | "ldsminalh" | "ldsminlb" | "ldsminlh" => Ldsmin,
        "ldumax" | "ldumaxa" | "ldumaxal" | "ldumaxl" | "ldumaxb" | "ldumaxh" | "ldumaxab"
        | "ldumaxah" | "ldumaxalb" | "ldumaxalh" | "ldumaxlb" | "ldumaxlh" => Ldumax,
        "ldumin" | "ldumina" | "lduminal" | "lduminl" | "lduminb" | "lduminh" | "lduminab"
        | "lduminah" | "lduminalb" | "lduminalh" | "lduminlb" | "lduminlh" => Ldumin,
        "swp" | "swpa" | "swpal" | "swpl" | "swpb" | "swph" | "swpab" | "swpah" | "swpalb"
        | "swpalh" | "swplb" | "swplh" => Swp,
        "addg" => Addg,
        "subg" => Subg,
        "gmi" => Gmi,
        "irg" => Irg,
        "subp" => Subp,
        "subps" => Subps,
        "ldclrp" => Ldclrp,
        "ldsetp" => Ldsetp,
        "swpp" => Swpp,
        "rcwcas" => Rcwcas,
        "rcwscas" => Rcwscas,
        "rcwclr" => Rcwclr,
        "rcwsclr" => Rcwsclr,
        "rcwset" => Rcwset,
        "rcwsset" => Rcwsset,
        "rcwswp" => Rcwswp,
        "rcwsswp" => Rcwsswp,
        "rcwcasp" | "rcwcaspa" | "rcwcaspal" | "rcwcaspl" => Rcwcasp,
        "rcwscasp" | "rcwscaspa" | "rcwscaspal" | "rcwscaspl" => Rcwscasp,
        "rcwclrp" | "rcwclrpa" | "rcwclrpal" | "rcwclrpl" => Rcwclrp,
        "rcwsclrp" | "rcwsclrpa" | "rcwsclrpal" | "rcwsclrpl" => Rcwsclrp,
        "rcwsetp" | "rcwsetpa" | "rcwsetpal" | "rcwsetpl" => Rcwsetp,
        "rcwssetp" | "rcwssetpa" | "rcwssetpal" | "rcwssetpl" => Rcwssetp,
        "rcwswpp" | "rcwswppa" | "rcwswppal" | "rcwswppl" => Rcwswpp,
        "rcwsswpp" | "rcwsswppa" | "rcwsswppal" | "rcwsswppl" => Rcwsswpp,
        "ldfadd" | "stfadd" => Ldfadd,
        "ldfmax" | "stfmax" => Ldfmax,
        "ldfmin" | "stfmin" => Ldfmin,
        "ldfmaxnm" | "stfmaxnm" => Ldfmaxnm,
        "ldfminnm" | "stfminnm" => Ldfminnm,
        "ldbfadd" | "stbfadd" => Ldbfadd,
        "ldbfmax" | "stbfmax" => Ldbfmax,
        "ldbfmin" | "stbfmin" => Ldbfmin,
        "ldbfmaxnm" | "stbfmaxnm" => Ldbfmaxnm,
        "ldbfminnm" | "stbfminnm" => Ldbfminnm,
        "ld64b" => Ld64b,
        "st64b" => St64b,
        "st64bv" => St64bv,
        "st64bv0" => St64bv0,
        "ldg" => Ldg,
        "ldgm" => Ldgm,
        "stg" => Stg,
        "stgm" => Stgm,
        "stgp" => Stgp,
        "stzg" => Stzg,
        "stzgm" => Stzgm,
        "st2g" => St2g,
        "stz2g" => Stz2g,
        value if value.starts_with("cpy") => MopsCopy,
        "set" | "sete" | "seten" | "setet" | "setetn" | "setm" | "setmn" | "setmt" | "setmtn"
        | "setp" | "setpn" | "setpt" | "setptn" => MopsSet,
        "setge" | "setgen" | "setget" | "setgetn" | "setgm" | "setgmn" | "setgmt" | "setgmtn"
        | "setgp" | "setgpn" | "setgpt" | "setgptn" => MopsSetg,
        value if value.starts_with("setgo") => MopsSetgo,
        "svc" => Svc,
        "mrs" => Mrs,
        "msr" => Msr,
        "pacga" => Pacga,
        "pacia" => Pacia,
        "pacib" => Pacib,
        "paciasp" => PaciaSp,
        "pacibsp" => PacibSp,
        "pacda" => Pacda,
        "pacdb" => Pacdb,
        "autia" => Autia,
        "autib" => Autib,
        "autiasp" => AutiaSp,
        "autibsp" => AutibSp,
        "autda" => Autda,
        "autdb" => Autdb,
        "xpaci" => Xpaci,
        "xpacd" => Xpacd,
        "fmov" => Fmov,
        "ucvtf" => Ucvtf,
        "scvtf" => Scvtf,
        "fcvtzu" => Fcvtzu,
        "fcvtzs" => Fcvtzs,
        "fabs" => Fabs,
        "fneg" => Fneg,
        "fsqrt" => Fsqrt,
        "fmax" => Fmax,
        "fmin" => Fmin,
        "fmaxnm" => Fmaxnm,
        "fminnm" => Fminnm,
        "fnmul" => Fnmul,
        "fcmp" => Fcmp,
        "fcmpe" => Fcmpe,
        "fcsel" => Fcsel,
        "fadd" => Fadd,
        "fsub" => Fsub,
        "fmul" => Fmul,
        "fdiv" => Fdiv,
        "fmadd" => Fmadd,
        "fmsub" => Fmsub,
        "fnmadd" => Fnmadd,
        "fnmsub" => Fnmsub,
        "fmla" => Fmla,
        "fmls" => Fmls,
        "movi" => Movi,
        "bit" => Bit,
        "bif" => Bif,
        "bsl" => Bsl,
        "dup" => Dup,
        "cmeq" => Cmeq,
        "cmhs" => Cmhs,
        "uzp1" => Uzp1,
        "uzp2" => Uzp2,
        "addv" => Addv,
        "addp" => Addp,
        "umaxp" => Umaxp,
        "ushl" => Ushl,
        "xtn" => Xtn,
        "xtn2" => Xtn2,
        "nop" => Nop,
        "hint" => Hint,
        "dmb" => Dmb,
        "dsb" => Dsb,
        "isb" => Isb,
        "ic" => Ic,
        "dc" => Dc,
        "prfm" => Prfm,
        "clrex" => Clrex,
        "brk" => Brk,
        other => Unsupported(other.to_owned()),
    }
}

fn MapShift(value: Arm64Shift) -> Shift {
    match value {
        Arm64Shift::Invalid => Shift::None,
        Arm64Shift::Lsl(amount) => Shift::Lsl(amount),
        Arm64Shift::Lsr(amount) => Shift::Lsr(amount),
        Arm64Shift::Asr(amount) => Shift::Asr(amount),
        Arm64Shift::Ror(amount) => Shift::Ror(amount),
        Arm64Shift::Msl(amount) => Shift::Msl(amount),
    }
}

fn MapExtend(value: Arm64Extender) -> Extend {
    use Arm64Extender::*;
    match value {
        ARM64_EXT_UXTB => Extend::Uxtb,
        ARM64_EXT_UXTH => Extend::Uxth,
        ARM64_EXT_UXTW => Extend::Uxtw,
        ARM64_EXT_UXTX => Extend::Uxtx,
        ARM64_EXT_SXTB => Extend::Sxtb,
        ARM64_EXT_SXTH => Extend::Sxth,
        ARM64_EXT_SXTW => Extend::Sxtw,
        ARM64_EXT_SXTX => Extend::Sxtx,
        _ => Extend::None,
    }
}

fn MapArrangement(value: Arm64Vas) -> Option<VectorArrangement> {
    use Arm64Vas::*;
    let (element_bits, lanes) = match value {
        ARM64_VAS_16B => (8, 16),
        ARM64_VAS_8B => (8, 8),
        ARM64_VAS_4B => (8, 4),
        ARM64_VAS_1B => (8, 1),
        ARM64_VAS_8H => (16, 8),
        ARM64_VAS_4H => (16, 4),
        ARM64_VAS_2H => (16, 2),
        ARM64_VAS_1H => (16, 1),
        ARM64_VAS_4S => (32, 4),
        ARM64_VAS_2S => (32, 2),
        ARM64_VAS_1S => (32, 1),
        ARM64_VAS_2D => (64, 2),
        ARM64_VAS_1D => (64, 1),
        ARM64_VAS_1Q => (128, 1),
        _ => return None,
    };
    Some(VectorArrangement {
        element_bits,
        lanes,
    })
}

fn MapCondition(value: Arm64CC) -> Condition {
    use Arm64CC::*;
    match value {
        ARM64_CC_EQ => Condition::Eq,
        ARM64_CC_NE => Condition::Ne,
        ARM64_CC_HS => Condition::Hs,
        ARM64_CC_LO => Condition::Lo,
        ARM64_CC_MI => Condition::Mi,
        ARM64_CC_PL => Condition::Pl,
        ARM64_CC_VS => Condition::Vs,
        ARM64_CC_VC => Condition::Vc,
        ARM64_CC_HI => Condition::Hi,
        ARM64_CC_LS => Condition::Ls,
        ARM64_CC_GE => Condition::Ge,
        ARM64_CC_LT => Condition::Lt,
        ARM64_CC_GT => Condition::Gt,
        ARM64_CC_LE => Condition::Le,
        ARM64_CC_AL => Condition::Al,
        ARM64_CC_NV => Condition::Nv,
        ARM64_CC_INVALID => Condition::None,
    }
}

fn DecodeMissingInstruction(pc: u64, word: u32) -> Option<DecodedInstruction> {
    let rd = word & 0x1f;
    let rn = (word >> 5) & 0x1f;
    let rm = (word >> 16) & 0x1f;
    let rt2 = (word >> 10) & 0x1f;
    let register = |raw: u32| {
        Operand::Register(RegisterOperand {
            register: DecodeXRegister(raw),
            shift: Shift::None,
            extend: Extend::None,
            arrangement: None,
            lane: None,
        })
    };
    let register_or_sp = |raw: u32| {
        Operand::Register(RegisterOperand {
            register: DecodeXOrSpRegister(raw),
            shift: Shift::None,
            extend: Extend::None,
            arrangement: None,
            lane: None,
        })
    };
    let memory = || {
        Operand::Memory(MemoryOperand {
            base: DecodeXOrSpRegister(rn),
            index: None,
            displacement: 0,
            shift: Shift::None,
            extend: Extend::None,
        })
    };
    if (word & 0x3FFF_0000) == 0x1DDF_0000 {
        return Some(DecodedInstruction {
            pc,
            word,
            mnemonic: Mnemonic::MopsSetgo,
            mnemonic_text: "setgo".to_owned(),
            operand_text: String::new(),
            operands: vec![register_or_sp(rd), register_or_sp(rn)],
            condition: Condition::None,
            updates_flags: false,
            writeback: false,
            address_mode: AddressMode::Offset,
        });
    }
    if let Some(decoded) = DecodeManualRcwPair(pc, word) {
        return Some(decoded);
    }
    if let Some(decoded) = DecodeManualLsfe(pc, word) {
        return Some(decoded);
    }
    let (mnemonic, mnemonic_text, operands, updates_flags) = match word & 0xFFC0_0000 {
        0x9180_0000 => (
            Mnemonic::Addg,
            "addg",
            vec![
                register_or_sp(rd),
                register_or_sp(rn),
                Operand::Immediate(i64::from(((word >> 16) & 0x3f) << 4)),
                Operand::Immediate(i64::from((word >> 10) & 0xf)),
            ],
            false,
        ),
        0xD180_0000 => (
            Mnemonic::Subg,
            "subg",
            vec![
                register_or_sp(rd),
                register_or_sp(rn),
                Operand::Immediate(i64::from(((word >> 16) & 0x3f) << 4)),
                Operand::Immediate(i64::from((word >> 10) & 0xf)),
            ],
            false,
        ),
        _ => match word & 0xFFC0_FC00 {
            0xF800_D000 => (
                Mnemonic::Ld64b,
                "ld64b",
                vec![register(rd), memory()],
                false,
            ),
            0xF800_9000 => (
                Mnemonic::St64b,
                "st64b",
                vec![register(rd), memory()],
                false,
            ),
            0xF800_B000 => (
                Mnemonic::St64bv,
                "st64bv",
                vec![register(rd), register(rm), memory()],
                false,
            ),
            0xF800_A000 => (
                Mnemonic::St64bv0,
                "st64bv0",
                vec![register(rd), register(rm), memory()],
                false,
            ),
            0xD940_0000 => (Mnemonic::Ldg, "ldg", vec![register(rd), memory()], false),
            0xD9C0_0000 => (Mnemonic::Ldgm, "ldgm", vec![register(rd), memory()], false),
            0xD900_0800 => (Mnemonic::Stg, "stg", vec![register(rd), memory()], false),
            0xD980_0000 => (Mnemonic::Stgm, "stgm", vec![register(rd), memory()], false),
            0x6900_4000 => (
                Mnemonic::Stgp,
                "stgp",
                vec![register(rd), register(rt2), memory()],
                false,
            ),
            0xD940_0800 => (Mnemonic::Stzg, "stzg", vec![register(rd), memory()], false),
            0xD900_0000 => (
                Mnemonic::Stzgm,
                "stzgm",
                vec![register(rd), memory()],
                false,
            ),
            0xD980_0800 => (Mnemonic::St2g, "st2g", vec![register(rd), memory()], false),
            0xD9C0_0800 => (
                Mnemonic::Stz2g,
                "stz2g",
                vec![register(rd), memory()],
                false,
            ),
            0x9AC0_1400 => (
                Mnemonic::Gmi,
                "gmi",
                vec![register(rd), register(rn), register(rm)],
                false,
            ),
            0x9AC0_1000 => (
                Mnemonic::Irg,
                "irg",
                vec![register(rd), register(rn), register(rm)],
                false,
            ),
            0x9AC0_0000 => (
                Mnemonic::Subp,
                "subp",
                vec![register(rd), register(rn), register(rm)],
                false,
            ),
            0xBAC0_0000 => (
                Mnemonic::Subps,
                "subps",
                vec![register(rd), register(rn), register(rm)],
                true,
            ),
            0x1900_1000 => (
                Mnemonic::Ldclrp,
                "ldclrp",
                vec![register(rd), register(rm), memory()],
                false,
            ),
            0x1900_3000 => (
                Mnemonic::Ldsetp,
                "ldsetp",
                vec![register(rd), register(rm), memory()],
                false,
            ),
            0x1900_8000 => (
                Mnemonic::Swpp,
                "swpp",
                vec![register(rd), register(rm), memory()],
                false,
            ),
            0x1900_0800 => (
                Mnemonic::Rcwcas,
                "rcwcas",
                vec![register(rm), register(rd), memory()],
                false,
            ),
            0x5900_0800 => (
                Mnemonic::Rcwscas,
                "rcwscas",
                vec![register(rm), register(rd), memory()],
                false,
            ),
            0x3800_9000 => (
                Mnemonic::Rcwclr,
                "rcwclr",
                vec![register(rm), register(rd), memory()],
                false,
            ),
            0x7800_9000 => (
                Mnemonic::Rcwsclr,
                "rcwsclr",
                vec![register(rm), register(rd), memory()],
                false,
            ),
            0x3800_B000 => (
                Mnemonic::Rcwset,
                "rcwset",
                vec![register(rm), register(rd), memory()],
                false,
            ),
            0x7800_B000 => (
                Mnemonic::Rcwsset,
                "rcwsset",
                vec![register(rm), register(rd), memory()],
                false,
            ),
            0x3800_A000 => (
                Mnemonic::Rcwswp,
                "rcwswp",
                vec![register(rm), register(rd), memory()],
                false,
            ),
            0x7800_A000 => (
                Mnemonic::Rcwsswp,
                "rcwsswp",
                vec![register(rm), register(rd), memory()],
                false,
            ),
            value
                if matches!(
                    value & 0xFCE0_0C00,
                    0x1800_0400
                        | 0x1840_0400
                        | 0x1880_0400
                        | 0x1C00_0400
                        | 0x1C40_0400
                        | 0x1C80_0400
                ) =>
            {
                (
                    Mnemonic::MopsCopy,
                    "cpy",
                    vec![register_or_sp(rd), register_or_sp(rn), register_or_sp(rm)],
                    false,
                )
            }
            value if (value & 0xFCE0_0C00) == 0x18C0_0400 => (
                Mnemonic::MopsSet,
                "set",
                vec![register_or_sp(rd), register_or_sp(rn), register_or_sp(rm)],
                false,
            ),
            value if (value & 0xFCE0_0C00) == 0x1CC0_0400 => (
                Mnemonic::MopsSetg,
                "setg",
                vec![register_or_sp(rd), register_or_sp(rn), register_or_sp(rm)],
                false,
            ),
            _ => return None,
        },
    };
    Some(DecodedInstruction {
        pc,
        word,
        mnemonic,
        mnemonic_text: mnemonic_text.to_owned(),
        operand_text: String::new(),
        operands,
        condition: Condition::None,
        updates_flags,
        writeback: false,
        address_mode: AddressMode::Offset,
    })
}

fn DecodeXRegister(raw: u32) -> Register {
    if raw == 31 {
        Register::Xzr
    } else {
        Register::X(raw as u8)
    }
}

fn DecodeXOrSpRegister(raw: u32) -> Register {
    if raw == 31 {
        Register::Sp
    } else {
        Register::X(raw as u8)
    }
}

fn DecodeFloatingRegister(raw: u32, width: u8) -> Register {
    Register::Vector {
        index: raw as u8,
        width,
    }
}

fn DecodeManualRcwPair(pc: u64, word: u32) -> Option<DecodedInstruction> {
    let rs = (word >> 16) & 0x1f;
    let rt = word & 0x1f;
    let rn = (word >> 5) & 0x1f;
    let register = |raw: u32| {
        Operand::Register(RegisterOperand {
            register: DecodeXRegister(raw),
            shift: Shift::None,
            extend: Extend::None,
            arrangement: None,
            lane: None,
        })
    };
    let memory = || {
        Operand::Memory(MemoryOperand {
            base: DecodeXOrSpRegister(rn),
            index: None,
            displacement: 0,
            shift: Shift::None,
            extend: Extend::None,
        })
    };
    let ordering_suffix = match (word >> 22) & 0x3 {
        0 => "",
        1 => "l",
        2 => "a",
        3 => "al",
        _ => unreachable!(),
    };
    let (mnemonic, base_name, operands) = match word & 0xFF20_FC00 {
        0x1920_0C00 => {
            if rs >= 31 || rt >= 31 {
                return None;
            }
            (
                Mnemonic::Rcwcasp,
                "rcwcasp",
                vec![
                    register(rs),
                    register(rs + 1),
                    register(rt),
                    register(rt + 1),
                    memory(),
                ],
            )
        }
        0x5920_0C00 => {
            if rs >= 31 || rt >= 31 {
                return None;
            }
            (
                Mnemonic::Rcwscasp,
                "rcwscasp",
                vec![
                    register(rs),
                    register(rs + 1),
                    register(rt),
                    register(rt + 1),
                    memory(),
                ],
            )
        }
        0x3820_9400 => (
            Mnemonic::Rcwclrp,
            "rcwclrp",
            vec![register(rt), register(rs), memory()],
        ),
        0x7820_9400 => (
            Mnemonic::Rcwsclrp,
            "rcwsclrp",
            vec![register(rt), register(rs), memory()],
        ),
        0x1920_B000 => (
            Mnemonic::Rcwsetp,
            "rcwsetp",
            vec![register(rt), register(rs), memory()],
        ),
        0x5920_B000 => (
            Mnemonic::Rcwssetp,
            "rcwssetp",
            vec![register(rt), register(rs), memory()],
        ),
        0x1920_8000 => (
            Mnemonic::Rcwswpp,
            "rcwswpp",
            vec![register(rt), register(rs), memory()],
        ),
        0x5920_8000 => (
            Mnemonic::Rcwsswpp,
            "rcwsswpp",
            vec![register(rt), register(rs), memory()],
        ),
        _ => return None,
    };
    Some(DecodedInstruction {
        pc,
        word,
        mnemonic,
        mnemonic_text: format!("{base_name}{ordering_suffix}"),
        operand_text: String::new(),
        operands,
        condition: Condition::None,
        updates_flags: false,
        writeback: false,
        address_mode: AddressMode::Offset,
    })
}

fn DecodeManualLsfe(pc: u64, word: u32) -> Option<DecodedInstruction> {
    let lsfe_load = (word & 0x3F20_8C00) == 0x3C20_0000;
    let lsfe_store = (word & 0x3FA0_8C1F) == 0x3C20_801F;
    let operation = (word >> 12) & 7;
    if !(lsfe_load || lsfe_store) || !matches!(operation, 0 | 4 | 5 | 6 | 7) {
        return None;
    }

    let width = match (word >> 30) & 0x3 {
        0 => 16,
        1 => 32,
        3 => 64,
        _ => return None,
    };
    let bfloat = width == 16;
    let source = (word >> 16) & 0x1f;
    let target = word & 0x1f;
    let base = (word >> 5) & 0x1f;
    let register = |raw: u32| {
        Operand::Register(RegisterOperand {
            register: DecodeFloatingRegister(raw, width),
            shift: Shift::None,
            extend: Extend::None,
            arrangement: None,
            lane: None,
        })
    };
    let memory = Operand::Memory(MemoryOperand {
        base: DecodeXOrSpRegister(base),
        index: None,
        displacement: 0,
        shift: Shift::None,
        extend: Extend::None,
    });
    let (mnemonic, suffix) = match (bfloat, operation) {
        (false, 0) => (Mnemonic::Ldfadd, "add"),
        (false, 4) => (Mnemonic::Ldfmax, "max"),
        (false, 5) => (Mnemonic::Ldfmin, "min"),
        (false, 6) => (Mnemonic::Ldfmaxnm, "maxnm"),
        (false, 7) => (Mnemonic::Ldfminnm, "minnm"),
        (true, 0) => (Mnemonic::Ldbfadd, "add"),
        (true, 4) => (Mnemonic::Ldbfmax, "max"),
        (true, 5) => (Mnemonic::Ldbfmin, "min"),
        (true, 6) => (Mnemonic::Ldbfmaxnm, "maxnm"),
        (true, 7) => (Mnemonic::Ldbfminnm, "minnm"),
        _ => return None,
    };

    let mut operands = vec![register(source)];
    if lsfe_load {
        operands.push(register(target));
    }
    operands.push(memory);

    Some(DecodedInstruction {
        pc,
        word,
        mnemonic,
        mnemonic_text: format!(
            "{}{}",
            if bfloat {
                if lsfe_store {
                    "stbf"
                } else {
                    "ldbf"
                }
            } else if lsfe_store {
                "stf"
            } else {
                "ldf"
            },
            suffix
        ),
        operand_text: String::new(),
        operands,
        condition: Condition::None,
        updates_flags: false,
        writeback: false,
        address_mode: AddressMode::Offset,
    })
}

fn RemapSpecialInstruction(instruction: &mut DecodedInstruction) {
    let rd = instruction.word & 0x1f;
    let register = || {
        Operand::Register(RegisterOperand {
            register: DecodeXRegister(rd),
            shift: Shift::None,
            extend: Extend::None,
            arrangement: None,
            lane: None,
        })
    };
    match instruction.word {
        0xD508_77BF => {
            instruction.mnemonic = Mnemonic::Gcspopcx;
            instruction.mnemonic_text = "gcspopcx".to_owned();
            instruction.operands.clear();
        }
        0xD508_77DF => {
            instruction.mnemonic = Mnemonic::Gcspopx;
            instruction.mnemonic_text = "gcspopx".to_owned();
            instruction.operands.clear();
        }
        0xD508_779F => {
            instruction.mnemonic = Mnemonic::Gcspushx;
            instruction.mnemonic_text = "gcspushx".to_owned();
            instruction.operands.clear();
        }
        _ => match instruction.word & 0xFFFF_FFE0 {
            0xD52B_7720 => {
                instruction.mnemonic = Mnemonic::Gcspopm;
                instruction.mnemonic_text = "gcspopm".to_owned();
                instruction.operands = vec![register()];
            }
            0xD50B_7700 => {
                instruction.mnemonic = Mnemonic::Gcspushm;
                instruction.mnemonic_text = "gcspushm".to_owned();
                instruction.operands = vec![register()];
            }
            0xD50B_7740 => {
                instruction.mnemonic = Mnemonic::Gcsss1;
                instruction.mnemonic_text = "gcsss1".to_owned();
                instruction.operands = vec![register()];
            }
            0xD52B_7760 => {
                instruction.mnemonic = Mnemonic::Gcsss2;
                instruction.mnemonic_text = "gcsss2".to_owned();
                instruction.operands = vec![register()];
            }
            _ => {}
        },
    }
    NormalizeMopsOperands(instruction);
}

fn NormalizeMopsOperands(instruction: &mut DecodedInstruction) {
    if !matches!(
        instruction.mnemonic,
        Mnemonic::MopsCopy | Mnemonic::MopsSet | Mnemonic::MopsSetg | Mnemonic::MopsSetgo
    ) {
        return;
    }
    let rd = instruction.word & 0x1f;
    let rn = (instruction.word >> 5) & 0x1f;
    let rm = (instruction.word >> 16) & 0x1f;
    let register = |raw: u32| {
        Operand::Register(RegisterOperand {
            register: DecodeXOrSpRegister(raw),
            shift: Shift::None,
            extend: Extend::None,
            arrangement: None,
            lane: None,
        })
    };
    instruction.operands = vec![register(rd), register(rn)];
    if !matches!(instruction.mnemonic, Mnemonic::MopsSetgo) {
        instruction.operands.push(register(rm));
    }
    instruction.writeback = false;
    instruction.address_mode = AddressMode::Offset;
}
