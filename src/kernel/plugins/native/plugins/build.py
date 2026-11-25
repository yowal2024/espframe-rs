#!/usr/bin/env python3
"""Build a freestanding ARM64 plugin; outputs belong in ignored build/."""
import argparse,pathlib,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
def build(source,out,cc="aarch64-linux-gnu-gcc"):
 out=pathlib.Path(out);out.parent.mkdir(parents=True,exist_ok=True)
 cmd=[cc,"-O2","-Wall","-Wextra","-Werror","-ffreestanding","-fPIC","-fvisibility=hidden",
      "-fno-builtin","-fno-stack-protector","-fno-unwind-tables","-fno-asynchronous-unwind-tables",
      "-mgeneral-regs-only","-ffixed-x18","-mbranch-protection=bti","-nostdlib","-shared",
      "-Wl,-Bsymbolic,-z,defs,--build-id=none,-z,max-page-size=65536",
      "-Wl,-T,"+str(ROOT/"plugins/plugin.lds"),"-I"+str(ROOT),
      str(source),str(ROOT/"plugins/runtime.c"),"-o",str(out)]
 subprocess.run(cmd,check=True)
 return out
if __name__=="__main__":
 p=argparse.ArgumentParser();p.add_argument("source",type=pathlib.Path)
 p.add_argument("--out",type=pathlib.Path,required=True);p.add_argument("--cc",default="aarch64-linux-gnu-gcc")
 a=p.parse_args();build(a.source,a.out,a.cc)
