# Android Binder regression checks

These checks run in their own processes. They do not register a system service,
load code into another process, or restart Android services. The Auto regression
also reads the existing remote display service.

`DisplayBinderProbe.java` creates its own local Java Binder. The Rust fixture
includes the production display client and calls it from Java's attached JNI
entry thread. It requires two explicit local-service rejections and two Auto
selections of the JNI callback, with zero local descriptor calls, zero local
transactions, and no cached local service. The original Java object and Binder
owner stay alive until the local test finishes. It then verifies that Auto selects
Binder twice for the real remote display service even though this process has a VM.

This checks the class-association guard. It does not establish that dropping an
arbitrary final Java Binder reference on an unattached thread is safe. The native
display client supports remote services; local Java services remain unsupported.

## Build

Configure NDK r26d, libclang 17, and both target-specific bindgen environment
variables as described in [the window README](../../src/window/README.md).
From the repository root in PowerShell:

```powershell
cargo +1.94.0 ndk -t arm64-v8a -P 31 build --locked --no-default-features --features xdl,jni,binder --example display_binder_probe --release
cargo +1.94.0 ndk -t arm64-v8a -P 31 build --locked --no-default-features --features xdl,binder --example display_snapshot --release

$sdk = "D:/developer/Android/Sdk"
$probeDir = "build/binder-display-probe"
New-Item -ItemType Directory -Force -Path "$probeDir/classes", "$probeDir/dex" | Out-Null
& "$env:JAVA_HOME/bin/javac.exe" --release 8 -cp "$sdk/platforms/android-36/android.jar" -d "$probeDir/classes" "tests/android/DisplayBinderProbe.java"
$probeClasses = Get-ChildItem "$probeDir/classes" -Filter '*.class' | ForEach-Object { $_.FullName }
& "$sdk/build-tools/36.0.0/d8.bat" --min-api 31 --lib "$sdk/platforms/android-36/android.jar" --output "$probeDir/dex" @probeClasses
```

## Run

Select the intended device with `adb -s SERIAL` if more than one is connected.

```powershell
adb push build/binder-display-probe/dex/classes.dex /data/local/tmp/espframe-binder-probe.dex
adb push target/aarch64-linux-android/release/examples/libdisplay_binder_probe.so /data/local/tmp/libespframe_binder_probe.so
adb shell 'CLASSPATH=/data/local/tmp/espframe-binder-probe.dex app_process /system/bin DisplayBinderProbe /data/local/tmp/libespframe_binder_probe.so'

adb push target/aarch64-linux-android/release/examples/display_snapshot /data/local/tmp/espframe-display-snapshot
adb shell chmod 755 /data/local/tmp/espframe-display-snapshot
adb shell /data/local/tmp/espframe-display-snapshot
```

The test prints `PASS: Auto local=JNI remote=Binder twice each; forced local rejected; descriptor=0 transactions=0`.
The remote test prints display IDs, layer stacks, logical sizes, and rotations.
It does not start a JavaVM. On 2026-09-07 both tests passed on the connected
Android 16/SDK 36 ARM64 device; remote queries succeeded as shell and root.
Other OS releases, OEMs, and mirror lifecycle behavior need separate validation.
The local JNI callback checks object identity in the test process; this is not a
full test of DisplayManagerInternal enumeration or the host's rendering lifecycle.

## UID 1000

The native example accepts `--uid-1000` only when launched from an existing root
shell. Before the first Binder call, it clears supplementary groups, sets real,
effective and saved GID/UID to 1000, and verifies `/proc/self/status`. Any failed
step stops the query. It does not change SELinux policy or context.

In PowerShell, sending the command over stdin preserves the argument quoting:

```powershell
@'
su -c '/data/local/tmp/espframe-display-snapshot --uid-1000'
'@ | adb shell sh
```

The 2026-09-07 Android 16 test returned:

```text
Uid: 1000 1000 1000 1000
Gid: 1000 1000 1000 1000
Groups:
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapAmb: 0000000000000000
selinux=u:r:su:s0
java_runtime_mapped=false
id=0 stack=0 logical=1600x2560 rotation=Portrait
```

The mapping check looks for libart, libnativehelper and libandroid_runtime.
The example's `xdl,binder` dependency tree contains no JNI crate; its dynamic
dependencies are libdl, libbinder_ndk and libc. Non-root use of `--uid-1000` and
unknown arguments were also checked to fail before querying.

This is a separate process in the recorded SELinux domain. UID 1000 does not
make the service local and does not reproduce a system_server process or domain.
