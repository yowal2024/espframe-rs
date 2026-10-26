use super::{
    AuthCrypto, AuthEnvelope, AuthHttpResponse, AuthMethod, AuthRequest, AuthResponse,
    AuthTransport, AuthTransportError, RemoteConfigClient, RemoteConfigData, RemoteConfigEnvelope,
};
use base64::Engine;
use serde::Serialize;
use std::collections::BTreeMap;
#[cfg(not(unix))]
use std::fs::{self, OpenOptions};
use std::path::Path;
use thiserror::Error;

/// Authenticated JSON responses are small manifests/envelopes. Keep a hard
/// cap so a peer cannot force unbounded allocation before parsing.
const MAX_AUTH_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub trait CryptoRandom {
    #[allow(non_snake_case)]
    fn Fill(&mut self, out: &mut [u8]);
}
pub trait Clock {
    #[allow(non_snake_case)]
    fn Now(&self) -> i64;
}

impl CryptoRandom for rand::rngs::OsRng {
    fn Fill(&mut self, out: &mut [u8]) {
        use rand::RngCore;
        self.fill_bytes(out);
    }
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn Now(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }
}

#[derive(Serialize)]
struct IniRequest<'a> {
    #[serde(rename = "versionKey")]
    version_key: &'a str,
    #[serde(rename = "versionNo")]
    version_no: &'a str,
}
#[derive(Serialize)]
struct LogonRequest<'a> {
    username: &'a str,
    password: &'a str,
    mi: &'a str,
}
#[derive(Serialize)]
struct HandshakeRequest<'a> {
    key: &'a str,
}
#[derive(Serialize)]
struct DataEnvelope<'a> {
    data: &'a str,
}

#[derive(Serialize)]
struct UserExtendsRequest<'a> {
    set: &'a BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub app_id: String,
    pub token_key: String,
}
impl AuthConfig {
    pub fn new(app_id: impl Into<String>) -> Self {
        Self {
            app_id: app_id.into(),
            token_key: String::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum AuthClientError {
    #[error("token unavailable")]
    TokenUnavailable,
    #[error("transport failure: {0}")]
    Transport(#[from] AuthTransportError),
    #[error("HTTP {0}")]
    Http(u16),
    #[error("response parse failed: {0}")]
    Response(String),
    #[error("download failed: {0}")]
    Download(String),
}

pub struct AuthClient<T: AuthTransport, R: CryptoRandom, C: Clock> {
    transport: T,
    random: R,
    clock: C,
    token: String,
    mi: String,
    config: AuthConfig,
    server_public_key: String,
    session_enabled: bool,
    session_id: String,
    session_key: Vec<u8>,
}

impl<T: AuthTransport, R: CryptoRandom, C: Clock> AuthClient<T, R, C> {
    pub fn new(transport: T, random: R, clock: C, config: AuthConfig) -> Self {
        Self {
            transport,
            random,
            clock,
            token: String::new(),
            mi: String::new(),
            config,
            server_public_key: String::new(),
            session_enabled: false,
            session_id: String::new(),
            session_key: Vec::new(),
        }
    }
    #[allow(non_snake_case)]
    pub fn SetToken(&mut self, token: impl Into<String>) {
        self.token = token.into();
    }
    #[allow(non_snake_case)]
    pub fn SetMi(&mut self, mi: impl Into<String>) {
        let mi = mi.into();
        if self.mi != mi {
            self.clear_session();
            self.mi = mi;
        }
    }
    #[allow(non_snake_case)]
    pub fn SetRsaKeys(&mut self, server_public_key: impl Into<String>) {
        let server_public_key = server_public_key.into();
        if self.server_public_key != server_public_key {
            self.clear_session();
            self.server_public_key = server_public_key;
        }
    }
    #[allow(non_snake_case)]
    pub fn SetSessionMode(&mut self, enabled: bool) {
        self.session_enabled = enabled;
        self.clear_session();
    }
    #[allow(non_snake_case)]
    pub fn GetToken(&self) -> &str {
        &self.token
    }
    #[allow(non_snake_case)]
    pub fn CaptureToken(&mut self, response: &AuthResponse) -> bool {
        let Some(token) = response
            .data
            .as_ref()
            .and_then(|data| data.get("token"))
            .and_then(serde_json::Value::as_str)
        else {
            return false;
        };
        self.token = token.to_owned();
        !self.token.is_empty()
    }
    #[allow(non_snake_case)]
    pub fn Logon(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<AuthResponse, AuthClientError> {
        let mi = self.mi.clone();
        self.post_value(
            "/api/sdk/logon",
            &LogonRequest {
                username,
                password,
                mi: &mi,
            },
            false,
        )
    }
    #[allow(non_snake_case)]
    pub fn Ini(
        &mut self,
        version_key: &str,
        version_no: &str,
    ) -> Result<AuthResponse, AuthClientError> {
        self.post_value(
            "/api/sdk/ini",
            &IniRequest {
                version_key,
                version_no,
            },
            false,
        )
    }
    #[allow(non_snake_case)]
    pub fn Info(&mut self) -> Result<AuthResponse, AuthClientError> {
        self.post("/api/sdk/info", "{}".to_owned(), true)
    }
    #[allow(non_snake_case)]
    pub fn Heartbeat(&mut self) -> Result<AuthResponse, AuthClientError> {
        self.post("/api/sdk/heartbeat", "{}".to_owned(), true)
    }
    #[allow(non_snake_case)]
    pub fn Clone(&mut self) -> Result<AuthResponse, AuthClientError> {
        self.get("/api/sdk/clone", true, false)
    }
    #[allow(non_snake_case)]
    pub fn RegenSign(&mut self) -> Result<AuthResponse, AuthClientError> {
        self.post_plain("/api/sdk/regen-sign", "{}", true)
    }
    #[allow(non_snake_case)]
    pub fn UserExtends(
        &mut self,
        set: &BTreeMap<String, String>,
    ) -> Result<RemoteConfigEnvelope, AuthClientError> {
        let response = if set.is_empty() {
            self.post("/api/sdk/userExtends", "{}".to_owned(), true)?
        } else {
            self.post_value("/api/sdk/userExtends", &UserExtendsRequest { set }, true)?
        };
        parse_user_extends_response(response)
    }
    #[allow(non_snake_case)]
    pub fn ExtendFileList(
        &mut self,
        category: &str,
        keyword: &str,
    ) -> Result<AuthResponse, AuthClientError> {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        if !category.is_empty() {
            serializer.append_pair("category", category);
        }
        if !keyword.is_empty() {
            serializer.append_pair("keyword", keyword);
        }
        let query = serializer.finish();
        let path = if query.is_empty() {
            "/api/sdk/extend-file/list".to_owned()
        } else {
            format!("/api/sdk/extend-file/list?{query}")
        };
        self.get(&path, false, true)
    }
    #[allow(non_snake_case)]
    pub fn DownloadDiffToFile(
        &mut self,
        path: &str,
        destination: &Path,
        expected: u64,
    ) -> Result<(), AuthClientError> {
        self.download_to_file(path, destination, expected, false)
    }
    #[allow(non_snake_case)]
    pub fn ExtendFileDownloadToFile(
        &mut self,
        id: i64,
        destination: &Path,
        expected: u64,
    ) -> Result<(), AuthClientError> {
        let request = self.file_download_request(
            &format!("/api/sdk/extend-file/{id}/download"),
            expected,
            true,
        )?;
        download_to_new_file(&self.transport, request, destination, expected)
    }
    #[allow(non_snake_case)]
    pub fn DownloadDiff(&mut self, path: &str) -> Result<Vec<u8>, AuthClientError> {
        self.download(path, false)
    }
    #[allow(non_snake_case)]
    pub fn ExtendFileDownload(&mut self, id: i64) -> Result<Vec<u8>, AuthClientError> {
        self.download(&format!("/api/sdk/extend-file/{id}/download"), true)
    }

    fn headers(
        &mut self,
        need_token: bool,
        secure: bool,
        body: &[u8],
    ) -> Result<Vec<(String, String)>, AuthClientError> {
        if need_token && self.token.is_empty() {
            return Err(AuthClientError::TokenUnavailable);
        }
        let mut headers = vec![("X-App-Id".to_owned(), self.config.app_id.clone())];
        if !body.is_empty() {
            headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
        }
        if secure && !self.config.token_key.is_empty() {
            let ts = self.clock.Now().to_string();
            let mut nonce_bytes = [0u8; 8];
            self.random.Fill(&mut nonce_bytes);
            let nonce = hex::encode(nonce_bytes);
            let sign = AuthCrypto::new(vec![]).HmacSha256Hex(
                self.config.token_key.as_bytes(),
                format!("{ts}\n{nonce}\n{}", String::from_utf8_lossy(body)).as_bytes(),
            );
            headers.extend([
                ("X-Ts".to_owned(), ts),
                ("X-Nonce".to_owned(), nonce),
                ("X-Sign".to_owned(), sign),
            ]);
        }
        if need_token {
            headers.push(("X-Token".to_owned(), self.token.clone()));
            if !self.mi.is_empty() {
                headers.push(("X-Mi".to_owned(), self.mi.clone()));
            }
        }
        Ok(headers)
    }
    fn send(&self, request: AuthRequest) -> Result<AuthHttpResponse, AuthClientError> {
        let response = self
            .transport
            .SendBounded(request, MAX_AUTH_RESPONSE_BYTES)?;
        if response.status != 200 {
            return Err(AuthClientError::Http(response.status));
        }
        Ok(response)
    }
    fn post(
        &mut self,
        path: &str,
        body: String,
        token: bool,
    ) -> Result<AuthResponse, AuthClientError> {
        let mut retried = false;
        loop {
            if self.session_enabled {
                self.ensure_session()?;
            }
            let bytes = self.build_body(body.as_bytes())?;
            let mut headers = self.headers(token, true, &bytes)?;
            if self.session_enabled {
                let session_index = headers
                    .iter()
                    .position(|(name, _)| name == "Content-Type")
                    .map_or(1, |index| index + 1);
                headers.insert(
                    session_index,
                    ("X-Session-Id".into(), self.session_id.clone()),
                );
            }
            let request = AuthRequest {
                method: AuthMethod::Post,
                path: path.to_owned(),
                headers,
                body: bytes,
            };
            let response = self.parse(self.send(request)?.body)?;
            if self.session_enabled && response.code == 1020 && !retried {
                self.clear_session();
                retried = true;
                continue;
            }
            return Ok(response);
        }
    }
    fn post_value<V: Serialize>(
        &mut self,
        path: &str,
        value: &V,
        token: bool,
    ) -> Result<AuthResponse, AuthClientError> {
        let body = serde_json::to_string(value)
            .map_err(|error| AuthClientError::Response(error.to_string()))?;
        self.post(path, body, token)
    }
    fn post_plain(
        &mut self,
        path: &str,
        body: &str,
        token: bool,
    ) -> Result<AuthResponse, AuthClientError> {
        let bytes = body.as_bytes().to_vec();
        let headers = self.headers(token, false, &bytes)?;
        let request = AuthRequest {
            method: AuthMethod::Post,
            path: path.to_owned(),
            headers,
            body: bytes,
        };
        self.parse(self.send(request)?.body)
    }
    fn clear_session(&mut self) {
        self.session_id.clear();
        self.session_key.clear();
    }
    fn ensure_session(&mut self) -> Result<(), AuthClientError> {
        if self.session_id.is_empty() {
            self.handshake()?;
        }
        Ok(())
    }
    fn handshake(&mut self) -> Result<(), AuthClientError> {
        if self.server_public_key.is_empty() {
            return Err(AuthClientError::Response(
                "server public key unavailable".into(),
            ));
        }
        let mut key = vec![0u8; 32];
        self.random.Fill(&mut key);
        let pem = self.server_public_key.clone();
        let cipher =
            AuthCrypto::RsaPublicEncryptWithRandom(&key, &pem, |bytes| self.random.Fill(bytes))
                .map_err(|e| AuthClientError::Response(e.to_string()))?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(cipher);
        let body = serde_json::to_vec(&HandshakeRequest { key: &encoded })
            .map_err(|e| AuthClientError::Response(e.to_string()))?;
        let headers = self.headers(false, true, &body)?;
        let response = self.send(AuthRequest {
            method: AuthMethod::Post,
            path: "/api/sdk/handshake".into(),
            headers,
            body,
        })?;
        let outer = AuthEnvelope::Parse(
            std::str::from_utf8(&response.body)
                .map_err(|e| AuthClientError::Response(e.to_string()))?,
        )
        .map_err(|e| AuthClientError::Response(e.to_string()))?;
        if outer.code != 0 {
            return Err(AuthClientError::Response(outer.msg));
        }
        let encoded = outer
            .data
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| AuthClientError::Response("handshake data unavailable".into()))?;
        let plain = decrypt_with_key(&key, &encoded)?;
        let value: serde_json::Value =
            serde_json::from_slice(&plain).map_err(|e| AuthClientError::Response(e.to_string()))?;
        self.session_id = value
            .get("sessionId")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| AuthClientError::Response("sessionId unavailable".into()))?
            .to_owned();
        self.session_key = key;
        Ok(())
    }
    fn build_body(&mut self, plain: &[u8]) -> Result<Vec<u8>, AuthClientError> {
        if !self.session_enabled {
            return Ok(plain.to_vec());
        }
        let mut iv = [0u8; 16];
        self.random.Fill(&mut iv);
        let text =
            std::str::from_utf8(plain).map_err(|e| AuthClientError::Response(e.to_string()))?;
        let cipher = AuthCrypto::new(self.session_key.clone())
            .AesEncrypt(text, &iv)
            .map_err(|e| AuthClientError::Response(e.to_string()))?;
        let mut blob = iv.to_vec();
        blob.extend(cipher);
        let encoded = base64::engine::general_purpose::STANDARD.encode(blob);
        serde_json::to_vec(&DataEnvelope { data: &encoded })
            .map_err(|e| AuthClientError::Response(e.to_string()))
    }
    fn get(
        &mut self,
        path: &str,
        token: bool,
        secure: bool,
    ) -> Result<AuthResponse, AuthClientError> {
        let mut retried = false;
        loop {
            if secure && self.session_enabled {
                self.ensure_session()?;
            }
            let mut headers = self.headers(token, secure, &[])?;
            if secure && self.session_enabled {
                headers.insert(1, ("X-Session-Id".into(), self.session_id.clone()));
            }
            let request = AuthRequest {
                method: AuthMethod::Get,
                path: path.to_owned(),
                headers,
                body: vec![],
            };
            let response = self.parse(self.send(request)?.body)?;
            if secure && self.session_enabled && response.code == 1020 && !retried {
                self.clear_session();
                retried = true;
                continue;
            }
            return Ok(response);
        }
    }
    fn parse(&self, body: Vec<u8>) -> Result<AuthResponse, AuthClientError> {
        let text = String::from_utf8(body).map_err(|e| AuthClientError::Response(e.to_string()))?;
        let envelope =
            AuthEnvelope::Parse(&text).map_err(|e| AuthClientError::Response(e.to_string()))?;
        if envelope.code == 1020 {
            return Ok(envelope.into());
        }
        if self.session_enabled && !self.session_key.is_empty() {
            if let Some(encoded) = envelope.data.as_ref().and_then(serde_json::Value::as_str) {
                let plain = decrypt_with_key(&self.session_key, encoded)?;
                let data = serde_json::from_slice(&plain)
                    .map_err(|e| AuthClientError::Response(e.to_string()))?;
                return Ok(AuthResponse {
                    code: envelope.code,
                    msg: envelope.msg,
                    data: Some(data),
                });
            }
        }
        Ok(envelope.into())
    }
    fn download(&mut self, path: &str, secure: bool) -> Result<Vec<u8>, AuthClientError> {
        let headers = self.headers(false, secure, &[])?;
        let request = AuthRequest {
            method: AuthMethod::Get,
            path: path.to_owned(),
            headers,
            body: vec![],
        };
        let mut body = Vec::new();
        self.transport.Download(request, &mut body)?;
        Ok(body)
    }
    fn file_download_request(
        &mut self,
        path: &str,
        expected: u64,
        secure: bool,
    ) -> Result<AuthRequest, AuthClientError> {
        if path.is_empty() || expected == 0 || expected > usize::MAX as u64 {
            return Err(AuthClientError::Download(
                "invalid download request".to_owned(),
            ));
        }
        let mut headers = self.headers(false, secure, &[])?;
        headers.push(("Accept-Encoding".to_owned(), "identity".to_owned()));
        Ok(AuthRequest {
            method: AuthMethod::Get,
            path: path.to_owned(),
            headers,
            body: vec![],
        })
    }

    fn download_to_file(
        &mut self,
        path: &str,
        destination: &Path,
        expected: u64,
        secure: bool,
    ) -> Result<(), AuthClientError> {
        let request = self.file_download_request(path, expected, secure)?;
        let mut random_name = [0u8; 16];
        self.random.Fill(&mut random_name);
        #[cfg(unix)]
        return download_to_file_unix(
            &self.transport,
            request,
            destination,
            expected,
            &hex::encode(random_name),
        );
        #[cfg(not(unix))]
        return download_to_file_fallback(
            &self.transport,
            request,
            destination,
            expected,
            &hex::encode(random_name),
        );
    }
}

/// 与 main 的扩展文件下载一致，直接创建调用方提供的 .part 文件。
/// 界面据此读取实时进度；完整包的校验和最终改名由调用方完成。
fn download_to_new_file<T: AuthTransport>(
    transport: &T,
    request: AuthRequest,
    destination: &Path,
    expected: u64,
) -> Result<(), AuthClientError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    // 创建失败时不能删除路径，否则会破坏原有文件或符号链接。
    let mut file = options.open(destination).map_err(|error| {
        AuthClientError::Download(format!("create download destination: {error}"))
    })?;
    let result = (|| {
        let metadata = file.metadata().map_err(|error| {
            AuthClientError::Download(format!("inspect download destination: {error}"))
        })?;
        if !metadata.is_file() {
            return Err(AuthClientError::Download(
                "download destination is not a regular file".into(),
            ));
        }
        transport.DownloadExact(request, &mut file, expected)?;
        let actual = file
            .metadata()
            .map_err(|error| {
                AuthClientError::Download(format!("inspect downloaded file: {error}"))
            })?
            .len();
        if actual != expected {
            return Err(AuthClientError::Download(format!(
                "expected {expected} bytes, file contains {actual}"
            )));
        }
        loop {
            match file.sync_all() {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(AuthClientError::Download(format!(
                        "sync downloaded file: {error}"
                    )));
                }
            }
        }
    })();
    #[cfg(unix)]
    let close_result = {
        use std::os::fd::IntoRawFd;
        // close 不能因 EINTR 重试：Linux 可能已释放并复用了这个 fd。
        if unsafe { libc::close(file.into_raw_fd()) } == 0 {
            Ok(())
        } else {
            Err(AuthClientError::Download(format!(
                "close downloaded file: {}",
                std::io::Error::last_os_error()
            )))
        }
    };
    #[cfg(not(unix))]
    let close_result = {
        drop(file);
        Ok(())
    };
    let result = result.and(close_result);
    if result.is_err() {
        let _ = std::fs::remove_file(destination);
    }
    result
}

#[cfg(not(unix))]
fn reject_symlink_components(path: &Path) -> Result<(), AuthClientError> {
    for component in path.ancestors().filter(|path| !path.as_os_str().is_empty()) {
        match fs::symlink_metadata(component) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(AuthClientError::Download(
                    "destination contains a symlink component".into(),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(AuthClientError::Download(error.to_string())),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn download_to_file_fallback<T: AuthTransport>(
    transport: &T,
    request: AuthRequest,
    destination: &Path,
    expected: u64,
    random_name: &str,
) -> Result<(), AuthClientError> {
    reject_symlink_components(destination)?;
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AuthClientError::Download("invalid destination name".into()))?;
    let temp = parent.join(format!(".{name}.{random_name}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|error| AuthClientError::Download(error.to_string()))?;
    let result = transport.Download(request, &mut file).and_then(|count| {
        if count != expected {
            return Err(AuthTransportError::Io(format!(
                "expected {expected} bytes, received {count}"
            )));
        }
        file.sync_all()
            .map_err(|error| AuthTransportError::Io(error.to_string()))
    });
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&temp);
        return Err(AuthClientError::Transport(error));
    }
    reject_symlink_components(destination)?;
    fs::rename(&temp, destination).map_err(|error| {
        let _ = fs::remove_file(&temp);
        AuthClientError::Download(error.to_string())
    })
}

#[cfg(unix)]
fn download_to_file_unix<T: AuthTransport>(
    transport: &T,
    request: AuthRequest,
    destination: &Path,
    expected: u64,
    random_name: &str,
) -> Result<(), AuthClientError> {
    use std::ffi::CString;
    use std::os::fd::{FromRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    struct Fd(RawFd);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }
    fn c_name(value: &std::ffi::OsStr) -> Result<CString, AuthClientError> {
        CString::new(value.as_bytes())
            .map_err(|_| AuthClientError::Download("path contains NUL".into()))
    }
    fn io_error(stage: &str) -> AuthClientError {
        AuthClientError::Download(format!("{stage}: {}", std::io::Error::last_os_error()))
    }
    fn reject_destination_symlink(dir: RawFd, name: &CString) -> Result<(), AuthClientError> {
        let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                dir,
                name.as_ptr(),
                status.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            let mode = unsafe { status.assume_init() }.st_mode;
            if mode & libc::S_IFMT == libc::S_IFLNK {
                return Err(AuthClientError::Download("destination is a symlink".into()));
            }
        } else {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(AuthClientError::Download(error.to_string()));
            }
        }
        Ok(())
    }

    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let destination_name = c_name(
        destination
            .file_name()
            .ok_or_else(|| AuthClientError::Download("invalid destination name".into()))?,
    )?;
    let initial = CString::new(if parent.is_absolute() { "/" } else { "." }).unwrap();
    // Android 应用可穿过 /data 等父目录，但没有列举这些目录的权限。
    // O_PATH 仅获取路径句柄，后续 openat 使用目录搜索权限，仍逐层拒绝符号链接。
    #[cfg(any(target_os = "android", target_os = "linux"))]
    let traversal_flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC;
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let traversal_flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    let mut directory = Fd(unsafe { libc::open(initial.as_ptr(), traversal_flags) });
    if directory.0 < 0 {
        return Err(io_error("open destination traversal root"));
    }
    for component in parent.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::ParentDir | Component::Prefix(_)) {
                return Err(AuthClientError::Download(
                    "destination contains unsupported path traversal".into(),
                ));
            }
            continue;
        };
        let name = c_name(name)?;
        let next = unsafe {
            libc::openat(
                directory.0,
                name.as_ptr(),
                traversal_flags | libc::O_NOFOLLOW,
            )
        };
        if next < 0 {
            return Err(io_error(&format!("open destination ancestor {name:?}")));
        }
        directory = Fd(next);
    }
    // O_PATH 不能 fsync；仅将最终已固定的应用私有目录打开为可同步的句柄。
    // 使用 openat(".") 保持前面固定的目录身份，不重新解析完整路径。
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let dot = CString::new(".").unwrap();
        let writable_parent = unsafe {
            libc::openat(
                directory.0,
                dot.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if writable_parent < 0 {
            return Err(io_error("open destination parent for sync"));
        }
        directory = Fd(writable_parent);
    }
    reject_destination_symlink(directory.0, &destination_name)?;
    let visible_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let temp_name = CString::new(format!(".{visible_name}.{random_name}.tmp")).unwrap();
    let file_fd = unsafe {
        libc::openat(
            directory.0,
            temp_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if file_fd < 0 {
        return Err(io_error("create download temporary file"));
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(file_fd) };
    let cleanup = || unsafe {
        libc::unlinkat(directory.0, temp_name.as_ptr(), 0);
    };
    let result = transport.Download(request, &mut file).and_then(|count| {
        if count != expected {
            return Err(AuthTransportError::Io(format!(
                "expected {expected} bytes, received {count}"
            )));
        }
        let metadata = file
            .metadata()
            .map_err(|error| AuthTransportError::Io(error.to_string()))?;
        if !metadata.file_type().is_file() || metadata.len() != expected {
            return Err(AuthTransportError::Io(
                "download did not produce the expected regular file".into(),
            ));
        }
        file.sync_all()
            .map_err(|error| AuthTransportError::Io(error.to_string()))
    });
    drop(file);
    if let Err(error) = result {
        cleanup();
        return Err(AuthClientError::Transport(error));
    }
    if let Err(error) = reject_destination_symlink(directory.0, &destination_name) {
        cleanup();
        return Err(error);
    }
    if unsafe {
        libc::renameat(
            directory.0,
            temp_name.as_ptr(),
            directory.0,
            destination_name.as_ptr(),
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        cleanup();
        return Err(AuthClientError::Download(error.to_string()));
    }
    if unsafe { libc::fsync(directory.0) } != 0 {
        return Err(io_error("sync download parent directory"));
    }
    Ok(())
}

impl<T: AuthTransport, R: CryptoRandom, C: Clock> RemoteConfigClient for AuthClient<T, R, C> {
    type Error = AuthClientError;

    fn fetch_user_extends(&mut self) -> Result<RemoteConfigEnvelope, Self::Error> {
        self.UserExtends(&BTreeMap::new())
    }

    fn save_user_extends(
        &mut self,
        extends: BTreeMap<String, String>,
    ) -> Result<RemoteConfigEnvelope, Self::Error> {
        self.UserExtends(&extends)
    }
}

fn parse_user_extends_response(
    response: AuthResponse,
) -> Result<RemoteConfigEnvelope, AuthClientError> {
    if response.code != 0 {
        return Ok(RemoteConfigEnvelope {
            code: response.code,
            msg: response.msg,
            data: None,
        });
    }

    let data = response
        .data
        .ok_or_else(|| AuthClientError::Response("user extends data unavailable".into()))?;
    let extends = data
        .get("extends")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AuthClientError::Response("user extends map unavailable".into()))?;
    let mut values = BTreeMap::new();
    for (key, value) in extends {
        let value = value.as_str().ok_or_else(|| {
            AuthClientError::Response(format!("user extends value for {key:?} is not a string"))
        })?;
        values.insert(key.clone(), value.to_owned());
    }
    Ok(RemoteConfigEnvelope {
        code: response.code,
        msg: response.msg,
        data: Some(RemoteConfigData { extends: values }),
    })
}

fn decrypt_with_key(key: &[u8], encoded: &str) -> Result<Vec<u8>, AuthClientError> {
    let blob =
        AuthCrypto::DecodeBase64(encoded).map_err(|e| AuthClientError::Response(e.to_string()))?;
    if blob.len() < 32 {
        return Err(AuthClientError::Response(
            "encrypted envelope is too short".into(),
        ));
    }
    AuthCrypto::new(key.to_vec())
        .AesDecrypt(&blob[16..], &blob[..16])
        .map_err(|e| AuthClientError::Response(e.to_string()))
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    struct NoopTransport;
    impl AuthTransport for NoopTransport {
        fn Send(&self, _: AuthRequest) -> Result<AuthHttpResponse, AuthTransportError> {
            unreachable!()
        }
        fn Download(
            &self,
            _: AuthRequest,
            _: &mut dyn std::io::Write,
        ) -> Result<u64, AuthTransportError> {
            unreachable!()
        }
    }
    struct NoopRandom;
    impl CryptoRandom for NoopRandom {
        fn Fill(&mut self, _: &mut [u8]) {}
    }
    struct NoopClock;
    impl Clock for NoopClock {
        fn Now(&self) -> i64 {
            0
        }
    }

    #[test]
    fn identity_and_key_changes_drop_cached_session() {
        let mut client =
            AuthClient::new(NoopTransport, NoopRandom, NoopClock, AuthConfig::new("app"));
        client.session_id = "session".into();
        client.session_key = vec![1, 2, 3];
        client.SetMi("device");
        assert!(client.session_id.is_empty());
        assert!(client.session_key.is_empty());

        client.session_id = "session".into();
        client.session_key = vec![4, 5, 6];
        client.SetRsaKeys("key");
        assert!(client.session_id.is_empty());
        assert!(client.session_key.is_empty());
    }
}
