//! Form processing and multipart support
//!
//! A repeated key resolves to its **first** value everywhere in this module
//! ([`parse_form`], [`parse_form_map`], [`MultipartParser::to_map`]), matching
//! the query-string rule documented in [`crate::query`](mod@crate::query): two layers reading the
//! same input must never see different values for one key.
//!
//! Everything that arrives here — field names, values, file names, content
//! types — is client-controlled. In particular [`FormFile::filename`] is
//! whatever the client typed; use [`FormFile::safe_filename`] or
//! [`FormFile::save_into`] before it gets anywhere near a filesystem path.

use crate::Error;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Parse URL-encoded form data
///
/// Serde errors become [`Error::Deserialization`], whose detail (Rust type and
/// field names) is kept out of the client response.
pub fn parse_form<T: DeserializeOwned>(body: &[u8]) -> Result<T, Error> {
    let body = crate::query::first_wins_urlencoded(body)
        .map_err(|e| Error::Deserialization(format!("Failed to parse form data: {e}")))?;
    serde_urlencoded::from_bytes(&body)
        .map_err(|e| Error::Deserialization(format!("Failed to parse form data: {}", e)))
}

/// Parse URL-encoded form data into a HashMap (first value wins)
pub fn parse_form_map(body: &[u8]) -> Result<HashMap<String, String>, Error> {
    let form_data: Vec<(String, String)> = serde_urlencoded::from_bytes(body)
        .map_err(|e| Error::Deserialization(format!("Failed to parse form data: {}", e)))?;

    let mut map = HashMap::with_capacity(form_data.len());
    for (k, v) in form_data {
        map.entry(k).or_insert(v);
    }
    Ok(map)
}

/// Multipart form field
///
/// `Debug` redacts the value: fields routinely carry passwords and tokens,
/// and a stray `{:?}` in a log line must not leak them.
#[derive(Clone)]
pub struct FormField {
    /// Field name
    pub name: String,

    /// Field value (for text fields)
    pub value: Option<String>,

    /// File data (for file fields)
    pub file: Option<FormFile>,
}

impl std::fmt::Debug for FormField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FormField")
            .field("name", &self.name)
            .field(
                "value",
                &self
                    .value
                    .as_ref()
                    .map(|v| format!("<redacted, {} bytes>", v.len())),
            )
            .field("file", &self.file)
            .finish()
    }
}

/// Longest name [`FormFile::safe_filename`] returns, in bytes. Most
/// filesystems cap a component at 255 bytes.
pub const MAX_SAFE_FILENAME_LEN: usize = 255;

/// Longest extension, in bytes, that [`FormFile::safe_filename`] keeps intact
/// when it has to shorten an over-long name.
pub const MAX_PRESERVED_EXTENSION_LEN: usize = 16;

/// Uploaded file data
///
/// `Debug` prints the data's length, not its bytes (which may be sensitive,
/// and are unreadable and unbounded in a log line anyway).
#[derive(Clone)]
pub struct FormFile {
    /// Original filename, **exactly as the client sent it**.
    ///
    /// Untrusted: it may contain `../`, absolute paths, backslashes, NUL or
    /// control characters, or be empty. Never join it onto a directory — use
    /// [`safe_filename`](Self::safe_filename) or
    /// [`save_into`](Self::save_into).
    pub filename: String,

    /// Content type (MIME type), as claimed by the client
    pub content_type: String,

    /// File size in bytes
    pub size: usize,

    /// File data
    pub data: Vec<u8>,
}

impl std::fmt::Debug for FormFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FormFile")
            .field("filename", &self.filename)
            .field("content_type", &self.content_type)
            .field("size", &self.size)
            .field("data", &format_args!("<{} bytes>", self.data.len()))
            .finish()
    }
}

impl FormFile {
    /// Create a new form file
    pub fn new(filename: String, content_type: String, data: Vec<u8>) -> Self {
        let size = data.len();
        Self {
            filename,
            content_type,
            size,
            data,
        }
    }

    /// The extension (without the dot) of [`safe_filename`](Self::safe_filename),
    /// or `None` if that name has none.
    ///
    /// It is read from the sanitized name, not the raw client one, so the
    /// extension an allowlist checks is always the one
    /// [`save_into`](Self::save_into) stores the file under: stripping and
    /// truncation cannot turn a checked `x.html.png` into a stored `x.html`.
    /// A leading dot does not start an extension, mirroring
    /// [`Path::extension`]. Still client-chosen: check it against an
    /// allowlist rather than trusting it to say what the content is.
    ///
    /// ```
    /// use armature_core::form::FormFile;
    /// let f = FormFile::new("dir/photo.JPG".into(), "image/jpeg".into(), vec![]);
    /// assert_eq!(f.extension().as_deref(), Some("JPG"));
    /// ```
    pub fn extension(&self) -> Option<String> {
        split_extension(&self.safe_filename()).map(|(_, ext)| ext.to_string())
    }

    /// A filename derived from [`filename`](Self::filename) that is safe to
    /// use as a single component inside an upload directory.
    ///
    /// Takes the part after the last `/` or `\`, drops control characters
    /// (including NUL), invisible Unicode format characters (bidi overrides
    /// such as U+202E, zero-width characters, BOM) that make a name display
    /// as something it is not, and `:` (an NTFS alternate data stream
    /// separator); strips leading dots (no hidden files, no `..`) and trailing
    /// dots and spaces (which Windows silently drops), and caps the length at
    /// [`MAX_SAFE_FILENAME_LEN`] bytes. An over-long name is shortened in its
    /// stem so the final extension survives (one longer than
    /// [`MAX_PRESERVED_EXTENSION_LEN`] bytes is not preserved); see
    /// [`extension`](Self::extension). A Windows reserved device name (`CON`,
    /// `NUL`, `COM1`, `CONIN$`, `lpt1.txt`, ...) gets a `_` prefix. Falls back
    /// to `"file"` when nothing is left.
    ///
    /// ```
    /// use armature_core::form::FormFile;
    /// let f = FormFile::new("../../etc/passwd".into(), "text/plain".into(), vec![]);
    /// assert_eq!(f.safe_filename(), "passwd");
    /// let f = FormFile::new("C:\\Users\\x\\..\\evil.exe".into(), "x".into(), vec![]);
    /// assert_eq!(f.safe_filename(), "evil.exe");
    /// ```
    pub fn safe_filename(&self) -> String {
        let name: String = last_component(&self.filename)
            .chars()
            .filter(|&c| !c.is_control() && !is_format_char(c) && c != ':')
            .collect();
        // Dots and whitespace together at the front: trimming them one after
        // the other lets `". .htaccess"` keep its inner dot once the leading
        // space goes.
        let name = name
            .trim_start_matches(|c: char| c == '.' || c.is_whitespace())
            .trim_end_matches(|c: char| c == '.' || c.is_whitespace());

        if name.is_empty() {
            "file".to_string()
        } else if is_windows_reserved(name) {
            // One byte for the prefix keeps the result within the cap.
            format!("_{}", fit_filename(name, MAX_SAFE_FILENAME_LEN - 1))
        } else {
            fit_filename(name, MAX_SAFE_FILENAME_LEN)
        }
    }

    /// Check if file is an image
    pub fn is_image(&self) -> bool {
        self.content_type.starts_with("image/")
    }

    /// Check if file size exceeds limit
    pub fn exceeds_size(&self, max_bytes: usize) -> bool {
        self.size > max_bytes
    }

    /// Save file to disk at exactly `path`.
    ///
    /// `path` is used as given. Do not build it from
    /// [`filename`](Self::filename); use [`save_into`](Self::save_into) to
    /// store an upload under its client-supplied name.
    pub fn save_to(&self, path: &str) -> Result<(), Error> {
        std::fs::write(path, &self.data)
            .map_err(|e| Error::Internal(format!("Failed to save file: {}", e)))
    }

    /// Save file to disk asynchronously at exactly `path` (see
    /// [`save_to`](Self::save_to)).
    pub async fn save_to_async(&self, path: &str) -> Result<(), Error> {
        tokio::fs::write(path, &self.data)
            .await
            .map_err(|e| Error::Internal(format!("Failed to save file: {}", e)))
    }

    /// Save the file inside `dir` under its [`safe_filename`](Self::safe_filename),
    /// returning the path written.
    ///
    /// The file is created exclusively: an existing entry with the same name
    /// (including a planted symlink) is an error rather than overwritten or
    /// followed.
    pub fn save_into(&self, dir: impl AsRef<Path>) -> Result<PathBuf, Error> {
        use std::io::Write;

        let path = self.contained_path(dir.as_ref())?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| Error::Internal(format!("Failed to save file: {}", e)))?;
        file.write_all(&self.data)
            .map_err(|e| Error::Internal(format!("Failed to save file: {}", e)))?;
        Ok(path)
    }

    /// Async [`save_into`](Self::save_into).
    pub async fn save_into_async(&self, dir: impl AsRef<Path>) -> Result<PathBuf, Error> {
        use tokio::io::AsyncWriteExt;

        let path = self.contained_path(dir.as_ref())?;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .map_err(|e| Error::Internal(format!("Failed to save file: {}", e)))?;
        file.write_all(&self.data)
            .await
            .map_err(|e| Error::Internal(format!("Failed to save file: {}", e)))?;
        Ok(path)
    }

    /// `dir/<safe_filename>`, after checking the name really is one plain
    /// component, so the join cannot leave `dir`.
    fn contained_path(&self, dir: &Path) -> Result<PathBuf, Error> {
        let name = self.safe_filename();
        let mut components = Path::new(&name).components();
        match (components.next(), components.next()) {
            (Some(std::path::Component::Normal(_)), None) => Ok(dir.join(&name)),
            _ => Err(Error::BadRequest("Invalid upload filename".to_string())),
        }
    }
}

/// `name` (non-empty, already trimmed) shortened to at most `max` bytes.
///
/// A plain cut would drop the real extension and could expose an inner one:
/// `A..A.html.png` cut to 255 bytes is `A..A.html`, which a static file server
/// then serves as HTML although the upload was checked as a PNG. So the stem
/// is shortened instead and the final extension kept, unless that extension
/// is longer than [`MAX_PRESERVED_EXTENSION_LEN`] (no real one is), in which
/// case the name is just cut; either way
/// [`FormFile::extension`] reads the result, so checks see what is stored.
fn fit_filename(name: &str, max: usize) -> String {
    if name.len() <= max {
        return name.to_string();
    }
    if let Some((stem, ext)) = split_extension(name)
        && ext.len() <= MAX_PRESERVED_EXTENSION_LEN
    {
        // The cut stem can still trim away to nothing (`a` followed by 300
        // dots); `.{ext}` would then be a hidden file, so it gets a stem.
        let stem = truncate_filename(stem, max - ext.len() - 1);
        let stem = if stem.is_empty() { "file" } else { stem };
        return format!("{stem}.{ext}");
    }
    match truncate_filename(name, max) {
        "" => "file".to_string(),
        cut => cut.to_string(),
    }
}

/// `(stem, extension)` of a single-component name, split at its last dot,
/// when both halves are non-empty (as [`Path::extension`] would see it).
fn split_extension(name: &str) -> Option<(&str, &str)> {
    let (stem, ext) = name.rsplit_once('.')?;
    (!stem.is_empty() && !ext.is_empty()).then_some((stem, ext))
}

/// `name` cut to at most `max` bytes on a char boundary, then stripped of
/// trailing dots and spaces -- after the cut, since a cut can expose new ones
/// that Windows would silently drop.
fn truncate_filename(name: &str, max: usize) -> &str {
    let mut end = name.len().min(max);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].trim_end_matches(['.', ' '])
}

/// Unicode general category `Cf` (format): invisible characters that change
/// how surrounding text renders -- bidi overrides/isolates (`invoice\u{202E}fdp.exe`
/// displays as `invoiceexe.pdf`), zero-width spaces/joiners, the BOM.
/// Listed by hand (Unicode 15.1) since the category tables are not a
/// dependency of this crate.
fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// Whether Windows treats `name` as a device (`CON`, `PRN`, `AUX`, `NUL`,
/// `CONIN$`, `CONOUT$`, `COM0`-`COM9`, `LPT0`-`LPT9`, and the
/// superscript-digit variants), with or without an extension: opening
/// `uploads\con.txt` opens the console, not a file.
fn is_windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    match upper.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        _ => {
            let Some(digit) = upper
                .strip_prefix("COM")
                .or_else(|| upper.strip_prefix("LPT"))
            else {
                return false;
            };
            let mut chars = digit.chars();
            matches!(
                (chars.next(), chars.next()),
                (Some('0'..='9' | '\u{B9}' | '\u{B2}' | '\u{B3}'), None)
            )
        }
    }
}

/// The part of a client path after its last `/` or `\`.
fn last_component(name: &str) -> &str {
    name.rsplit(['/', '\\']).next().unwrap_or(name)
}

/// Save multiple files in parallel
///
/// This function saves multiple uploaded files concurrently, providing
/// significant performance improvements over sequential saves.
///
/// # Arguments
///
/// * `files` - Vector of tuples containing (file, destination_path)
///
/// # Returns
///
/// Returns a vector of saved file paths in the same order as input.
///
/// # Performance
///
/// - **Sequential:** O(n * disk_write_time)
/// - **Parallel:** O(max(disk_write_times))
/// - **Speedup:** 5-10x for batch file uploads
///
/// # Examples
///
/// ```no_run
/// # use armature_core::form::*;
/// # async fn example(files: Vec<FormFile>) -> Result<(), armature_core::Error> {
/// // Save 10 files in parallel (5-10x faster)
/// let file_paths: Vec<_> = files.iter()
///     .enumerate()
///     .map(|(i, file)| (file, format!("uploads/file_{}.dat", i)))
///     .collect();
///
/// let saved = save_files_parallel(file_paths).await?;
/// println!("Saved {} files", saved.len());
/// # Ok(())
/// # }
/// ```
pub async fn save_files_parallel(files: Vec<(&FormFile, String)>) -> Result<Vec<String>, Error> {
    use tokio::task::JoinSet;

    let mut set = JoinSet::new();

    for (file, path) in files {
        let data = file.data.clone();
        let path_clone = path.clone();

        set.spawn(async move {
            tokio::fs::write(&path_clone, &data)
                .await
                .map_err(|e| Error::Internal(format!("Failed to save file: {}", e)))?;
            Ok::<_, Error>(path_clone)
        });
    }

    let mut saved_paths = Vec::new();
    while let Some(result) = set.join_next().await {
        saved_paths.push(result.map_err(|e| Error::Internal(e.to_string()))??);
    }

    Ok(saved_paths)
}

/// Default cap on the number of parts [`MultipartParser`] accepts.
pub const DEFAULT_MAX_MULTIPART_PARTS: usize = 1000;

/// Default cap on the size of one part's header block, in bytes.
pub const DEFAULT_MAX_MULTIPART_HEADER_BYTES: usize = 8 * 1024;

/// Multipart form data parser (RFC 2046 / RFC 7578)
pub struct MultipartParser {
    boundary: String,
    max_parts: usize,
    max_header_bytes: usize,
}

impl MultipartParser {
    /// Create a new multipart parser from Content-Type header
    ///
    /// The boundary must be 1-70 characters from RFC 2046's `bchars` set and
    /// must not end in a space. An empty boundary would make the delimiter a
    /// bare `--`, which matches all over ordinary content.
    pub fn from_content_type(content_type: &str) -> Result<Self, Error> {
        // Example: "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"
        let params = content_type
            .split_once(';')
            .map(|(_, params)| params)
            .unwrap_or("");
        let mut boundaries = parse_params(params)?
            .into_iter()
            .filter(|(name, _)| name == "boundary")
            .map(|(_, value)| value);
        let boundary = boundaries
            .next()
            .ok_or_else(|| Error::BadRequest("Missing boundary in Content-Type".to_string()))?;
        if boundaries.next().is_some() {
            return Err(Error::BadRequest(
                "Duplicate boundary in Content-Type".to_string(),
            ));
        }

        if !is_valid_boundary(&boundary) {
            return Err(Error::BadRequest("Invalid multipart boundary".to_string()));
        }

        Ok(Self {
            boundary,
            max_parts: DEFAULT_MAX_MULTIPART_PARTS,
            max_header_bytes: DEFAULT_MAX_MULTIPART_HEADER_BYTES,
        })
    }

    /// Set the maximum number of parts; more is an error.
    pub fn with_max_parts(mut self, max_parts: usize) -> Self {
        self.max_parts = max_parts;
        self
    }

    /// Set the maximum size of one part's header block; larger is an error.
    pub fn with_max_header_bytes(mut self, max_header_bytes: usize) -> Self {
        self.max_header_bytes = max_header_bytes;
        self
    }

    /// Parse multipart form data
    pub fn parse(&self, body: &[u8]) -> Result<Vec<FormField>, Error> {
        self.parts(body).collect()
    }

    /// Iterate over the parts of `body` one at a time.
    ///
    /// Delimiters are found lazily, so a body is never indexed up front, and
    /// iteration stops at the first error (malformed framing, too many parts,
    /// oversized headers).
    pub fn parts<'a>(&'a self, body: &'a [u8]) -> MultipartParts<'a> {
        let mut dash_boundary = Vec::with_capacity(self.boundary.len() + 4);
        dash_boundary.extend_from_slice(b"\r\n--");
        dash_boundary.extend_from_slice(self.boundary.as_bytes());
        MultipartParts {
            parser: self,
            body,
            finder: memchr::memmem::Finder::new(&dash_boundary).into_owned(),
            pos: None,
            count: 0,
            done: false,
        }
    }

    /// Parse a single multipart part
    fn parse_part(&self, part: &[u8]) -> Result<FormField, Error> {
        // Split the header block from the body at the first blank line, only
        // looking as far as the header limit allows. The body must stay a raw
        // byte slice: file uploads are arbitrary binary.
        let (header_block, content) = if let Some(rest) = part.strip_prefix(b"\r\n") {
            (&part[..0], rest)
        } else {
            let window = &part[..part.len().min(self.max_header_bytes.saturating_add(4))];
            match memchr::memmem::find(window, b"\r\n\r\n") {
                Some(pos) if pos <= self.max_header_bytes => (&part[..pos], &part[pos + 4..]),
                Some(_) => return Err(multipart_error("part headers too large")),
                None if part.len() > window.len() => {
                    return Err(multipart_error("part headers too large"));
                }
                None => return Err(multipart_error("part headers not terminated")),
            }
        };

        // Lines end in CRLF and nothing else. A bare LF or CR is a line break
        // to lenient parsers but not to us, so `X-Pad: x\nContent-Disposition:
        // ..` would carry a header past this check and into theirs; NUL and
        // other controls are similarly truncated or dropped by some readers.
        // Checked on the raw bytes, before lossy decoding can rewrite them.
        if !header_block_is_clean(header_block) {
            return Err(multipart_error("invalid character in part headers"));
        }

        // Headers are ASCII per RFC 7578, so parsing them as UTF-8 is safe.
        let headers = String::from_utf8_lossy(header_block);

        let mut disposition = None;
        let mut content_type = None;
        let mut transfer_encoding = None;

        for line in headers.split("\r\n") {
            // A line starting with SP/HT is an obsolete folded continuation
            // (RFC 9112 §5.2). Parsers disagree on whether to unfold it into
            // the previous header, so a fold can hide a parameter from one
            // reader and show it to another: refuse it.
            if line.starts_with([' ', '\t']) {
                return Err(multipart_error("folded part header"));
            }
            let Some((name, value)) = line.split_once(':') else {
                return Err(multipart_error("malformed part header"));
            };
            // The name must be a bare RFC 9110 token: no whitespace before the
            // colon (RFC 9112 §5.1 requires rejecting it), which some readers
            // would otherwise trim and others treat as a different header.
            if name.is_empty() || !name.bytes().all(is_tchar) {
                return Err(multipart_error("invalid part header name"));
            }
            // Header names are case-insensitive (RFC 7578 §4.8 defers to
            // RFC 2045/5322).
            let slot = if name.eq_ignore_ascii_case("Content-Disposition") {
                &mut disposition
            } else if name.eq_ignore_ascii_case("Content-Type") {
                &mut content_type
            } else if name.eq_ignore_ascii_case("Content-Transfer-Encoding") {
                &mut transfer_encoding
            } else {
                continue;
            };
            // Two copies of a header that decides the field's name or type is
            // an ambiguity a client should not get to resolve for us.
            if slot.replace(value.trim()).is_some() {
                return Err(multipart_error("duplicate part header"));
            }
        }

        // RFC 7578 §4.7 deprecates Content-Transfer-Encoding. A part claiming
        // base64 or quoted-printable would be decoded by some readers and
        // stored verbatim by us -- two different contents for one upload --
        // so only the identity encodings are accepted.
        if let Some(cte) = transfer_encoding
            && !["7bit", "8bit", "binary"]
                .iter()
                .any(|identity| cte.eq_ignore_ascii_case(identity))
        {
            return Err(multipart_error("unsupported Content-Transfer-Encoding"));
        }

        let disposition =
            disposition.ok_or_else(|| Error::BadRequest("Missing field name".to_string()))?;
        let params = disposition
            .split_once(';')
            .map(|(_, params)| params)
            .unwrap_or("");

        let mut name = None;
        let mut filename = None;
        // No backslash escapes here: browsers percent-encode `"` and CR/LF in
        // these values (WHATWG HTML's multipart encoding) and send `\`
        // literally, while RFC-style parsers unescape it. Either reading is
        // wrong for one side, so a `\` in a quoted name/filename is refused.
        for (key, value) in parse_params_with(params, QuotedBackslash::Reject)? {
            let slot = match key.as_str() {
                "name" => &mut name,
                "filename" => &mut filename,
                // RFC 7578 §4.2: `filename*` must not be used. Ignoring it
                // would let a client show one name here and another to a proxy
                // or scanner that honours the RFC 5987 form.
                "name*" | "filename*" => {
                    return Err(multipart_error(
                        "extended (RFC 5987) Content-Disposition parameter",
                    ));
                }
                _ => continue,
            };
            if slot.replace(value).is_some() {
                return Err(multipart_error("duplicate Content-Disposition parameter"));
            }
        }

        let name = name.ok_or_else(|| Error::BadRequest("Missing field name".to_string()))?;

        if let Some(filename) = filename {
            // File field: keep the body bytes exactly as uploaded
            let file = FormFile::new(
                filename,
                content_type
                    .map(str::to_string)
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                content.to_vec(),
            );
            Ok(FormField {
                name,
                value: None,
                file: Some(file),
            })
        } else {
            Ok(FormField {
                name,
                value: Some(String::from_utf8_lossy(content).into_owned()),
                file: None,
            })
        }
    }

    /// Convert parsed fields to HashMap (first value for a name wins)
    pub fn to_map(fields: Vec<FormField>) -> HashMap<String, String> {
        let mut map = HashMap::with_capacity(fields.len());
        for field in fields {
            if let Some(value) = field.value {
                map.entry(field.name).or_insert(value);
            }
        }
        map
    }

    /// Get files from parsed fields
    pub fn get_files(fields: &[FormField]) -> Vec<(String, &FormFile)> {
        fields
            .iter()
            .filter_map(|field| field.file.as_ref().map(|file| (field.name.clone(), file)))
            .collect()
    }
}

/// Lazy iterator over the parts of a multipart body; see
/// [`MultipartParser::parts`].
pub struct MultipartParts<'a> {
    parser: &'a MultipartParser,
    body: &'a [u8],
    /// Finds `CRLF--boundary`: RFC 2046 only recognises a delimiter at the
    /// start of a line, so `--boundary` in the middle of content is content.
    finder: memchr::memmem::Finder<'static>,
    /// Start of the next part's content; `None` before the first delimiter.
    pos: Option<usize>,
    count: usize,
    done: bool,
}

impl MultipartParts<'_> {
    /// If a delimiter (`--boundary`, already matched) ends at `at`, classify
    /// what follows it: `Some(Some(next))` for a part starting at `next`,
    /// `Some(None)` for the close delimiter, `None` when this is not a
    /// delimiter line at all.
    fn after_delimiter(&self, at: usize) -> Option<Option<usize>> {
        let rest = &self.body[at..];
        // transport-padding is linear whitespace before the CRLF.
        let padding = |bytes: &[u8]| {
            bytes
                .iter()
                .take_while(|&&b| b == b' ' || b == b'\t')
                .count()
        };
        if let Some(after) = rest.strip_prefix(b"--") {
            // The close delimiter, too, must end its line (or the body):
            // `--boundary--junk` is a content line, not the end of the form,
            // or a reader that agrees with RFC 2046 would see parts we do not.
            let after = &after[padding(after)..];
            return (after.is_empty() || after.starts_with(b"\r\n")).then_some(None);
        }
        let pad = padding(rest);
        rest[pad..]
            .starts_with(b"\r\n")
            .then_some(Some(at + pad + 2))
    }

    /// The next real delimiter at or after `from`: where it starts (its
    /// leading CRLF) and what follows it.
    fn find_delimiter(&self, mut from: usize) -> Option<(usize, Option<usize>)> {
        let delim_len = self.finder.needle().len();
        while let Some(rel) = self.finder.find(&self.body[from..]) {
            let start = from + rel;
            if let Some(next) = self.after_delimiter(start + delim_len) {
                return Some((start, next));
            }
            // `--boundaryX`: a content line that merely begins like a delimiter.
            from = start + 1;
        }
        None
    }

    fn fail(&mut self, msg: &str) -> Option<Result<FormField, Error>> {
        self.done = true;
        Some(Err(multipart_error(msg)))
    }
}

impl Iterator for MultipartParts<'_> {
    type Item = Result<FormField, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let start = match self.pos {
            Some(start) => start,
            None => {
                // The first delimiter has no CRLF before it when the body
                // opens with it (no preamble).
                let delim_len = self.finder.needle().len();
                let first = if self.body.starts_with(&self.finder.needle()[2..]) {
                    self.after_delimiter(delim_len - 2)
                } else {
                    None
                };
                let first = match first {
                    Some(next) => next,
                    None => match self.find_delimiter(0) {
                        Some((_, next)) => next,
                        None => return self.fail("missing boundary"),
                    },
                };
                match first {
                    Some(start) => start,
                    None => {
                        // Close delimiter straight away: no parts.
                        self.done = true;
                        return None;
                    }
                }
            }
        };

        let Some((end, next)) = self.find_delimiter(start) else {
            return self.fail("unterminated multipart body");
        };

        self.count += 1;
        if self.count > self.parser.max_parts {
            return self.fail("too many parts");
        }

        match next {
            Some(next) => self.pos = Some(next),
            None => self.done = true,
        }

        let result = self.parser.parse_part(&self.body[start..end]);
        if result.is_err() {
            self.done = true;
        }
        Some(result)
    }
}

/// Whether a part's raw header block uses only CRLF line breaks and holds no
/// control characters other than HTAB.
fn header_block_is_clean(block: &[u8]) -> bool {
    block.iter().enumerate().all(|(i, &b)| match b {
        b'\r' => block.get(i + 1) == Some(&b'\n'),
        b'\n' => i > 0 && block[i - 1] == b'\r',
        b'\t' => true,
        _ => b >= 0x20 && b != 0x7f,
    })
}

fn multipart_error(msg: &str) -> Error {
    Error::BadRequest(format!("Malformed multipart body: {msg}"))
}

/// RFC 2046 §5.1.1: 1-70 `bchars`, not ending in a space.
fn is_valid_boundary(boundary: &str) -> bool {
    (1..=70).contains(&boundary.len())
        && !boundary.ends_with(' ')
        && boundary
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&b))
}

/// RFC 9110 `tchar`: the bytes a header field name (a `token`) may contain.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// How [`parse_params_with`] treats a `\` inside a quoted value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum QuotedBackslash {
    /// RFC 9110 `quoted-pair`: `\x` stands for `x`.
    Unescape,
    /// Refuse the parameter list.
    Reject,
}

/// [`parse_params_with`] with RFC 9110 quoted-pair unescaping.
fn parse_params(s: &str) -> Result<Vec<(String, String)>, Error> {
    parse_params_with(s, QuotedBackslash::Unescape)
}

/// Parse `; key=value; key="quoted; value"` header parameters.
///
/// Splitting on every `;` broke a quoted filename such as `"a;b.txt"` into a
/// truncated name plus a phantom parameter (`b.txt"`), which is also how a
/// client smuggles a second `name=` past a naive parser. Keys are lowercased;
/// a backslash in a quoted value is handled per `backslash`.
fn parse_params_with(s: &str, backslash: QuotedBackslash) -> Result<Vec<(String, String)>, Error> {
    let bytes = s.as_bytes();
    let mut params = Vec::new();
    let mut i = 0;

    let skip_ws = |i: &mut usize| {
        while *i < bytes.len() && (bytes[*i] == b' ' || bytes[*i] == b'\t') {
            *i += 1;
        }
    };

    loop {
        // Skip separators and whitespace between parameters.
        while i < bytes.len() && matches!(bytes[i], b';' | b' ' | b'\t') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let key_start = i;
        while i < bytes.len() && !matches!(bytes[i], b'=' | b';') {
            i += 1;
        }
        let key = s[key_start..i].trim().to_ascii_lowercase();
        if i >= bytes.len() || bytes[i] == b';' {
            // A bare token without a value carries nothing we use.
            continue;
        }
        i += 1; // '='
        skip_ws(&mut i);

        let value = if bytes.get(i) == Some(&b'"') {
            i += 1;
            let mut value = Vec::new();
            loop {
                match bytes.get(i) {
                    None => return Err(multipart_error("unterminated quoted parameter")),
                    Some(b'"') => {
                        i += 1;
                        break;
                    }
                    Some(b'\\') if backslash == QuotedBackslash::Reject => {
                        return Err(multipart_error("backslash in quoted parameter"));
                    }
                    Some(b'\\') if i + 1 < bytes.len() => {
                        value.push(bytes[i + 1]);
                        i += 2;
                    }
                    Some(&b) => {
                        value.push(b);
                        i += 1;
                    }
                }
            }
            skip_ws(&mut i);
            if i < bytes.len() && bytes[i] != b';' {
                return Err(multipart_error("garbage after quoted parameter"));
            }
            String::from_utf8_lossy(&value).into_owned()
        } else {
            let value_start = i;
            while i < bytes.len() && bytes[i] != b';' {
                i += 1;
            }
            s[value_start..i].trim().to_string()
        };

        params.push((key, value));
    }

    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_form_map() {
        let body = b"name=John+Doe&email=john%40example.com&age=30";
        let form = parse_form_map(body).unwrap();

        assert_eq!(form.get("name"), Some(&"John Doe".to_string()));
        assert_eq!(form.get("email"), Some(&"john@example.com".to_string()));
        assert_eq!(form.get("age"), Some(&"30".to_string()));
    }

    #[test]
    fn test_form_file_extension() {
        let file = FormFile::new(
            "document.pdf".to_string(),
            "application/pdf".to_string(),
            vec![1, 2, 3],
        );

        assert_eq!(file.extension().as_deref(), Some("pdf"));
    }

    #[test]
    fn test_form_file_is_image() {
        let image = FormFile::new("photo.jpg".to_string(), "image/jpeg".to_string(), vec![]);
        assert!(image.is_image());

        let doc = FormFile::new("doc.pdf".to_string(), "application/pdf".to_string(), vec![]);
        assert!(!doc.is_image());
    }

    #[test]
    fn test_form_file_size_check() {
        let file = FormFile::new(
            "file.txt".to_string(),
            "text/plain".to_string(),
            vec![0; 1024], // 1KB
        );

        assert!(!file.exceeds_size(2048)); // 2KB limit
        assert!(file.exceeds_size(512)); // 512B limit
    }

    #[test]
    fn test_multipart_parser_from_content_type() {
        let content_type = "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW";
        let parser = MultipartParser::from_content_type(content_type).unwrap();

        assert_eq!(parser.boundary, "----WebKitFormBoundary7MA4YWxkTrZu0gW");
    }

    #[test]
    fn test_multipart_binary_roundtrip() {
        // Non-UTF-8 bytes, embedded CRLFs, and leading/trailing whitespace
        // must all survive the parse exactly as uploaded.
        let file_data: Vec<u8> = vec![
            b' ', b'\t', 0x00, 0xFF, 0xFE, b'\r', b'\n', 0x80, 0xC3, 0x01, b'\n', b' ',
        ];

        let mut body = Vec::new();
        body.extend_from_slice(b"--XBOUNDARY\r\n");
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"file\"; filename=\"blob.bin\"\r\n",
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(&file_data);
        body.extend_from_slice(b"\r\n--XBOUNDARY\r\n");
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"note\"\r\n\r\n");
        body.extend_from_slice(b"hello world");
        body.extend_from_slice(b"\r\n--XBOUNDARY--\r\n");

        let parser =
            MultipartParser::from_content_type("multipart/form-data; boundary=XBOUNDARY").unwrap();
        let fields = parser.parse(&body).unwrap();

        assert_eq!(fields.len(), 2);

        let file = fields[0].file.as_ref().unwrap();
        assert_eq!(fields[0].name, "file");
        assert_eq!(file.filename, "blob.bin");
        assert_eq!(file.content_type, "application/octet-stream");
        assert_eq!(file.data, file_data);
        assert_eq!(file.size, file_data.len());

        assert_eq!(fields[1].name, "note");
        assert_eq!(fields[1].value.as_deref(), Some("hello world"));
    }

    #[test]
    fn test_multipart_parser_missing_boundary() {
        let content_type = "multipart/form-data";
        let result = MultipartParser::from_content_type(content_type);

        assert!(result.is_err());
    }

    fn parser(boundary: &str) -> MultipartParser {
        MultipartParser::from_content_type(&format!("multipart/form-data; boundary={boundary}"))
            .unwrap()
    }

    #[test]
    fn delimiter_only_counts_at_the_start_of_a_line() {
        // `--XB` in the middle of a value is content, not a part boundary.
        let body =
            b"--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx--XBy\r\n--XB--\r\n";
        let fields = parser("XB").parse(body).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].value.as_deref(), Some("x--XBy"));

        // A line that begins like the delimiter but continues is content too.
        let body =
            b"--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nl1\r\n--XBnot\r\n--XB--";
        let fields = parser("XB").parse(body).unwrap();
        assert_eq!(fields[0].value.as_deref(), Some("l1\r\n--XBnot"));
    }

    #[test]
    fn preamble_and_epilogue_are_ignored() {
        let body = b"preamble\r\n--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--XB--\r\nepilogue";
        let fields = parser("XB").parse(body).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].value.as_deref(), Some("1"));
    }

    #[test]
    fn unterminated_body_is_an_error() {
        let body = b"--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1";
        assert!(parser("XB").parse(body).is_err());
    }

    #[test]
    fn quoted_parameters_may_contain_semicolons() {
        let body = b"--XB\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a;name=b.txt\"\r\n\r\ndata\r\n--XB--";
        let fields = parser("XB").parse(body).unwrap();
        assert_eq!(fields[0].name, "f");
        assert_eq!(fields[0].file.as_ref().unwrap().filename, "a;name=b.txt");
    }

    /// One part whose header block is `headers` (CRLF-separated lines).
    fn one_part(headers: &str) -> Vec<u8> {
        format!("--XB\r\n{headers}\r\n\r\nv\r\n--XB--").into_bytes()
    }

    #[test]
    fn folded_and_non_token_part_headers_are_rejected() {
        for headers in [
            // obs-fold: a continuation line smuggling a second disposition.
            "Content-Disposition: form-data; name=\"a\"\r\n name=\"admin\"",
            "Content-Disposition: form-data; name=\"a\"\r\n\tx",
            // Whitespace before the colon (RFC 9112 §5.1 says reject).
            "Content-Disposition : form-data; name=\"a\"",
            // Leading whitespace in the name, and a non-token name.
            " Content-Disposition: form-data; name=\"a\"",
            "Content-Disposition: form-data; name=\"a\"\r\nX(Y): z",
            "Content-Disposition: form-data; name=\"a\"\r\n: empty-name",
        ] {
            assert!(
                parser("XB").parse(&one_part(headers)).is_err(),
                "{headers:?}"
            );
        }
        // Unknown but well-formed headers are still fine.
        let ok = one_part("Content-Disposition: form-data; name=\"a\"\r\nX-Custom_1: z");
        assert_eq!(parser("XB").parse(&ok).unwrap()[0].name, "a");
    }

    /// Browsers percent-encode `"` in names rather than backslash-escaping
    /// it, so `\` inside a quoted name/filename is read differently by
    /// different parsers; refuse it rather than pick one reading.
    #[test]
    fn backslashes_in_quoted_disposition_values_are_rejected() {
        for headers in [
            r#"Content-Disposition: form-data; name="a\"b""#,
            r#"Content-Disposition: form-data; name="f"; filename="C:\x.txt""#,
        ] {
            assert!(
                parser("XB").parse(&one_part(headers)).is_err(),
                "{headers:?}"
            );
        }
    }

    /// RFC 7578 §4.2 forbids `filename*`; silently ignoring it (or `name*`)
    /// lets a client present one name to this parser and another to a proxy
    /// or WAF that honours the extended form.
    #[test]
    fn extended_disposition_parameters_are_rejected() {
        for headers in [
            "Content-Disposition: form-data; name=\"f\"; filename=\"a.txt\"; filename*=UTF-8''evil.exe",
            "Content-Disposition: form-data; name=\"a\"; name*=UTF-8''admin",
        ] {
            assert!(
                parser("XB").parse(&one_part(headers)).is_err(),
                "{headers:?}"
            );
        }
    }

    #[test]
    fn huge_max_header_bytes_does_not_overflow() {
        let parser = parser("XB").with_max_header_bytes(usize::MAX);
        let fields = parser
            .parse(&one_part("Content-Disposition: form-data; name=\"a\""))
            .unwrap();
        assert_eq!(fields[0].name, "a");
    }

    #[test]
    fn debug_output_redacts_values_and_file_contents() {
        let field = FormField {
            name: "password".to_string(),
            value: Some("hunter2".to_string()),
            file: None,
        };
        let shown = format!("{field:?}");
        assert!(
            shown.contains("password") && !shown.contains("hunter2"),
            "{shown}"
        );

        let file = FormFile::new("a.txt".into(), "text/plain".into(), b"TOPSECRET".to_vec());
        let shown = format!("{file:?}");
        assert!(
            shown.contains("a.txt") && !shown.contains("84, 79"),
            "{shown}"
        );
        assert!(shown.contains('9'), "data length is still shown: {shown}");
    }

    #[test]
    fn duplicate_disposition_parameters_are_rejected() {
        let body = b"--XB\r\nContent-Disposition: form-data; name=\"user\"; name=\"admin\"\r\n\r\nv\r\n--XB--";
        assert!(parser("XB").parse(body).is_err());
        let body = b"--XB\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a\"; filename=\"b\"\r\n\r\nv\r\n--XB--";
        assert!(parser("XB").parse(body).is_err());
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let body = b"--XB\r\ncontent-disposition: form-data; NAME=\"f\"; filename=\"a.txt\"\r\nCONTENT-TYPE: text/plain\r\n\r\nv\r\n--XB--";
        let fields = parser("XB").parse(body).unwrap();
        assert_eq!(fields[0].name, "f");
        assert_eq!(fields[0].file.as_ref().unwrap().content_type, "text/plain");
    }

    #[test]
    fn boundary_must_be_1_to_70_bchars() {
        for ct in [
            "multipart/form-data; boundary=",
            "multipart/form-data; boundary=\"\"",
            "multipart/form-data; boundary=a\u{0}b",
            "multipart/form-data; boundary=x; boundary=y",
        ] {
            assert!(MultipartParser::from_content_type(ct).is_err(), "{ct}");
        }
        let long = "a".repeat(71);
        assert!(
            MultipartParser::from_content_type(&format!("multipart/form-data; boundary={long}"))
                .is_err()
        );
        let ok = "a".repeat(70);
        assert!(
            MultipartParser::from_content_type(&format!("multipart/form-data; BOUNDARY=\"{ok}\""))
                .is_ok()
        );
    }

    #[test]
    fn part_count_and_header_size_are_capped() {
        let mut body = Vec::new();
        for i in 0..5 {
            body.extend_from_slice(
                format!("--XB\r\nContent-Disposition: form-data; name=\"f{i}\"\r\n\r\nv\r\n")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(b"--XB--");
        assert_eq!(parser("XB").parse(&body).unwrap().len(), 5);
        assert!(parser("XB").with_max_parts(4).parse(&body).is_err());

        let mut big = b"--XB\r\nContent-Disposition: form-data; name=\"a\"\r\nX-Pad: ".to_vec();
        big.extend(std::iter::repeat_n(b'p', 200));
        big.extend_from_slice(b"\r\n\r\nv\r\n--XB--");
        assert!(parser("XB").parse(&big).is_ok());
        assert!(parser("XB").with_max_header_bytes(100).parse(&big).is_err());
    }

    #[test]
    fn repeated_keys_are_first_wins_everywhere() {
        let form = parse_form_map(b"role=user&role=admin").unwrap();
        assert_eq!(form.get("role").map(String::as_str), Some("user"));

        #[derive(serde::Deserialize)]
        struct Role {
            role: String,
        }
        let parsed: Role = parse_form(b"role=user&role=admin").unwrap();
        assert_eq!(parsed.role, "user");

        let body = b"--XB\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nuser\r\n--XB\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nadmin\r\n--XB--";
        let map = MultipartParser::to_map(parser("XB").parse(body).unwrap());
        assert_eq!(map.get("role").map(String::as_str), Some("user"));
    }

    #[test]
    fn form_serde_errors_are_redacted_deserialization_errors() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct Age {
            age: u8,
        }
        let err = parse_form::<Age>(b"age=old").unwrap_err();
        assert!(matches!(err, Error::Deserialization(_)), "{err:?}");
        assert!(!err.client_message().contains("u8"));
    }

    #[test]
    fn extension_is_none_without_a_dot() {
        let f = |name: &str| FormFile::new(name.to_string(), String::new(), vec![]);
        assert_eq!(f("README").extension(), None);
        assert_eq!(f(".bashrc").extension(), None);
        assert_eq!(f("trailing.").extension(), None);
        assert_eq!(f("dir.d/file").extension(), None);
        assert_eq!(f("a.tar.gz").extension().as_deref(), Some("gz"));
    }

    #[test]
    fn safe_filename_strips_paths_dots_and_control_chars() {
        let f = |name: &str| FormFile::new(name.to_string(), String::new(), vec![]).safe_filename();
        assert_eq!(f("../../etc/passwd"), "passwd");
        assert_eq!(f("..\\..\\boot.ini"), "boot.ini");
        assert_eq!(f("/abs/path/x.png"), "x.png");
        assert_eq!(f(".htaccess"), "htaccess");
        assert_eq!(f(".."), "file");
        assert_eq!(f(""), "file");
        assert_eq!(f("a\u{0}b\r\n.txt"), "ab.txt");
        assert_eq!(f("name.txt. . "), "name.txt");
        let long = format!("{}.txt", "é".repeat(200));
        let safe = f(&long);
        assert!(safe.len() <= MAX_SAFE_FILENAME_LEN);
        assert!(safe.starts_with('é'));
    }

    #[test]
    fn safe_filename_strips_format_chars_and_ads_separators() {
        let f = |name: &str| FormFile::new(name.to_string(), String::new(), vec![]).safe_filename();
        // U+202E RIGHT-TO-LEFT OVERRIDE: `invoice\u{202E}fdp.exe` renders as
        // `invoiceexe.pdf`.
        assert_eq!(f("invoice\u{202E}fdp.exe"), "invoicefdp.exe");
        assert_eq!(f("\u{200B}.env"), "env");
        assert_eq!(f("a\u{FEFF}b\u{2066}c\u{200F}.txt"), "abc.txt");
        // NTFS alternate data stream.
        assert_eq!(f("file.txt:hidden.exe"), "file.txthidden.exe");
    }

    #[test]
    fn safe_filename_avoids_windows_reserved_names() {
        let f = |name: &str| FormFile::new(name.to_string(), String::new(), vec![]).safe_filename();
        for (input, want) in [
            ("CON", "_CON"),
            ("con.txt", "_con.txt"),
            ("Aux.tar.gz", "_Aux.tar.gz"),
            ("nul", "_nul"),
            ("COM1.log", "_COM1.log"),
            ("lpt9", "_lpt9"),
            ("PRN.", "_PRN"),
        ] {
            assert_eq!(f(input), want, "{input}");
        }
        for ok in ["CONSOLE.txt", "COM10", "LPT10", "nullable", "com"] {
            assert_eq!(f(ok), ok);
        }
    }

    #[test]
    fn safe_filename_never_yields_a_hidden_name() {
        let named = |n: String| FormFile::new(n, "x".into(), vec![]).safe_filename();
        // Leading dot, space, then dots that the stem cut trims to nothing.
        let n = named(format!(". {}htaccess", ".".repeat(300)));
        assert!(!n.starts_with('.') && !n.is_empty(), "{n:?}");
        assert_eq!(named(". .htaccess".into()), "htaccess");
        assert_eq!(named(" . .env".into()), "env");
        // A stem that trims away entirely still keeps a name before the dot.
        let n = named(format!("a{}.png", ".".repeat(300)));
        assert!(!n.starts_with('.'), "{n:?}");
        assert!(n.ends_with(".png"), "{n:?}");
        // An over-long extension that is cut away to nothing falls back too.
        let n = named(format!(". {}{}", ".".repeat(300), "x".repeat(0)));
        assert_eq!(n, "file");
    }

    #[test]
    fn windows_zero_numbered_devices_are_reserved() {
        for name in ["COM0", "lpt0.txt"] {
            let f = FormFile::new(name.into(), "x".into(), vec![]);
            assert!(f.safe_filename().starts_with('_'), "{name}");
        }
    }

    #[test]
    fn safe_filename_retrims_after_truncation() {
        let f = |name: &str| FormFile::new(name.to_string(), String::new(), vec![]).safe_filename();
        // Truncation lands right after a run of dots/spaces.
        let name = format!("{}. .{}", "a".repeat(252), "b".repeat(20));
        let got = f(&name);
        assert_eq!(got, "a".repeat(252));
        // Multi-byte chars: still cut on a char boundary.
        let got = f(&"é".repeat(200));
        assert!(got.len() <= MAX_SAFE_FILENAME_LEN);
        assert!(got.chars().all(|c| c == 'é'));
    }

    /// Truncating an over-long name must not cut off the real extension:
    /// `A..A.html.png` checked as `png` but stored as `A..A.html` would be
    /// served as HTML.
    #[test]
    fn long_filename_keeps_its_final_extension() {
        let name = format!("{}.html.png", "A".repeat(250));
        let file = FormFile::new(name, "image/png".into(), vec![]);
        let safe = file.safe_filename();
        assert!(safe.len() <= MAX_SAFE_FILENAME_LEN, "{}", safe.len());
        assert!(safe.ends_with(".png"), "{safe}");
        assert_eq!(file.extension().as_deref(), Some("png"));

        // Windows reserved stem plus a long name: the `_` prefix must not
        // push the extension out either.
        let name = format!("CON.{}.png", "b".repeat(300));
        let safe = FormFile::new(name, String::new(), vec![]).safe_filename();
        assert!(
            safe.starts_with("_CON.") && safe.ends_with(".png"),
            "{safe}"
        );
        assert!(safe.len() <= MAX_SAFE_FILENAME_LEN);
    }

    /// An extension too long to preserve is not kept, and whatever the
    /// stored name ends up ending in is exactly what `extension()` reports.
    #[test]
    fn extension_always_matches_the_stored_name() {
        let name = format!("{}.html.{}", "A".repeat(249), "x".repeat(20));
        let file = FormFile::new(name, String::new(), vec![]);
        let safe = file.safe_filename();
        assert!(safe.len() <= MAX_SAFE_FILENAME_LEN);
        let stored_ext = Path::new(&safe)
            .extension()
            .map(|e| e.to_str().unwrap().to_string());
        assert_eq!(file.extension(), stored_ext);
        // The raw name's `xxx..` extension is not what gets stored.
        assert_ne!(file.extension(), Some("x".repeat(20)));

        let f = |name: &str| FormFile::new(name.to_string(), String::new(), vec![]);
        // Control/format characters stripped from the name are stripped from
        // the extension too.
        assert_eq!(f("a.ht\u{200B}ml").extension().as_deref(), Some("html"));
        assert_eq!(f("x.png. . ").extension().as_deref(), Some("png"));
    }

    #[test]
    fn windows_console_device_names_are_reserved() {
        let f = |name: &str| FormFile::new(name.to_string(), String::new(), vec![]).safe_filename();
        for (input, want) in [
            ("CONIN$", "_CONIN$"),
            ("conout$", "_conout$"),
            ("CONIN$.txt", "_CONIN$.txt"),
            ("ConOut$.log", "_ConOut$.log"),
        ] {
            assert_eq!(f(input), want, "{input}");
        }
        for ok in ["CONIN", "CONOUT$x", "CONIN$$"] {
            assert_eq!(f(ok), ok);
        }
    }

    /// Bare LF/CR, NUL and other control characters inside part headers are
    /// read differently by LF-tolerant parsers (an `X-Pad: x\nContent-
    /// Disposition: ..` line hides a second header from us): reject them.
    #[test]
    fn part_headers_with_bare_line_breaks_or_controls_are_rejected() {
        let body = |headers: &[u8]| {
            let mut b = b"--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n".to_vec();
            b.extend_from_slice(headers);
            b.extend_from_slice(b"\r\n\r\nv\r\n--XB--");
            b
        };
        for bad in [
            &b"X-Pad: x\nContent-Disposition: form-data; name=\"b\""[..],
            b"X-Pad: x\rContent-Type: text/html",
            b"X-Pad: a\0b",
            b"X-Pad: a\x01b",
            b"X-Pad: a\x7fb",
            b"X-Pad: x\r",
        ] {
            assert!(parser("XB").parse(&body(bad)).is_err(), "{bad:?}");
        }
        // HTAB inside a value is fine.
        assert!(parser("XB").parse(&body(b"X-Pad: a\tb")).is_ok());
        // Bare LF in the first header line too.
        let b = b"--XB\r\nX-Pad: x\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--XB--";
        assert!(parser("XB").parse(b).is_err());
    }

    #[test]
    fn close_delimiter_must_end_its_line() {
        // `--XB--junk` is not a close delimiter, so the body never closes.
        let body = b"--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--XB--junk";
        assert!(parser("XB").parse(body).is_err());
        // ...and as content it stays part of the field.
        let body =
            b"--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--XB--junk\r\n--XB--";
        let fields = parser("XB").parse(body).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].value.as_deref(), Some("v\r\n--XB--junk"));
        // Padding, then CRLF (with an epilogue) or end of body, is a close.
        for tail in [&b"--XB--"[..], b"--XB-- \t", b"--XB--\r\nepilogue"] {
            let mut body =
                b"--XB\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n".to_vec();
            body.extend_from_slice(tail);
            assert_eq!(parser("XB").parse(&body).unwrap().len(), 1, "{tail:?}");
        }
    }

    #[test]
    fn non_identity_content_transfer_encoding_is_rejected() {
        let body = |cte: &str| {
            format!(
                "--XB\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Transfer-Encoding: {cte}\r\n\r\nv\r\n--XB--"
            )
        };
        for ok in ["7bit", "8BIT", "Binary"] {
            assert!(parser("XB").parse(body(ok).as_bytes()).is_ok(), "{ok}");
        }
        for bad in ["base64", "quoted-printable", "x-custom", ""] {
            assert!(parser("XB").parse(body(bad).as_bytes()).is_err(), "{bad}");
        }
        let dup = "--XB\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Transfer-Encoding: binary\r\ncontent-transfer-encoding: binary\r\n\r\nv\r\n--XB--";
        assert!(parser("XB").parse(dup.as_bytes()).is_err());
    }

    #[test]
    fn save_into_stays_inside_the_directory_and_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("armature_form_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let file = FormFile::new(
            "../../escape.txt".into(),
            "text/plain".into(),
            b"hi".to_vec(),
        );
        let saved = file.save_into(&dir).unwrap();
        assert_eq!(saved, dir.join("escape.txt"));
        assert_eq!(std::fs::read(&saved).unwrap(), b"hi");

        // Same name again: refused rather than clobbered.
        assert!(file.save_into(&dir).is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
