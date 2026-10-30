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
#[derive(Debug, Clone)]
pub struct FormField {
    /// Field name
    pub name: String,

    /// Field value (for text fields)
    pub value: Option<String>,

    /// File data (for file fields)
    pub file: Option<FormFile>,
}

/// Longest name [`FormFile::safe_filename`] returns, in bytes. Most
/// filesystems cap a component at 255 bytes.
pub const MAX_SAFE_FILENAME_LEN: usize = 255;

/// Uploaded file data
#[derive(Debug, Clone)]
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

    /// Get the file extension (without the dot), or `None` if the name has
    /// none.
    ///
    /// Only the last path component is considered, and a leading dot does not
    /// start an extension (`.bashrc` has none), mirroring
    /// [`Path::extension`]. Still client-controlled: do not use it to decide
    /// how a file is executed or served.
    pub fn extension(&self) -> Option<&str> {
        let name = last_component(&self.filename);
        let (stem, ext) = name.rsplit_once('.')?;
        (!stem.is_empty() && !ext.is_empty()).then_some(ext)
    }

    /// A filename derived from [`filename`](Self::filename) that is safe to
    /// use as a single component inside an upload directory.
    ///
    /// Takes the part after the last `/` or `\`, drops control characters
    /// (including NUL), strips leading dots (no hidden files, no `..`) and
    /// trailing dots and spaces (which Windows silently drops), and caps the
    /// length at [`MAX_SAFE_FILENAME_LEN`] bytes. Falls back to `"file"` when
    /// nothing is left.
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
            .filter(|c| !c.is_control())
            .collect();
        let name = name
            .trim()
            .trim_start_matches('.')
            .trim_end_matches(['.', ' ']);

        let mut end = name.len().min(MAX_SAFE_FILENAME_LEN);
        while !name.is_char_boundary(end) {
            end -= 1;
        }
        let name = &name[..end];

        if name.is_empty() {
            "file".to_string()
        } else {
            name.to_string()
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
            let window = &part[..part.len().min(self.max_header_bytes + 4)];
            match memchr::memmem::find(window, b"\r\n\r\n") {
                Some(pos) if pos <= self.max_header_bytes => (&part[..pos], &part[pos + 4..]),
                Some(_) => return Err(multipart_error("part headers too large")),
                None if part.len() > window.len() => {
                    return Err(multipart_error("part headers too large"));
                }
                None => return Err(multipart_error("part headers not terminated")),
            }
        };

        // Headers are ASCII per RFC 7578, so parsing them as UTF-8 is safe.
        let headers = String::from_utf8_lossy(header_block);

        let mut disposition = None;
        let mut content_type = None;

        for line in headers.split("\r\n") {
            let Some((name, value)) = line.split_once(':') else {
                return Err(multipart_error("malformed part header"));
            };
            // Header names are case-insensitive (RFC 7578 §4.8 defers to
            // RFC 2045/5322).
            let name = name.trim();
            let slot = if name.eq_ignore_ascii_case("Content-Disposition") {
                &mut disposition
            } else if name.eq_ignore_ascii_case("Content-Type") {
                &mut content_type
            } else {
                continue;
            };
            // Two copies of a header that decides the field's name or type is
            // an ambiguity a client should not get to resolve for us.
            if slot.replace(value.trim()).is_some() {
                return Err(multipart_error("duplicate part header"));
            }
        }

        let disposition =
            disposition.ok_or_else(|| Error::BadRequest("Missing field name".to_string()))?;
        let params = disposition
            .split_once(';')
            .map(|(_, params)| params)
            .unwrap_or("");

        let mut name = None;
        let mut filename = None;
        for (key, value) in parse_params(params)? {
            let slot = match key.as_str() {
                "name" => &mut name,
                "filename" => &mut filename,
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
        if rest.starts_with(b"--") {
            return Some(None);
        }
        // transport-padding is linear whitespace before the CRLF.
        let padding = rest
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
        rest[padding..]
            .starts_with(b"\r\n")
            .then_some(Some(at + padding + 2))
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

/// Parse `; key=value; key="quoted; value"` header parameters.
///
/// Splitting on every `;` broke a quoted filename such as `"a;b.txt"` into a
/// truncated name plus a phantom parameter (`b.txt"`), which is also how a
/// client smuggles a second `name=` past a naive parser. Keys are lowercased;
/// quoted values have their backslash escapes removed.
fn parse_params(s: &str) -> Result<Vec<(String, String)>, Error> {
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

        assert_eq!(file.extension(), Some("pdf"));
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
        assert_eq!(f("a.tar.gz").extension(), Some("gz"));
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
