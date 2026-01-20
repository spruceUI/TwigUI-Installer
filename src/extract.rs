use crate::config::TEMP_PREFIX;
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Clone)]
pub enum ExtractProgress {
    Started,
    Extracting,
    Progress { percent: u8 },
    Completed,
    Cancelled,
    Error(String),
}

pub async fn extract_7z(
    archive_path: &Path,
    dest_dir: &Path,
    progress_tx: mpsc::UnboundedSender<ExtractProgress>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    crate::debug::log_section("7z Extraction");
    crate::debug::log(&format!("Archive: {:?}", archive_path));
    crate::debug::log(&format!("Destination: {:?}", dest_dir));

    // Check for cancellation before starting
    if cancel_token.is_cancelled() {
        let _ = progress_tx.send(ExtractProgress::Cancelled);
        return Err("Extraction cancelled".to_string());
    }

    let _ = progress_tx.send(ExtractProgress::Started);

    // Verify archive exists
    if !archive_path.exists() {
        crate::debug::log("ERROR: Archive not found");
        return Err(format!("Archive not found: {:?}", archive_path));
    }
    crate::debug::log("Archive file exists");

    // Ensure destination directory exists
    if !dest_dir.exists() {
        crate::debug::log("Creating destination directory...");
        std::fs::create_dir_all(dest_dir)
            .map_err(|e| format!("Failed to create destination directory: {}", e))?;
    }
    crate::debug::log("Destination directory ready");

    let _ = progress_tx.send(ExtractProgress::Extracting);

    // On macOS, try to use the bundled 7zz from the app bundle first
    // This avoids Gatekeeper quarantine issues since the app is already unquarantined
    #[cfg(target_os = "macos")]
    let (seven_zip_path, is_bundled) = {
        // Try to find 7zz in app bundle: Contents/Resources/7zz
        let bundled_path = std::env::current_exe()
            .ok()
            .and_then(|exe| {
                // exe is at: SpruceOSInstaller.app/Contents/MacOS/spruceos-installer
                // We want: SpruceOSInstaller.app/Contents/Resources/7zz
                exe.parent()  // Contents/MacOS
                    .and_then(|p| p.parent())  // Contents
                    .map(|contents| contents.join("Resources/7zz"))
            });

        if let Some(ref path) = bundled_path {
            if path.exists() {
                crate::debug::log(&format!("Using bundled 7zz from app bundle: {:?}", path));
                (path.clone(), true)
            } else {
                crate::debug::log("Bundled 7zz not found, extracting to temp...");
                // Fallback to temp extraction
                let bin_dir = dirs::cache_dir().unwrap_or_else(std::env::temp_dir);
                let temp_path = bin_dir.join(format!("7zr_{}", TEMP_PREFIX));
                std::fs::write(&temp_path, SEVEN_ZIP_EXE)
                    .map_err(|e| format!("Failed to extract 7z tool: {}", e))?;
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&temp_path)
                    .map_err(|e| format!("Failed to get file permissions: {}", e))?
                    .permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&temp_path, perms)
                    .map_err(|e| format!("Failed to set executable permission: {}", e))?;
                crate::debug::log(&format!("Extracted 7z binary to: {:?}", temp_path));
                (temp_path, false)
            }
        } else {
            // Fallback to temp extraction
            let bin_dir = dirs::cache_dir().unwrap_or_else(std::env::temp_dir);
            let temp_path = bin_dir.join(format!("7zr_{}", TEMP_PREFIX));
            std::fs::write(&temp_path, SEVEN_ZIP_EXE)
                .map_err(|e| format!("Failed to extract 7z tool: {}", e))?;
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&temp_path)
                .map_err(|e| format!("Failed to get file permissions: {}", e))?
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&temp_path, perms)
                .map_err(|e| format!("Failed to set executable permission: {}", e))?;
            crate::debug::log(&format!("Extracted 7z binary to: {:?}", temp_path));
            (temp_path, false)
        }
    };

    // On non-macOS platforms, extract 7z binary to temp/cache directory (always temp-extracted, never bundled)
    #[cfg(not(target_os = "macos"))]
    let (seven_zip_path, is_bundled) = {
        #[cfg(target_os = "linux")]
        let bin_dir = dirs::cache_dir().unwrap_or_else(std::env::temp_dir);
        #[cfg(not(target_os = "linux"))]
        let bin_dir = std::env::temp_dir();

        #[cfg(target_os = "windows")]
        let temp_path = bin_dir.join(format!("7zr_{}.exe", TEMP_PREFIX));
        #[cfg(not(target_os = "windows"))]
        let temp_path = bin_dir.join(format!("7zr_{}", TEMP_PREFIX));

        crate::debug::log(&format!("Extracting 7z binary to: {:?}", temp_path));
        std::fs::write(&temp_path, SEVEN_ZIP_EXE)
            .map_err(|e| format!("Failed to extract 7z tool: {}", e))?;
        crate::debug::log("7z binary extracted successfully");

        // On Unix (Linux), make the binary executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&temp_path)
                .map_err(|e| format!("Failed to get file permissions: {}", e))?
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&temp_path, perms)
                .map_err(|e| format!("Failed to set executable permission: {}", e))?;
        }

        (temp_path, false)
    };

    // Run 7z to extract the archive with -bsp1 for progress output
    let output_arg = format!("-o{}", dest_dir.display());
    crate::debug::log(&format!("Running 7z extraction command with output arg: {}", output_arg));

    #[cfg(target_os = "windows")]
    let mut child = Command::new(&seven_zip_path)
        .arg("x")
        .arg(archive_path)
        .arg(&output_arg)
        .arg("-y")
        .arg("-bsp1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("Failed to start 7z: {}", e))?;

    #[cfg(not(target_os = "windows"))]
    let mut child = Command::new(&seven_zip_path)
        .arg("x")
        .arg(archive_path)
        .arg(&output_arg)
        .arg("-y")
        .arg("-bsp1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start 7z: {}", e))?;

    // Take stdout for progress parsing
    let stdout = child.stdout.take()
        .ok_or_else(|| "Failed to capture 7z stdout".to_string())?;

    // Take stderr for error capture
    let stderr = child.stderr.take();

    let mut reader = BufReader::new(stdout);
    let mut last_percent: u8 = 0;
    let mut buffer = Vec::new();

    // Read stdout looking for progress - 7z uses \r for progress updates
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                crate::debug::log("Extraction cancelled by user");
                let _ = child.kill().await;
                // Only delete if it's a temp-extracted binary, not a bundled one
                if !is_bundled {
                    let _ = std::fs::remove_file(&seven_zip_path);
                }
                let _ = progress_tx.send(ExtractProgress::Cancelled);
                return Err("Extraction cancelled".to_string());
            }
            read_result = reader.read_until(b'\r', &mut buffer) => {
                match read_result {
                    Ok(0) => {
                        // EOF - process finished output
                        break;
                    }
                    Ok(_) => {
                        // Parse the buffer for percentage
                        if let Ok(line) = std::str::from_utf8(&buffer) {
                            if let Some(percent) = parse_7z_percentage(line) {
                                if percent != last_percent {
                                    last_percent = percent;
                                    let _ = progress_tx.send(ExtractProgress::Progress { percent });
                                }
                            }
                        }
                        buffer.clear();
                    }
                    Err(e) => {
                        crate::debug::log(&format!("Error reading 7z output: {}", e));
                        break;
                    }
                }
            }
        }
    }

    // Wait for process to complete
    let status = child.wait().await
        .map_err(|e| format!("Failed to wait for 7z: {}", e))?;

    // Clean up the temp 7z executable (only if not bundled)
    if !is_bundled {
        let _ = std::fs::remove_file(&seven_zip_path);
        crate::debug::log("Cleaned up temp 7z binary");
    } else {
        crate::debug::log("Keeping bundled 7z binary (from app bundle)");
    }

    if status.success() {
        crate::debug::log("7z extraction completed successfully");
        let _ = progress_tx.send(ExtractProgress::Completed);
        Ok(())
    } else {
        // Read stderr for error details
        let stderr_output = if let Some(mut stderr) = stderr {
            use tokio::io::AsyncReadExt;
            let mut stderr_buf = Vec::new();
            let _ = stderr.read_to_end(&mut stderr_buf).await;
            String::from_utf8_lossy(&stderr_buf).trim().to_string()
        } else {
            String::new()
        };

        let exit_code = status.code().map(|c| c.to_string()).unwrap_or_else(|| "unknown".to_string());
        let err_msg = if stderr_output.is_empty() {
            format!("7z extraction failed with exit code: {}", exit_code)
        } else {
            format!("7z extraction failed (code {}): {}", exit_code, stderr_output)
        };

        crate::debug::log(&format!("ERROR: {}", err_msg));
        let _ = progress_tx.send(ExtractProgress::Error(err_msg.clone()));
        Err(err_msg)
    }
}

/// Parse percentage from 7z output line
/// 7z with -bsp1 outputs progress like " 45% 12 - filename" or just " 45%"
fn parse_7z_percentage(line: &str) -> Option<u8> {
    // Look for pattern like "45%" anywhere in the line
    if let Some(percent_pos) = line.find('%') {
        let before_percent = &line[..percent_pos];
        let num_str: String = before_percent
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .chars()
            .rev()
            .collect();

        if !num_str.is_empty() {
            if let Ok(percent) = num_str.parse::<u8>() {
                return Some(percent.min(100));
            }
        }
    }
    None
}

/// Main entry point for extraction with cancellation support
pub async fn extract_7z_with_progress(
    archive_path: &Path,
    dest_dir: &Path,
    progress_tx: mpsc::UnboundedSender<ExtractProgress>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    extract_7z(archive_path, dest_dir, progress_tx, cancel_token).await
}

// =============================================================================
// ZIP Extraction (for image files)
// =============================================================================

/// Extract a ZIP archive and find the .img file inside
/// Returns the path to the extracted .img file
pub async fn extract_zip_and_find_img(
    archive_path: &Path,
    dest_dir: &Path,
    progress_tx: mpsc::UnboundedSender<ExtractProgress>,
    cancel_token: CancellationToken,
) -> Result<std::path::PathBuf, String> {
    crate::debug::log_section("ZIP Extraction");
    crate::debug::log(&format!("Archive: {:?}", archive_path));
    crate::debug::log(&format!("Destination: {:?}", dest_dir));

    // Check for cancellation before starting
    if cancel_token.is_cancelled() {
        let _ = progress_tx.send(ExtractProgress::Cancelled);
        return Err("Extraction cancelled".to_string());
    }

    let _ = progress_tx.send(ExtractProgress::Started);

    // Verify archive exists
    if !archive_path.exists() {
        crate::debug::log("ERROR: Archive not found");
        return Err(format!("Archive not found: {:?}", archive_path));
    }
    crate::debug::log("Archive file exists");

    // Ensure destination directory exists
    if !dest_dir.exists() {
        crate::debug::log("Creating destination directory...");
        std::fs::create_dir_all(dest_dir)
            .map_err(|e| format!("Failed to create destination directory: {}", e))?;
    }
    crate::debug::log("Destination directory ready");

    let _ = progress_tx.send(ExtractProgress::Extracting);

    // Open the ZIP archive
    let archive_file = std::fs::File::open(archive_path)
        .map_err(|e| format!("Failed to open archive: {}", e))?;

    let mut archive = zip::ZipArchive::new(archive_file)
        .map_err(|e| format!("Failed to read ZIP archive: {}", e))?;

    let total_files = archive.len();
    crate::debug::log(&format!("Archive contains {} files", total_files));

    let mut img_file_path: Option<std::path::PathBuf> = None;

    // Extract all files
    for i in 0..total_files {
        // Check for cancellation
        if cancel_token.is_cancelled() {
            crate::debug::log("Extraction cancelled by user");
            let _ = progress_tx.send(ExtractProgress::Cancelled);
            return Err("Extraction cancelled".to_string());
        }

        let mut file = archive.by_index(i)
            .map_err(|e| format!("Failed to read file {}: {}", i, e))?;

        let file_path: std::path::PathBuf = match file.enclosed_name() {
            Some(path) => path.to_owned(),
            None => {
                crate::debug::log(&format!("Skipping file {} (invalid name)", i));
                continue;
            }
        };

        let outpath = dest_dir.join(&file_path);

        if file.is_dir() {
            crate::debug::log(&format!("Creating directory: {:?}", outpath));
            std::fs::create_dir_all(&outpath)
                .map_err(|e| format!("Failed to create directory {:?}: {}", outpath, e))?;
        } else {
            crate::debug::log(&format!("Extracting file: {:?}", outpath));

            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(p)
                        .map_err(|e| format!("Failed to create parent directory {:?}: {}", p, e))?;
                }
            }

            let mut outfile = std::fs::File::create(&outpath)
                .map_err(|e| format!("Failed to create file {:?}: {}", outpath, e))?;

            std::io::copy(&mut file, &mut outfile)
                .map_err(|e| format!("Failed to extract file {:?}: {}", outpath, e))?;

            // Check if this is an .img file
            if let Some(ext) = outpath.extension() {
                if ext.to_string_lossy().to_lowercase() == "img" {
                    crate::debug::log(&format!("Found .img file: {:?}", outpath));
                    img_file_path = Some(outpath.clone());
                }
            }
        }

        // Send progress update
        let percent = ((i + 1) as f32 / total_files as f32 * 100.0) as u8;
        let _ = progress_tx.send(ExtractProgress::Progress { percent });

        // Yield to allow UI updates
        tokio::task::yield_now().await;
    }

    crate::debug::log("Extraction completed");
    let _ = progress_tx.send(ExtractProgress::Completed);

    // Return the path to the .img file
    img_file_path.ok_or_else(|| {
        "No .img file found in archive. The ZIP should contain a disk image file with .img extension.".to_string()
    })
}

// =============================================================================
// GZIP Decompression (for .img.gz files)
// =============================================================================

/// Decompress a .img.gz file and return the path to the extracted .img file
pub async fn decompress_img_gz(
    gz_path: &Path,
    dest_dir: &Path,
    progress_tx: mpsc::UnboundedSender<ExtractProgress>,
    cancel_token: CancellationToken,
) -> Result<std::path::PathBuf, String> {
    use async_compression::tokio::bufread::GzipDecoder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

    crate::debug::log_section("GZIP Decompression");
    crate::debug::log(&format!("Archive: {:?}", gz_path));
    crate::debug::log(&format!("Destination: {:?}", dest_dir));

    // Check for cancellation before starting
    if cancel_token.is_cancelled() {
        let _ = progress_tx.send(ExtractProgress::Cancelled);
        return Err("Decompression cancelled".to_string());
    }

    let _ = progress_tx.send(ExtractProgress::Started);

    // Verify archive exists
    if !gz_path.exists() {
        crate::debug::log("ERROR: Archive not found");
        return Err(format!("Archive not found: {:?}", gz_path));
    }
    crate::debug::log("Archive file exists");

    // Get file size for progress tracking
    let gz_size = tokio::fs::metadata(gz_path)
        .await
        .map_err(|e| format!("Failed to get archive size: {}", e))?
        .len();
    crate::debug::log(&format!("Archive size: {} bytes", gz_size));

    // Ensure destination directory exists
    if !dest_dir.exists() {
        crate::debug::log("Creating destination directory...");
        tokio::fs::create_dir_all(dest_dir)
            .await
            .map_err(|e| format!("Failed to create destination directory: {}", e))?;
    }
    crate::debug::log("Destination directory ready");

    let _ = progress_tx.send(ExtractProgress::Extracting);

    // Determine output filename (remove .gz extension)
    let output_filename = gz_path
        .file_stem()
        .ok_or_else(|| "Invalid archive filename".to_string())?;
    let output_path = dest_dir.join(output_filename);

    crate::debug::log(&format!("Output file: {:?}", output_path));

    // Open the .gz file
    let gz_file = tokio::fs::File::open(gz_path)
        .await
        .map_err(|e| format!("Failed to open archive: {}", e))?;

    // Create gzip decoder
    let buf_reader = BufReader::new(gz_file);
    let mut decoder = GzipDecoder::new(buf_reader);

    // Create output file
    let mut output_file = tokio::fs::File::create(&output_path)
        .await
        .map_err(|e| format!("Failed to create output file: {}", e))?;

    // Decompress in chunks with progress updates
    const BUFFER_SIZE: usize = 1024 * 1024; // 1MB chunks
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut total_written: u64 = 0;

    loop {
        // Check for cancellation
        if cancel_token.is_cancelled() {
            crate::debug::log("Decompression cancelled by user");
            let _ = progress_tx.send(ExtractProgress::Cancelled);
            // Clean up partial file
            let _ = tokio::fs::remove_file(&output_path).await;
            return Err("Decompression cancelled".to_string());
        }

        // Read decompressed data
        let bytes_read = decoder
            .read(&mut buffer)
            .await
            .map_err(|e| format!("Failed to decompress: {}", e))?;

        if bytes_read == 0 {
            break; // EOF
        }

        // Write to output file
        output_file
            .write_all(&buffer[..bytes_read])
            .await
            .map_err(|e| format!("Failed to write decompressed data: {}", e))?;

        total_written += bytes_read as u64;

        // Send progress update (estimate based on written bytes)
        // Note: Decompressed size is typically larger than compressed, so we estimate
        let percent = ((total_written.min(gz_size * 3) * 100) / (gz_size * 3)).min(99) as u8;
        let _ = progress_tx.send(ExtractProgress::Progress { percent });

        // Yield to allow UI updates
        tokio::task::yield_now().await;
    }

    // Flush output file
    output_file
        .flush()
        .await
        .map_err(|e| format!("Failed to flush output file: {}", e))?;

    crate::debug::log(&format!(
        "Decompression complete. Wrote {} bytes",
        total_written
    ));

    // Verify the output is an .img file
    if let Some(ext) = output_path.extension() {
        if ext.to_string_lossy().to_lowercase() == "img" {
            crate::debug::log(&format!("Successfully decompressed .img file: {:?}", output_path));
            let _ = progress_tx.send(ExtractProgress::Completed);
            Ok(output_path)
        } else {
            Err(format!(
                "Decompressed file is not an .img file: {:?}",
                output_path
            ))
        }
    } else {
        Err(format!("Decompressed file has no extension: {:?}", output_path))
    }
}
