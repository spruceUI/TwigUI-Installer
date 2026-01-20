use std::path::Path;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub enum ExtractProgress {
    Started,
    Extracting,
    Progress { percent: u8 },
    Completed,
    Cancelled,
    Error(String),
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
