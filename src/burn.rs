use std::path::Path;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub enum BurnProgress {
    Started,
    Burning,
    Progress { bytes_written: u64, total_bytes: u64 },
    Verifying,
    Completed,
    Cancelled,
    Error(String),
}

/// Burn a disk image (.img file) to a raw device
/// This writes directly to the device, overwriting everything including partition table
pub async fn burn_image(
    image_path: &Path,
    device_path: &str,
    progress_tx: mpsc::UnboundedSender<BurnProgress>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    crate::debug::log_section("Burn Disk Image");
    crate::debug::log(&format!("Image: {:?}", image_path));
    crate::debug::log(&format!("Device: {}", device_path));

    // Check for cancellation before starting
    if cancel_token.is_cancelled() {
        let _ = progress_tx.send(BurnProgress::Cancelled);
        return Err("Burn cancelled".to_string());
    }

    let _ = progress_tx.send(BurnProgress::Started);

    // Verify image exists
    if !image_path.exists() {
        crate::debug::log("ERROR: Image file not found");
        return Err(format!("Image file not found: {:?}", image_path));
    }

    // Get image size
    let image_size = std::fs::metadata(image_path)
        .map_err(|e| format!("Failed to get image size: {}", e))?
        .len();

    crate::debug::log(&format!("Image size: {} bytes ({:.2} GB)",
        image_size, image_size as f64 / (1024.0 * 1024.0 * 1024.0)));

    let _ = progress_tx.send(BurnProgress::Burning);

    // Platform-specific burn implementation
    #[cfg(target_os = "windows")]
    {
        burn_image_windows(image_path, device_path, image_size, progress_tx, cancel_token).await
    }

    #[cfg(target_os = "linux")]
    {
        burn_image_linux(image_path, device_path, image_size, progress_tx, cancel_token).await
    }

    #[cfg(target_os = "macos")]
    {
        burn_image_macos(image_path, device_path, image_size, progress_tx, cancel_token).await
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = progress_tx.send(BurnProgress::Error(
            "Burning not supported on this platform".to_string(),
        ));
        Err("Burning not supported on this platform".to_string())
    }
}

// =============================================================================
// Windows Helper Functions
// =============================================================================

/// Get the physical disk number from a drive letter (Windows only)
#[cfg(target_os = "windows")]
fn get_disk_number_from_drive(drive_letter: char) -> Result<u32, String> {
    use std::fs::OpenOptions;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::Win32::System::Ioctl::IOCTL_STORAGE_GET_DEVICE_NUMBER;

    crate::debug::log(&format!("Getting disk number for drive: {}", drive_letter));

    let volume_path = format!("\\\\.\\{}:", drive_letter);

    let file = OpenOptions::new()
        .read(true)
        .open(&volume_path)
        .map_err(|e| format!("Failed to open volume {}: {}", drive_letter, e))?;

    let handle = HANDLE(file.as_raw_handle() as *mut std::ffi::c_void);

    #[repr(C)]
    #[derive(Default)]
    struct StorageDeviceNumber {
        device_type: u32,
        device_number: u32,
        partition_number: u32,
    }

    let mut device_number = StorageDeviceNumber::default();
    let mut bytes_returned = 0u32;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_GET_DEVICE_NUMBER,
            None,
            0,
            Some(&mut device_number as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<StorageDeviceNumber>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    if result.is_err() {
        return Err(format!(
            "Failed to get disk number for drive {}: {:?}",
            drive_letter, result
        ));
    }

    let disk_number = device_number.device_number;
    crate::debug::log(&format!("Disk number: {}", disk_number));

    Ok(disk_number)
}

// =============================================================================
// Windows Implementation
// =============================================================================

#[cfg(target_os = "windows")]
async fn burn_image_windows(
    image_path: &Path,
    device_path: &str,
    image_size: u64,
    progress_tx: mpsc::UnboundedSender<BurnProgress>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    use std::io::Read;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, WriteFile,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH,
    };
    use windows::core::PCWSTR;

    crate::debug::log("Using Windows direct disk access");

    // Extract drive letter from device path (e.g., "E:" -> 'E')
    let drive_letter = device_path
        .chars()
        .next()
        .ok_or_else(|| "Invalid device path".to_string())?;

    // Get disk number using Windows API
    let disk_number = get_disk_number_from_drive(drive_letter)?;
    crate::debug::log(&format!("Physical disk number: {}", disk_number));

    // Open the physical disk for raw access
    let disk_path: Vec<u16> = format!("\\\\.\\PhysicalDrive{}", disk_number)
        .encode_utf16()
        .chain(Some(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            PCWSTR(disk_path.as_ptr()),
            (GENERIC_READ.0 | GENERIC_WRITE.0).into(),
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
            None,
        )
    }.map_err(|e| format!("Failed to open disk {}: {}", disk_number, e))?;

    // Open image file
    let mut image_file = std::fs::File::open(image_path)
        .map_err(|e| format!("Failed to open image file: {}", e))?;

    // Write image to disk in chunks
    const BUFFER_SIZE: usize = 1024 * 1024; // 1MB chunks
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut bytes_written: u64 = 0;

    loop {
        // Check for cancellation
        if cancel_token.is_cancelled() {
            unsafe { let _ = CloseHandle(handle); }
            crate::debug::log("Burn cancelled by user");
            let _ = progress_tx.send(BurnProgress::Cancelled);
            return Err("Burn cancelled".to_string());
        }

        // Read from image
        let bytes_read = image_file.read(&mut buffer)
            .map_err(|e| {
                unsafe { let _ = CloseHandle(handle); }
                format!("Failed to read image: {}", e)
            })?;

        if bytes_read == 0 {
            break; // EOF
        }

        // Pad buffer to sector size if needed (512 bytes)
        let write_size = if bytes_read % 512 != 0 {
            ((bytes_read / 512) + 1) * 512
        } else {
            bytes_read
        };

        // Zero-pad the remainder
        if write_size > bytes_read {
            buffer[bytes_read..write_size].fill(0);
        }

        // Write to disk
        let mut written = 0u32;
        unsafe {
            WriteFile(handle, Some(&buffer[..write_size]), Some(&mut written), None)
                .map_err(|e| {
                    let _ = CloseHandle(handle);
                    format!("Write failed at offset {}: {}", bytes_written, e)
                })?;
        }

        bytes_written += bytes_read as u64;

        // Send progress update
        let _ = progress_tx.send(BurnProgress::Progress {
            bytes_written,
            total_bytes: image_size,
        });

        // Yield to allow UI updates
        tokio::task::yield_now().await;
    }

    // Close handle
    unsafe { let _ = CloseHandle(handle); }

    crate::debug::log(&format!("Successfully wrote {} bytes", bytes_written));
    let _ = progress_tx.send(BurnProgress::Completed);
    Ok(())
}

// =============================================================================
// Linux Implementation
// =============================================================================

#[cfg(target_os = "linux")]
async fn burn_image_linux(
    image_path: &Path,
    device_path: &str,
    image_size: u64,
    progress_tx: mpsc::UnboundedSender<BurnProgress>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    use tokio::fs::File;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    crate::debug::log("Using Linux direct device write");

    // Open image file
    let mut image_file = File::open(image_path).await
        .map_err(|e| format!("Failed to open image file: {}", e))?;

    // Open device for writing
    let mut device_file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(device_path)
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                format!("Permission denied writing to {}. Ensure the application is running with root privileges.", device_path)
            } else {
                format!("Failed to open device {}: {}", device_path, e)
            }
        })?;

    // Write image to device in chunks
    const BUFFER_SIZE: usize = 1024 * 1024; // 1MB chunks
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut bytes_written: u64 = 0;

    loop {
        // Check for cancellation
        if cancel_token.is_cancelled() {
            crate::debug::log("Burn cancelled by user");
            let _ = progress_tx.send(BurnProgress::Cancelled);
            return Err("Burn cancelled".to_string());
        }

        // Read from image
        let bytes_read = image_file.read(&mut buffer).await
            .map_err(|e| format!("Failed to read image: {}", e))?;

        if bytes_read == 0 {
            break; // EOF
        }

        // Write to device
        device_file.write_all(&buffer[..bytes_read]).await
            .map_err(|e| format!("Write failed at offset {}: {}", bytes_written, e))?;

        bytes_written += bytes_read as u64;

        // Send progress update
        let _ = progress_tx.send(BurnProgress::Progress {
            bytes_written,
            total_bytes: image_size,
        });

        // Yield to allow UI updates
        tokio::task::yield_now().await;
    }

    // Sync to ensure all writes are flushed
    device_file.sync_all().await
        .map_err(|e| format!("Failed to sync device: {}", e))?;

    crate::debug::log(&format!("Successfully wrote {} bytes", bytes_written));
    let _ = progress_tx.send(BurnProgress::Completed);
    Ok(())
}

// =============================================================================
// macOS Implementation
// =============================================================================

#[cfg(target_os = "macos")]
async fn burn_image_macos(
    image_path: &Path,
    device_path: &str,
    image_size: u64,
    progress_tx: mpsc::UnboundedSender<BurnProgress>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    use tokio::fs::File;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::process::Command;

    crate::debug::log("Using macOS direct device write");

    // Unmount all partitions on this disk first
    crate::debug::log(&format!("Unmounting all partitions on {}", device_path));
    let output = Command::new("diskutil")
        .args(["unmountDisk", device_path])
        .output()
        .await
        .map_err(|e| format!("Failed to unmount disk: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        crate::debug::log(&format!("Unmount warning: {}", stderr));
        // Continue anyway - might not be mounted
    }

    // Convert /dev/diskN to /dev/rdiskN (raw disk for faster writes)
    let raw_device_path = device_path.replace("/dev/disk", "/dev/rdisk");
    crate::debug::log(&format!("Using raw device: {}", raw_device_path));

    // Open image file
    let mut image_file = File::open(image_path).await
        .map_err(|e| format!("Failed to open image file: {}", e))?;

    // Open device for writing
    let mut device_file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&raw_device_path)
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                format!("Permission denied writing to {}. Ensure the application is running with root privileges.", raw_device_path)
            } else {
                format!("Failed to open device {}: {}", raw_device_path, e)
            }
        })?;

    // Write image to device in chunks
    const BUFFER_SIZE: usize = 1024 * 1024; // 1MB chunks
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut bytes_written: u64 = 0;

    loop {
        // Check for cancellation
        if cancel_token.is_cancelled() {
            crate::debug::log("Burn cancelled by user");
            let _ = progress_tx.send(BurnProgress::Cancelled);
            return Err("Burn cancelled".to_string());
        }

        // Read from image
        let bytes_read = image_file.read(&mut buffer).await
            .map_err(|e| format!("Failed to read image: {}", e))?;

        if bytes_read == 0 {
            break; // EOF
        }

        // Write to device
        device_file.write_all(&buffer[..bytes_read]).await
            .map_err(|e| format!("Write failed at offset {}: {}", bytes_written, e))?;

        bytes_written += bytes_read as u64;

        // Send progress update
        let _ = progress_tx.send(BurnProgress::Progress {
            bytes_written,
            total_bytes: image_size,
        });

        // Yield to allow UI updates
        tokio::task::yield_now().await;
    }

    // Sync to ensure all writes are flushed
    device_file.sync_all().await
        .map_err(|e| format!("Failed to sync device: {}", e))?;

    crate::debug::log(&format!("Successfully wrote {} bytes", bytes_written));
    let _ = progress_tx.send(BurnProgress::Completed);
    Ok(())
}
