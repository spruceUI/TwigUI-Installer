use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[cfg(target_os = "windows")]
use std::process::Stdio;
#[cfg(target_os = "windows")]
use tokio::io::AsyncWriteExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Clone)]
pub enum FormatProgress {
    Started,
    Unmounting,
    CleaningDisk,
    CreatingPartition,
    Formatting,
    Progress { percent: u8 },
    Completed,
    Cancelled,
    Error(String),
}

// =============================================================================
// Windows Implementation
// =============================================================================

/// Get the physical disk number from a drive letter (Windows only)
/// Used by burn.rs to get the disk number for raw disk access
#[cfg(target_os = "windows")]
pub fn get_disk_number_from_drive(drive_letter: char) -> Result<u32, String> {
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

/// Format a drive to FAT32 with MBR partition table (Windows)
/// Works for drives of any size (bypasses Windows 32GB FAT32 limit)
#[cfg(target_os = "windows")]
pub async fn format_drive_fat32(
    device_path: &str,
    volume_label: &str,
    progress_tx: mpsc::UnboundedSender<FormatProgress>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::Win32::System::Ioctl::{IOCTL_DISK_GET_LENGTH_INFO, IOCTL_STORAGE_GET_DEVICE_NUMBER};

    crate::debug::log_section("Windows Format Operation");
    crate::debug::log(&format!("Device path: {}", device_path));
    crate::debug::log(&format!("Volume label: {}", volume_label));

    // Check for cancellation before starting
    if cancel_token.is_cancelled() {
        let _ = progress_tx.send(FormatProgress::Cancelled);
        return Err("Format cancelled".to_string());
    }

    let _ = progress_tx.send(FormatProgress::Started);
    let _ = progress_tx.send(FormatProgress::Progress { percent: 0 });

    // Extract drive letter from device path (e.g., "E:" -> 'E')
    let drive_letter = device_path
        .chars()
        .next()
        .ok_or_else(|| "Invalid device path".to_string())?;

    // Get disk number using Windows API directly
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
    drop(file);

    let _ = progress_tx.send(FormatProgress::Progress { percent: 10 });

    // Get the disk size from the physical disk
    let disk_path = format!("\\\\.\\PhysicalDrive{}", disk_number);
    let disk_file = OpenOptions::new()
        .read(true)
        .open(&disk_path)
        .map_err(|e| format!("Failed to open physical disk {}: {}", disk_number, e))?;

    let disk_handle = HANDLE(disk_file.as_raw_handle() as *mut std::ffi::c_void);

    #[repr(C)]
    #[derive(Default)]
    struct GetLengthInfo {
        length: i64,
    }

    let mut length_info = GetLengthInfo::default();

    let result = unsafe {
        DeviceIoControl(
            disk_handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            None,
            0,
            Some(&mut length_info as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<GetLengthInfo>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    let disk_size = if result.is_ok() && length_info.length > 0 {
        length_info.length as u64
    } else {
        // Fallback: try GetDiskFreeSpaceExW
        get_drive_size_windows(drive_letter).unwrap_or(32u64 * 1024 * 1024 * 1024)
    };

    crate::debug::log(&format!("Disk size: {} bytes ({:.2} GB)", disk_size, disk_size as f64 / 1_073_741_824.0));
    drop(disk_file);

    // Check for cancellation before destructive operation
    if cancel_token.is_cancelled() {
        let _ = progress_tx.send(FormatProgress::Cancelled);
        return Err("Format cancelled".to_string());
    }

    // Lock and dismount the volume BEFORE running diskpart
    // This is critical - diskpart's clean command will fail if the volume is mounted
    let _ = progress_tx.send(FormatProgress::Unmounting);
    let _ = progress_tx.send(FormatProgress::Progress { percent: 15 });
    crate::debug::log("Locking and dismounting volume before diskpart...");
    lock_and_dismount_volume(drive_letter).await;
    crate::debug::log("Volume locked/dismounted");

    // Give Windows a moment to fully release the volume
    // Check for cancellation during the sleep to avoid destructive operations if user cancelled
    tokio::select! {
        _ = cancel_token.cancelled() => {
            crate::debug::log("Format cancelled during volume release wait");
            let _ = progress_tx.send(FormatProgress::Cancelled);
            return Err("Format cancelled".to_string());
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_millis(500)) => {}
    }

    // Check for cancellation one more time before destructive diskpart clean operation
    if cancel_token.is_cancelled() {
        crate::debug::log("Format cancelled before diskpart clean");
        let _ = progress_tx.send(FormatProgress::Cancelled);
        return Err("Format cancelled".to_string());
    }

    let _ = progress_tx.send(FormatProgress::CleaningDisk);
    let _ = progress_tx.send(FormatProgress::Progress { percent: 20 });
    crate::debug::log("Running diskpart to clean and partition disk...");

    // Create diskpart script for partitioning only (no format)
    let script = create_partition_script(disk_number, drive_letter);

    // Run diskpart with the script
    let mut child = Command::new("diskpart")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("Failed to start diskpart: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .await
            .map_err(|e| format!("Failed to write to diskpart: {}", e))?;
    }

    let _ = progress_tx.send(FormatProgress::CreatingPartition);
    let _ = progress_tx.send(FormatProgress::Progress { percent: 40 });

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("Diskpart failed: {}", e))?;

    // Check for errors
    let stdout = String::from_utf8_lossy(&output.stdout);
    crate::debug::log(&format!("Diskpart output:\n{}", stdout));

    if stdout.contains("DiskPart has encountered an error")
        || stdout.contains("Virtual Disk Service error")
        || stdout.contains("Access is denied")
    {
        crate::debug::log(&format!("Diskpart error detected"));
        return Err(format!("Diskpart error:\n{}", stdout));
    }

    crate::debug::log("Diskpart completed successfully");
    let _ = progress_tx.send(FormatProgress::Progress { percent: 50 });

    // Check for cancellation before format
    if cancel_token.is_cancelled() {
        let _ = progress_tx.send(FormatProgress::Cancelled);
        return Err("Format cancelled".to_string());
    }

    // Wait for diskpart to finish and Windows to settle
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

    let _ = progress_tx.send(FormatProgress::Formatting);
    let _ = progress_tx.send(FormatProgress::Progress { percent: 60 });

    // Lock/dismount again in case Windows auto-mounted the new partition
    lock_and_dismount_volume(drive_letter).await;

    let _ = progress_tx.send(FormatProgress::Progress { percent: 70 });

    // Note: FAT32 formatting removed - this burner writes raw disk images instead
    // The format_drive_fat32 function is kept only for backwards compatibility
    // and because get_disk_number_from_drive() is still used by burn.rs
    crate::debug::log("Format function called but FAT32 formatting is disabled (raw image burning only)");
    return Err("FAT32 formatting is no longer supported - this tool burns raw disk images".to_string());

    #[allow(unreachable_code)]
    {
        let _ = progress_tx.send(FormatProgress::Progress { percent: 95 });
    crate::debug::log("FAT32 format completed, waiting for Windows to recognize filesystem...");
    // Wait for Windows to recognize the new filesystem
    tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;

    let _ = progress_tx.send(FormatProgress::Progress { percent: 100 });
    let _ = progress_tx.send(FormatProgress::Completed);
    crate::debug::log("Windows format operation completed successfully");
    Ok(())
}

#[cfg(target_os = "windows")]
fn get_drive_size_windows(drive_letter: char) -> Result<u64, String> {
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let root_path: Vec<u16> = format!("{}:\\", drive_letter)
        .encode_utf16()
        .chain(Some(0))
        .collect();

    let mut total_bytes = 0u64;

    unsafe {
        let _ = GetDiskFreeSpaceExW(
            windows::core::PCWSTR(root_path.as_ptr()),
            None,
            Some(&mut total_bytes),
            None,
        );
    }

    if total_bytes == 0 {
        total_bytes = 32u64 * 1024 * 1024 * 1024;
    }

    Ok(total_bytes)
}

#[cfg(target_os = "windows")]
fn create_partition_script(disk_number: u32, drive_letter: char) -> String {
    // Only partition, don't format - we'll use our custom formatter
    // Remove the drive letter first to force Windows to release the volume,
    // then clean and recreate. Assign the letter back at the end.
    format!(
        r#"select volume {}
remove letter={}
select disk {}
clean
create partition primary
select partition 1
active
assign letter={}
exit
"#,
        drive_letter, drive_letter, disk_number, drive_letter
    )
}

#[cfg(target_os = "windows")]
async fn lock_and_dismount_volume(drive_letter: char) {
    use std::fs::OpenOptions;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::IO::DeviceIoControl;

    const FSCTL_LOCK_VOLUME: u32 = 0x00090018;
    const FSCTL_DISMOUNT_VOLUME: u32 = 0x00090020;

    let volume_path = format!("\\\\.\\{}:", drive_letter);

    // Try to open and lock the volume
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .open(&volume_path)
    {
        Ok(f) => f,
        Err(_) => return, // Volume might not exist yet, that's okay
    };

    let handle = HANDLE(file.as_raw_handle() as *mut std::ffi::c_void);
    let mut bytes_returned = 0u32;

    // Try to lock the volume
    let _ = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_LOCK_VOLUME,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    // Dismount the volume
    let _ = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_DISMOUNT_VOLUME,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    // Keep the handle open briefly to maintain the lock
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    drop(file);
}

// =============================================================================
// Linux Implementation
// =============================================================================

#[cfg(target_os = "linux")]
pub async fn format_drive_fat32(
    device_path: &str,
    volume_label: &str,
    progress_tx: mpsc::UnboundedSender<FormatProgress>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    crate::debug::log_section("Linux Format Operation");
    crate::debug::log(&format!("Device path: {}", device_path));
    crate::debug::log(&format!("Volume label: {}", volume_label));

    // Check for cancellation before starting
    if cancel_token.is_cancelled() {
        let _ = progress_tx.send(FormatProgress::Cancelled);
        return Err("Format cancelled".to_string());
    }

    let _ = progress_tx.send(FormatProgress::Started);
    let _ = progress_tx.send(FormatProgress::Progress { percent: 0 });

    // Unmount any mounted partitions on this device
    let _ = progress_tx.send(FormatProgress::Unmounting);
    let _ = progress_tx.send(FormatProgress::Progress { percent: 10 });
    crate::debug::log("Unmounting device partitions...");
    unmount_linux_device(device_path).await?;
    crate::debug::log("Unmount complete");

    // Check for cancellation before destructive operation
    if cancel_token.is_cancelled() {
        let _ = progress_tx.send(FormatProgress::Cancelled);
        return Err("Format cancelled".to_string());
    }

    let _ = progress_tx.send(FormatProgress::CleaningDisk);
    let _ = progress_tx.send(FormatProgress::Progress { percent: 20 });
    crate::debug::log("Creating msdos partition table with parted...");

    // Create a new partition table and partition using parted
    // First, create a new msdos partition table
    let output = Command::new("parted")
        .args(["-s", device_path, "mklabel", "msdos"])
        .output()
        .await
        .map_err(|e| format!("Failed to run parted: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        crate::debug::log(&format!("Parted mklabel failed: {}", stderr));
        return Err(format!("Failed to create partition table: {}", stderr));
    }
    crate::debug::log("Partition table created");

    let _ = progress_tx.send(FormatProgress::CreatingPartition);
    let _ = progress_tx.send(FormatProgress::Progress { percent: 40 });
    crate::debug::log("Creating primary partition...");

    // Create a primary partition spanning the entire disk
    let output = Command::new("parted")
        .args([
            "-s", device_path, "mkpart", "primary", "fat32", "1MiB", "100%",
        ])
        .output()
        .await
        .map_err(|e| format!("Failed to create partition: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        crate::debug::log(&format!("Parted mkpart failed: {}", stderr));
        return Err(format!("Failed to create partition: {}", stderr));
    }
    crate::debug::log("Primary partition created");

    let _ = progress_tx.send(FormatProgress::Progress { percent: 50 });

    // Set the partition as bootable
    crate::debug::log("Setting boot flag...");
    let _ = Command::new("parted")
        .args(["-s", device_path, "set", "1", "boot", "on"])
        .output()
        .await;

    // Wait for the kernel to recognize the new partition
    crate::debug::log("Running partprobe...");
    let _ = Command::new("partprobe")
        .args([device_path])
        .output()
        .await;

    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

    // Check for cancellation before format
    if cancel_token.is_cancelled() {
        let _ = progress_tx.send(FormatProgress::Cancelled);
        return Err("Format cancelled".to_string());
    }

    let _ = progress_tx.send(FormatProgress::Formatting);
    let _ = progress_tx.send(FormatProgress::Progress { percent: 60 });

    // Determine the partition path (e.g., /dev/sdb1 or /dev/mmcblk0p1)
    let partition_path = if device_path.contains("mmcblk") || device_path.contains("nvme") {
        format!("{}p1", device_path)
    } else {
        format!("{}1", device_path)
    };
    crate::debug::log(&format!("Partition path: {}", partition_path));

    // Format the partition as FAT32
    crate::debug::log("Running mkfs.vfat...");
    let output = Command::new("mkfs.vfat")
        .args(["-F", "32", "-n", volume_label, &partition_path])
        .output()
        .await
        .map_err(|e| format!("Failed to run mkfs.vfat: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        crate::debug::log(&format!("mkfs.vfat failed: {}", stderr));
        return Err(format!("Failed to format partition: {}", stderr));
    }

    let _ = progress_tx.send(FormatProgress::Progress { percent: 100 });
    crate::debug::log("Linux format operation completed successfully");
    let _ = progress_tx.send(FormatProgress::Completed);
    Ok(())
}

#[cfg(target_os = "linux")]
async fn unmount_linux_device(device_path: &str) -> Result<(), String> {
    // Read /proc/mounts to find all mount points for this device
    let mounts = std::fs::read_to_string("/proc/mounts")
        .map_err(|e| format!("Failed to read /proc/mounts: {}", e))?;

    let mut errors = Vec::new();
    let mut unmount_count = 0;

    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0].starts_with(device_path) {
            let mount_point = parts[1];
            crate::debug::log(&format!("Unmounting: {}", mount_point));

            match Command::new("umount")
                .args([mount_point])
                .output()
                .await
            {
                Ok(output) if output.status.success() => {
                    crate::debug::log(&format!("Successfully unmounted: {}", mount_point));
                    unmount_count += 1;
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let error_msg = format!("Failed to unmount {}: {}", mount_point, stderr.trim());
                    crate::debug::log(&error_msg);
                    errors.push(error_msg);
                }
                Err(e) => {
                    let error_msg = format!("Failed to run umount for {}: {}", mount_point, e);
                    crate::debug::log(&error_msg);
                    errors.push(error_msg);
                }
            }
        }
    }

    // Give the system time to complete unmounting
    if unmount_count > 0 {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    if !errors.is_empty() {
        crate::debug::log(&format!("Unmount had {} errors", errors.len()));
        // Return error if we failed to unmount anything
        Err(errors.join("; "))
    } else {
        crate::debug::log("All partitions unmounted successfully (or none were mounted)");
        Ok(())
    }
}

// =============================================================================
// macOS Implementation
// =============================================================================

#[cfg(target_os = "macos")]
pub async fn format_drive_fat32(
    device_path: &str,
    volume_label: &str,
    progress_tx: mpsc::UnboundedSender<FormatProgress>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    use tokio::time::{timeout, Duration, interval};

    crate::debug::log_section("macOS Format Operation");
    crate::debug::log(&format!("Device path: {}", device_path));
    crate::debug::log(&format!("Volume label: {}", volume_label));

    if cancel_token.is_cancelled() {
        let _ = progress_tx.send(FormatProgress::Cancelled);
        return Err("Format cancelled".to_string());
    }

    let _ = progress_tx.send(FormatProgress::Started);
    let _ = progress_tx.send(FormatProgress::Progress { percent: 0 });

    let disk_id = device_path
        .strip_prefix("/dev/")
        .unwrap_or(device_path);
    crate::debug::log(&format!("Disk ID: {}", disk_id));

    const MAX_ATTEMPTS: u32 = 3;
    /// Timeout for diskutil eraseDisk operation
    /// 5 minutes should be sufficient for most SD cards up to 512GB
    /// Larger cards or slower systems may need more time
    const TIMEOUT_SECS: u64 = 300;

    // Track the last error to provide better feedback to user
    let mut last_error = String::new();

    for attempt in 1..=MAX_ATTEMPTS {
        if attempt > 1 {
            let msg = format!("Formatting failed, attempting again [Attempt {}/{}]: {}", attempt, MAX_ATTEMPTS, last_error);
            crate::debug::log(&msg);
            let _ = progress_tx.send(FormatProgress::Error(msg.clone()));
            tokio::time::sleep(Duration::from_secs(2)).await;
            let _ = progress_tx.send(FormatProgress::Progress { percent: 0 });
        }

        crate::debug::log(&format!("Format attempt {} of {}", attempt, MAX_ATTEMPTS));

        if cancel_token.is_cancelled() {
            let _ = progress_tx.send(FormatProgress::Cancelled);
            return Err("Format cancelled".to_string());
        }

        let _ = progress_tx.send(FormatProgress::Unmounting);
        let _ = progress_tx.send(FormatProgress::Progress { percent: 5 });
        crate::debug::log("Unmounting disk...");

        let unmount_result = timeout(
            Duration::from_secs(30),
            Command::new("diskutil")
                .args(["unmountDisk", device_path])
                .output()
        ).await;

        match unmount_result {
            Ok(Ok(output)) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if !stderr.contains("was already unmounted") && !stderr.contains("not mounted") {
                        crate::debug::log(&format!("Unmount warning: {}", stderr));
                    }
                } else {
                    crate::debug::log("Disk unmounted successfully");
                }
            }
            Ok(Err(e)) => {
                last_error = format!("Unmount failed: {}", e);
                crate::debug::log(&last_error);
                if attempt == MAX_ATTEMPTS {
                    let final_error = format!("Formatting failed after {} attempts: {}", MAX_ATTEMPTS, last_error);
                    let _ = progress_tx.send(FormatProgress::Error(final_error.clone()));
                    return Err(final_error);
                }
                continue;
            }
            Err(_) => {
                last_error = "Unmount timed out".to_string();
                crate::debug::log(&last_error);
                if attempt == MAX_ATTEMPTS {
                    let final_error = format!("Formatting failed after {} attempts: {}", MAX_ATTEMPTS, last_error);
                    let _ = progress_tx.send(FormatProgress::Error(final_error.clone()));
                    return Err(final_error);
                }
                continue;
            }
        }

        let _ = progress_tx.send(FormatProgress::Progress { percent: 10 });

        if cancel_token.is_cancelled() {
            let _ = progress_tx.send(FormatProgress::Cancelled);
            return Err("Format cancelled".to_string());
        }

        let _ = progress_tx.send(FormatProgress::Formatting);
        let _ = progress_tx.send(FormatProgress::Progress { percent: 15 });
        crate::debug::log("Running diskutil eraseDisk...");
        crate::debug::log(&format!("Command: diskutil eraseDisk FAT32 {} MBRFormat {}", volume_label, device_path));

        let progress_tx_clone = progress_tx.clone();
        let progress_task = tokio::spawn(async move {
            let mut progress_interval = interval(Duration::from_secs(15));
            let mut current_percent = 20u8;
            
            loop {
                progress_interval.tick().await;
                if current_percent < 95 {
                    current_percent += 5;
                    let _ = progress_tx_clone.send(FormatProgress::Progress { percent: current_percent });
                }
            }
        });

        let format_result = timeout(
            Duration::from_secs(TIMEOUT_SECS),
            Command::new("diskutil")
                .args([
                    "eraseDisk",
                    "FAT32",
                    volume_label,
                    "MBRFormat",
                    device_path,
                ])
                .output()
        ).await;

        progress_task.abort();

        match format_result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                crate::debug::log(&format!("diskutil stdout: {}", stdout));
                if !stderr.is_empty() {
                    crate::debug::log(&format!("diskutil stderr: {}", stderr));
                }

                if output.status.success() {
                    let _ = progress_tx.send(FormatProgress::Progress { percent: 100 });
                    crate::debug::log("macOS format operation completed successfully");
                    let _ = progress_tx.send(FormatProgress::Completed);
                    return Ok(());
                } else {
                    last_error = format!("diskutil eraseDisk failed with status code {}: {}",
                        output.status.code().unwrap_or(-1),
                        stderr.trim());
                    crate::debug::log(&format!("Format attempt {} failed: {}", attempt, last_error));
                    if attempt == MAX_ATTEMPTS {
                        let final_error = format!("Formatting failed after {} attempts: {}", MAX_ATTEMPTS, last_error);
                        let _ = progress_tx.send(FormatProgress::Error(final_error.clone()));
                        return Err(final_error);
                    }
                }
            }
            Ok(Err(e)) => {
                last_error = format!("Failed to execute diskutil: {}", e);
                crate::debug::log(&format!("Format attempt {} failed: {}", attempt, last_error));
                if attempt == MAX_ATTEMPTS {
                    let final_error = format!("Formatting failed after {} attempts: {}", MAX_ATTEMPTS, last_error);
                    let _ = progress_tx.send(FormatProgress::Error(final_error.clone()));
                    return Err(final_error);
                }
            }
            Err(_) => {
                last_error = format!("diskutil timed out after {} seconds", TIMEOUT_SECS);
                crate::debug::log(&format!("Format attempt {} timed out", attempt));
                if attempt == MAX_ATTEMPTS {
                    let final_error = format!("Formatting failed after {} attempts: {}", MAX_ATTEMPTS, last_error);
                    let _ = progress_tx.send(FormatProgress::Error(final_error.clone()));
                    return Err(final_error);
                }
            }
        }
    }

    // If we somehow exit the loop without returning, use the last error
    let final_error = if last_error.is_empty() {
        "Formatting failed after all attempts, please check your SD Card".to_string()
    } else {
        format!("Formatting failed: {}", last_error)
    };
    let _ = progress_tx.send(FormatProgress::Error(final_error.clone()));
    Err(final_error)
}

// =============================================================================
// Fallback for other platforms
// =============================================================================

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub async fn format_drive_fat32(
    _device_path: &str,
    _volume_label: &str,
    progress_tx: mpsc::UnboundedSender<FormatProgress>,
    _cancel_token: CancellationToken,
) -> Result<(), String> {
    let _ = progress_tx.send(FormatProgress::Error(
        "Formatting not supported on this platform".to_string(),
    ));
    Err("Formatting not supported on this platform".to_string())
}

