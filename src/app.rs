use crate::config::{
    setup_theme, APP_NAME, ASSET_EXTENSION, COLOR_ACCENT, COLOR_ACCENT_DIM, COLOR_BG_DARK,
    COLOR_BG_LIGHT, COLOR_ERROR, COLOR_SPINNER, COLOR_SUCCESS, COLOR_TEXT, COLOR_WARNING,
    DEFAULT_REPO_INDEX, REPO_OPTIONS, TEMP_PREFIX,
};
use crate::burn::{burn_image, BurnProgress};
use crate::drives::{get_removable_drives, DriveInfo};
use crate::eject::eject_drive;
use crate::extract::{extract_zip_and_find_img, ExtractProgress};
use crate::github::{download_asset, find_release_asset, get_latest_release, DownloadProgress, Release};
use eframe::egui;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, PartialEq)]
enum AppState {
    Idle,
    AwaitingConfirmation,
    FetchingRelease,
    Downloading,
    Extracting,
    Burning,  // Replaces Formatting + Copying - burns raw disk image
    Complete,
    Ejecting,
    Ejected,
    Cancelling,
    Error,
}

#[derive(Debug, Clone)]
struct ProgressInfo {
    current: u64,
    total: u64,
    message: String,
}

#[derive(Debug, Clone)]
struct StateUpdate {
    new_state: Option<AppState>,
}

pub struct InstallerApp {
    // Runtime for async operations
    runtime: Runtime,

    // UI State
    drives: Vec<DriveInfo>,
    selected_drive_idx: Option<usize>,
    selected_repo_idx: usize,
    release_info: Option<Release>,

    // Progress tracking
    state: AppState,
    progress: Arc<Mutex<ProgressInfo>>,
    log_messages: Arc<Mutex<Vec<String>>>,
    state_update: Arc<Mutex<StateUpdate>>,

    // Temp file for downloads
    temp_download_path: Option<PathBuf>,

    // Drive that was installed to (for eject)
    installed_drive: Option<DriveInfo>,

    // Cancellation token for aborting installation
    cancel_token: Option<CancellationToken>,
}

impl InstallerApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Apply theme from config
        setup_theme(&cc.egui_ctx);

        let runtime = Runtime::new().expect("Failed to create Tokio runtime");

        let mut app = Self {
            runtime,
            drives: Vec::new(),
            selected_drive_idx: None,
            selected_repo_idx: DEFAULT_REPO_INDEX,
            release_info: None,
            state: AppState::Idle,
            progress: Arc::new(Mutex::new(ProgressInfo {
                current: 0,
                total: 100,
                message: String::new(),
            })),
            log_messages: Arc::new(Mutex::new(Vec::new())),
            state_update: Arc::new(Mutex::new(StateUpdate { new_state: None })),
            temp_download_path: None,
            installed_drive: None,
            cancel_token: None,
        };

        app.refresh_drives();
        app
    }

    fn refresh_drives(&mut self) {
        self.drives = get_removable_drives();
        if !self.drives.is_empty() && self.selected_drive_idx.is_none() {
            self.selected_drive_idx = Some(0);
        }
        if let Some(idx) = self.selected_drive_idx {
            if idx >= self.drives.len() {
                self.selected_drive_idx = if self.drives.is_empty() {
                    None
                } else {
                    Some(0)
                };
            }
        }
    }

    fn log(&self, msg: &str) {
        if let Ok(mut logs) = self.log_messages.lock() {
            logs.push(msg.to_string());
            // Keep only last 100 messages
            if logs.len() > 100 {
                logs.remove(0);
            }
        }
    }

    fn cancel_installation(&mut self) {
        if let Some(token) = &self.cancel_token {
            self.log("Cancelling installation...");
            token.cancel();
            self.state = AppState::Cancelling;
        }
    }

    fn start_installation(&mut self, ctx: egui::Context) {
        let Some(drive_idx) = self.selected_drive_idx else {
            self.log("No drive selected");
            self.state = AppState::Idle;
            return;
        };

        let Some(drive) = self.drives.get(drive_idx).cloned() else {
            self.log("Invalid drive selection");
            self.state = AppState::Idle;
            return;
        };

        // Store the drive for later ejection
        self.installed_drive = Some(drive.clone());

        self.state = AppState::FetchingRelease;
        let (repo_name, repo_url) = REPO_OPTIONS[self.selected_repo_idx];
        self.log(&format!(
            "Starting installation to {} using {}",
            drive.name, repo_name
        ));

        // Log installation start to debug log
        crate::debug::log_section("Installation Started");
        crate::debug::log(&format!("Drive: {} ({})", drive.name, drive.device_path));
        crate::debug::log(&format!("Drive size: {} bytes", drive.size_bytes));
        crate::debug::log(&format!("Mount path: {:?}", drive.mount_path));
        crate::debug::log(&format!("Repository: {} ({})", repo_name, repo_url));

        let repo_url = repo_url.to_string();
        let progress = self.progress.clone();
        let log_messages = self.log_messages.clone();
        let state_update = self.state_update.clone();
        let ctx_clone = ctx.clone();

        // Create cancellation token
        let cancel_token = CancellationToken::new();
        self.cancel_token = Some(cancel_token.clone());

        // Channel for state updates
        let (state_tx, mut state_rx) = mpsc::unbounded_channel::<AppState>();

        // Clone values for the async block
        let state_tx_clone = state_tx.clone();
        let cancel_token_clone = cancel_token.clone();

        // Spawn the installation task
        self.runtime.spawn(async move {
            let log = |msg: &str| {
                if let Ok(mut logs) = log_messages.lock() {
                    logs.push(msg.to_string());
                }
                ctx_clone.request_repaint();
            };

            let set_progress = |current: u64, total: u64, message: &str| {
                if let Ok(mut p) = progress.lock() {
                    p.current = current;
                    p.total = total;
                    p.message = message.to_string();
                }
                ctx_clone.request_repaint();
            };

            // Step 1: Fetch release
            log("Fetching latest release from GitHub...");
            crate::debug::log_section("Fetching Release");
            crate::debug::log(&format!("Repository URL: {}", repo_url));
            set_progress(0, 100, "Fetching release info...");

            let release = match get_latest_release(&repo_url).await {
                Ok(r) => r,
                Err(e) => {
                    log(&format!("Error: {}", e));
                    crate::debug::log(&format!("ERROR fetching release: {}", e));
                    let _ = state_tx_clone.send(AppState::Error);
                    return;
                }
            };

            let asset = match find_release_asset(&release) {
                Some(a) => a,
                None => {
                    log(&format!("Error: No {} file found in release", ASSET_EXTENSION));
                    crate::debug::log(&format!("ERROR: No {} asset found in release", ASSET_EXTENSION));
                    let _ = state_tx_clone.send(AppState::Error);
                    return;
                }
            };

            log(&format!(
                "Found release: {} ({})",
                release.tag_name, asset.name
            ));
            crate::debug::log(&format!("Release: {}", release.tag_name));
            crate::debug::log(&format!("Asset: {} ({} bytes)", asset.name, asset.size));

            // Step 2: Download
            // Define temp/cache directory for downloads and extraction
            // On Linux/macOS, use cache dir to avoid temp space issues
            // Linux: ~/.cache, macOS: ~/Library/Caches
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let temp_dir = dirs::cache_dir().unwrap_or_else(std::env::temp_dir);
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let temp_dir = std::env::temp_dir();

            // Step 2: Download (we download first, then burn the image directly to disk)
            let _ = state_tx_clone.send(AppState::Downloading);
            log("Downloading release...");
            crate::debug::log_section("Downloading Release");

            let download_path = temp_dir.join(&asset.name);
            crate::debug::log(&format!("Download path: {:?}", download_path));

            let (dl_tx, mut dl_rx) = mpsc::unbounded_channel::<DownloadProgress>();

            let download_path_clone = download_path.clone();
            let asset_clone = asset.clone();
            let progress_clone = progress.clone();
            let ctx_dl = ctx_clone.clone();

            // Spawn download progress handler
            let dl_handle = tokio::spawn(async move {
                while let Some(prog) = dl_rx.recv().await {
                    match prog {
                        DownloadProgress::Started { total_bytes } => {
                            if let Ok(mut p) = progress_clone.lock() {
                                p.total = total_bytes;
                                p.current = 0;
                                p.message = "Downloading...".to_string();
                            }
                        }
                        DownloadProgress::Progress { downloaded, total } => {
                            if let Ok(mut p) = progress_clone.lock() {
                                p.current = downloaded;
                                p.total = total;
                                let pct = (downloaded as f64 / total as f64 * 100.0) as u32;
                                p.message = format!("Downloading... {}%", pct);
                            }
                        }
                        DownloadProgress::Completed => {
                            if let Ok(mut p) = progress_clone.lock() {
                                p.message = "Download complete".to_string();
                            }
                        }
                        DownloadProgress::Cancelled => {
                            if let Ok(mut p) = progress_clone.lock() {
                                p.message = "Download cancelled".to_string();
                            }
                        }
                        DownloadProgress::Error(e) => {
                            if let Ok(mut p) = progress_clone.lock() {
                                p.message = format!("Download error: {}", e);
                            }
                        }
                    }
                    ctx_dl.request_repaint();
                }
            });

            if let Err(e) = download_asset(&asset_clone, &download_path_clone, dl_tx, cancel_token_clone.clone()).await {
                if e.contains("cancelled") {
                    log("Download cancelled");
                    let _ = state_tx_clone.send(AppState::Idle);
                    return;
                }
                log(&format!("Download error: {}", e));
                let _ = state_tx_clone.send(AppState::Error);
                return;
            }

            let _ = dl_handle.await;
            log("Download complete");
            crate::debug::log("Download complete");

            // Step 3: Extract ZIP and find .img file
            // On Linux/macOS, use cache dir to avoid temp space issues
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let extract_base_dir = dirs::cache_dir().unwrap_or_else(|| temp_dir.clone());
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let extract_base_dir = temp_dir.clone();

            let _ = state_tx_clone.send(AppState::Extracting);
            let temp_extract_dir = extract_base_dir.join(format!("{}_extract", TEMP_PREFIX));
            log("Extracting ZIP and finding disk image...");
            crate::debug::log_section("Extracting Image");
            crate::debug::log(&format!("Temp extract dir: {:?}", temp_extract_dir));
            set_progress(0, 100, "Extracting image...");

            // Clean up any previous extraction
            let _ = std::fs::remove_dir_all(&temp_extract_dir);
            if let Err(e) = std::fs::create_dir_all(&temp_extract_dir) {
                let error_msg = format!("Failed to create temp extract dir: {}", e);
                crate::debug::log(&error_msg);
                log(&error_msg);
                let _ = state_tx_clone.send(AppState::Error);
                return;
            }

            let (ext_tx, mut ext_rx) = mpsc::unbounded_channel::<ExtractProgress>();
            let progress_ext = progress.clone();
            let ctx_ext = ctx_clone.clone();

            // Spawn extract progress handler
            let ext_handle = tokio::spawn(async move {
                while let Some(prog) = ext_rx.recv().await {
                    if let Ok(mut p) = progress_ext.lock() {
                        match prog {
                            ExtractProgress::Started => {
                                p.message = "Starting extraction...".to_string();
                            }
                            ExtractProgress::Extracting => {
                                p.message = "Extracting files...".to_string();
                            }
                            ExtractProgress::Progress { percent } => {
                                p.current = percent as u64;
                                p.total = 100;
                                p.message = format!("Extracting... {}%", percent);
                            }
                            ExtractProgress::Completed => {
                                p.current = 100;
                                p.total = 100;
                                p.message = "Extraction complete".to_string();
                            }
                            ExtractProgress::Cancelled => {
                                p.message = "Extraction cancelled".to_string();
                            }
                            ExtractProgress::Error(e) => {
                                p.message = format!("Extract error: {}", e);
                            }
                        }
                    }
                    ctx_ext.request_repaint();
                }
            });

            crate::debug::log(&format!("Extracting ZIP: {:?} -> {:?}", download_path, temp_extract_dir));

            let img_path = match extract_zip_and_find_img(&download_path, &temp_extract_dir, ext_tx, cancel_token_clone.clone()).await {
                Ok(path) => path,
                Err(e) => {
                    if e.contains("cancelled") {
                        log("Extraction cancelled");
                        let _ = std::fs::remove_dir_all(&temp_extract_dir);
                        let _ = state_tx_clone.send(AppState::Idle);
                        return;
                    }
                    log(&format!("Extract error: {}", e));
                    let _ = std::fs::remove_dir_all(&temp_extract_dir);
                    let _ = state_tx_clone.send(AppState::Error);
                    return;
                }
            };

            let _ = ext_handle.await;
            log(&format!("Found disk image: {}", img_path.display()));
            crate::debug::log(&format!("Image file: {:?}", img_path));

            // Step 4: Burn disk image to SD card
            let _ = state_tx_clone.send(AppState::Burning);
            log("Burning disk image to SD card...");
            crate::debug::log_section("Burning Disk Image");
            set_progress(0, 100, "Burning disk image...");

            let (burn_tx, mut burn_rx) = mpsc::unbounded_channel::<BurnProgress>();
            let progress_burn = progress.clone();
            let ctx_burn = ctx_clone.clone();

            // Spawn burn progress handler
            let burn_handle = tokio::spawn(async move {
                while let Some(prog) = burn_rx.recv().await {
                    if let Ok(mut p) = progress_burn.lock() {
                        match prog {
                            BurnProgress::Started => {
                                p.message = "Starting burn...".to_string();
                            }
                            BurnProgress::Burning => {
                                p.message = "Burning disk image...".to_string();
                            }
                            BurnProgress::Progress { bytes_written, total_bytes } => {
                                p.current = bytes_written;
                                p.total = total_bytes;
                                let pct = if total_bytes > 0 {
                                    (bytes_written as f64 / total_bytes as f64 * 100.0) as u32
                                } else {
                                    0
                                };
                                p.message = format!("Burning... {}%", pct);
                            }
                            BurnProgress::Verifying => {
                                p.message = "Verifying...".to_string();
                            }
                            BurnProgress::Completed => {
                                p.current = p.total;
                                p.message = "Burn complete".to_string();
                            }
                            BurnProgress::Cancelled => {
                                p.message = "Burn cancelled".to_string();
                            }
                            BurnProgress::Error(e) => {
                                p.message = format!("Burn error: {}", e);
                            }
                        }
                    }
                    ctx_burn.request_repaint();
                }
            });

            write_card_log(&format!(
                "Burning image: {:?} -> {}",
                img_path, drive.device_path
            ));

            if let Err(e) = burn_image(&img_path, &drive.device_path, burn_tx, cancel_token_clone.clone()).await {
                if e.contains("cancelled") {
                    write_card_log("Burn cancelled");
                    log("Burn cancelled");
                    let _ = std::fs::remove_dir_all(&temp_extract_dir);
                    let _ = state_tx_clone.send(AppState::Idle);
                    return;
                }
                write_card_log(&format!("Burn error: {}", e));
                log(&format!("Burn error: {}", e));
                let _ = std::fs::remove_dir_all(&temp_extract_dir);
                let _ = state_tx_clone.send(AppState::Error);
                return;
            }

            let _ = burn_handle.await;
            log("Burn complete");
            write_card_log("Burn complete");
            crate::debug::log("Burn complete");

            // Clean up temp extraction folder
            let _ = std::fs::remove_dir_all(&temp_extract_dir);
            crate::debug::log("Cleaned up temp extraction folder");

            // Cleanup temp file
            let _ = tokio::fs::remove_file(&download_path).await;
            write_card_log("Cleaned up temp download file");
            crate::debug::log("Cleaned up temp download file");

            log("Burn complete! You can now safely eject the SD card.");
            write_card_log("Burn complete!");
            crate::debug::log("Burn complete!");
            let _ = state_tx_clone.send(AppState::Complete);
        });

        // Spawn a task to update state from the channel
        let state_update_clone = state_update.clone();
        let ctx_state = ctx.clone();
        self.runtime.spawn(async move {
            while let Some(new_state) = state_rx.recv().await {
                // Update the state_update field which will be checked by the UI
                if let Ok(mut update) = state_update_clone.lock() {
                    update.new_state = Some(new_state);
                }
                ctx_state.request_repaint();
            }
        });
    }
}

impl eframe::App for InstallerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check for state updates from async eject on Windows
        if let Ok(mut progress) = self.progress.lock() {
            if progress.message.starts_with("EJECT_") {
                if progress.message == "EJECT_SUCCESS" {
                    self.log("SD card safely ejected. You may now remove it.");
                    self.state = AppState::Ejected;
                } else if let Some(error_msg) = progress.message.strip_prefix("EJECT_ERROR: ") {
                    self.log(&format!("Eject warning: {}. The card should still be safe to remove.", error_msg));
                    self.state = AppState::Ejected;
                }
                progress.message.clear(); // Consume the message
            }
        }

        // Check for state updates from main installation process
        // This uses a separate state update mechanism to avoid race conditions
        if let Ok(mut update) = self.state_update.lock() {
            if let Some(new_state) = update.new_state.take() {
                match new_state {
                    AppState::Complete => {
                        self.state = AppState::Complete;
                        self.cancel_token = None;
                    }
                    AppState::Error => {
                        self.state = AppState::Error;
                        self.cancel_token = None;
                    }
                    AppState::Idle => {
                        // Idle state means cancelled
                        self.state = AppState::Idle;
                        self.cancel_token = None;
                    }
                    _ => {
                        self.state = new_state;
                    }
                }
            }
        }


        // Keep requesting repaints while busy so UI stays responsive
        let is_busy = matches!(
            self.state,
            AppState::FetchingRelease
                | AppState::Downloading
                | AppState::Extracting
                | AppState::Burning
                | AppState::Ejecting
                | AppState::Cancelling
        );
        if is_busy {
            ctx.request_repaint();
        }

        // Show confirmation dialog if awaiting confirmation
        if self.state == AppState::AwaitingConfirmation {
            let window_frame = egui::Frame::window(&ctx.style())
                .fill(COLOR_BG_DARK)
                .stroke(egui::Stroke::new(1.0, COLOR_ACCENT_DIM));

            let selected_repo_name = REPO_OPTIONS[self.selected_repo_idx].0;
            egui::Window::new(format!("Confirm {} Installation", selected_repo_name))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .frame(window_frame)
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(10.0);
                        ui.colored_label(COLOR_WARNING, "WARNING");
                        ui.add_space(10.0);

                        ui.label("This will DELETE ALL DATA on the selected drive:");
                        ui.add_space(5.0);

                        if let Some(idx) = self.selected_drive_idx {
                            if let Some(drive) = self.drives.get(idx) {
                                ui.colored_label(COLOR_ACCENT, drive.display_name());
                            }
                        }

                        ui.add_space(10.0);
                        ui.label("Are you sure you want to continue?");
                        ui.add_space(15.0);

                        ui.horizontal(|ui| {
                            if ui.button("Cancel").clicked() {
                                self.state = AppState::Idle;
                            }

                            ui.add_space(20.0);

                            if ui
                                .add(egui::Button::new(format!("Yes, Install {}", selected_repo_name)).fill(COLOR_ERROR))
                                .clicked()
                            {
                                self.start_installation(ctx.clone());
                            }
                        });

                        ui.add_space(10.0);
                    });
                });
        }

        let panel_frame = egui::Frame::central_panel(&ctx.style()).fill(COLOR_BG_DARK);

        egui::CentralPanel::default()
            .frame(panel_frame)
            .show(ctx, |ui| {
                ui.heading(
                    egui::RichText::new(format!("{} Installer", APP_NAME)).color(COLOR_ACCENT),
                );
                ui.add_space(10.0);

                // Drive selection
                ui.horizontal(|ui| {
                    ui.label("Target Drive:");

                    let selected_text = self
                        .selected_drive_idx
                        .and_then(|idx| self.drives.get(idx))
                        .map(|d| d.display_name())
                        .unwrap_or_else(|| "No drives found".to_string());

                    egui::ComboBox::from_id_salt("drive_select")
                        .selected_text(&selected_text)
                        .show_ui(ui, |ui| {
                            for (idx, drive) in self.drives.iter().enumerate() {
                                ui.selectable_value(
                                    &mut self.selected_drive_idx,
                                    Some(idx),
                                    drive.display_name(),
                                );
                            }
                        });

                    if ui.button("Refresh").clicked() {
                        self.refresh_drives();
                    }
                });

                ui.add_space(10.0);

                // Repository selection
                ui.horizontal(|ui| {
                    ui.label("Release Channel:");

                    let selected_repo_name = REPO_OPTIONS[self.selected_repo_idx].0;

                    egui::ComboBox::from_id_salt("repo_select")
                        .selected_text(selected_repo_name)
                        .show_ui(ui, |ui| {
                            for (idx, (name, _url)) in REPO_OPTIONS.iter().enumerate() {
                                ui.selectable_value(&mut self.selected_repo_idx, idx, *name);
                            }
                        });
                });

                ui.add_space(10.0);

                // Install button
                let is_busy = matches!(
                    self.state,
                    AppState::FetchingRelease
                        | AppState::Downloading
                        | AppState::Extracting
                        | AppState::Burning
                        | AppState::AwaitingConfirmation
                        | AppState::Ejecting
                        | AppState::Cancelling
                );

                ui.add_enabled_ui(!is_busy && self.selected_drive_idx.is_some(), |ui| {
                    let selected_repo_name = REPO_OPTIONS[self.selected_repo_idx].0;
                    if ui.button(format!("Install {}", selected_repo_name)).clicked() {
                        self.state = AppState::AwaitingConfirmation;
                    }
                });

                ui.add_space(10.0);

                // Progress bar
                let show_progress = matches!(
                    self.state,
                    AppState::FetchingRelease
                        | AppState::Downloading
                        | AppState::Extracting
                        | AppState::Burning
                        | AppState::Cancelling
                );

                if show_progress {
                    let (current, total, message) = {
                        match self.progress.lock() {
                            Ok(p) => (p.current, p.total, p.message.clone()),
                            Err(_) => (0, 100, String::from("Progress unavailable")),
                        }
                    };

                    // Only FetchingRelease has indeterminate progress
                    // Downloading, Formatting, and Extracting now report percentages
                    let is_indeterminate = matches!(
                        self.state,
                        AppState::FetchingRelease
                    );

                    if is_indeterminate {
                        // Animated indeterminate progress bar
                        let time = ctx.input(|i| i.time);

                        // Allocate space for the progress bar
                        let desired_size = egui::vec2(ui.available_width(), 20.0);
                        let (rect, _response) =
                            ui.allocate_exact_size(desired_size, egui::Sense::hover());

                        if ui.is_rect_visible(rect) {
                            let painter = ui.painter();

                            // Background
                            painter.rect_filled(rect, 4.0, COLOR_BG_LIGHT);

                            // Animated highlight - moves back and forth
                            let cycle = (time * 0.8).sin() * 0.5 + 0.5; // 0.0 to 1.0
                            let bar_width = rect.width() * 0.3;
                            let bar_x = rect.left() + (rect.width() - bar_width) * cycle as f32;

                            let highlight_rect = egui::Rect::from_min_size(
                                egui::pos2(bar_x, rect.top()),
                                egui::vec2(bar_width, rect.height()),
                            );

                            painter.rect_filled(highlight_rect, 4.0, COLOR_ACCENT);
                        }
                    } else {
                        // Normal progress bar for downloading, formatting, extracting, and copying
                        let progress = if total > 0 {
                            current as f32 / total as f32
                        } else {
                            0.0
                        };

                        ui.add(
                            egui::ProgressBar::new(progress)
                                .fill(COLOR_ACCENT),
                        );
                    }

                    ui.add_space(5.0);
                    ui.colored_label(COLOR_TEXT, &message);

                    // Cancel button (only show during cancellable operations)
                    let can_cancel = matches!(
                        self.state,
                        AppState::FetchingRelease
                            | AppState::Downloading
                            | AppState::Extracting
                            | AppState::Burning
                    ) && self.cancel_token.is_some();

                    if can_cancel {
                        ui.add_space(10.0);
                        if ui.button("Cancel").clicked() {
                            self.cancel_installation();
                        }
                    }

                    // Show cancelling message
                    if self.state == AppState::Cancelling {
                        ui.add_space(5.0);
                        ui.colored_label(COLOR_WARNING, "Cancelling...");
                    }
                }

                // Status
                match self.state {
                    AppState::Complete => {
                        let selected_repo_name = REPO_OPTIONS[self.selected_repo_idx].0;
                        ui.colored_label(COLOR_SUCCESS, format!("{} installation complete!", selected_repo_name));
                        ui.add_space(5.0);
                        if ui.button("Safely Eject SD Card").clicked() {
                            if let Some(drive) = self.installed_drive.clone() {
                                // Run eject in background task so UI stays responsive
                                self.state = AppState::Ejecting;
                                self.log("Ejecting SD card...");

                                let progress = self.progress.clone();
                                let ctx_clone = ctx.clone();

                                self.runtime.spawn(async move {
                                    let result = tokio::task::spawn_blocking(move || {
                                        eject_drive(&drive)
                                    }).await.unwrap();

                                    if let Ok(mut progress) = progress.lock() {
                                        match result {
                                            Ok(()) => progress.message = "EJECT_SUCCESS".to_string(),
                                            Err(e) => progress.message = format!("EJECT_ERROR: {}", e),
                                        }
                                    }
                                    ctx_clone.request_repaint();
                                });
                            }
                        }
                    }
                    AppState::Ejecting => {
                        let selected_repo_name = REPO_OPTIONS[self.selected_repo_idx].0;
                        ui.colored_label(COLOR_SUCCESS, format!("{} installation complete!", selected_repo_name));
                        ui.add_space(5.0);
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new().color(COLOR_SPINNER));
                            ui.label(" Ejecting SD card...");
                        });
                    }
                    AppState::Ejected => {
                        ui.colored_label(COLOR_SUCCESS, "SD card ejected! You may safely remove it.");
                    }
                    AppState::Error => {
                        let selected_repo_name = REPO_OPTIONS[self.selected_repo_idx].0;
                        ui.colored_label(COLOR_ERROR, format!("{} installation failed. See log for details.", selected_repo_name));
                    }
                    _ => {}
                }

                ui.add_space(10.0);

                // Log area
                ui.separator();
                ui.label("Log:");

                egui::ScrollArea::vertical()
                    .max_height(150.0)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        if let Ok(logs) = self.log_messages.lock() {
                            for msg in logs.iter() {
                                ui.colored_label(COLOR_TEXT, msg);
                            }
                        }
                    });
            });
    }
}