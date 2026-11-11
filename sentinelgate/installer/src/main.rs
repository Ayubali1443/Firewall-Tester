#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::env;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MB_OK: u32 = 0x0000_0000;
const MB_YESNO: u32 = 0x0000_0004;
const MB_ICONINFORMATION: u32 = 0x0000_0040;
const MB_ICONQUESTION: u32 = 0x0000_0020;
const MB_ICONERROR: u32 = 0x0000_0010;
const IDYES: i32 = 6;

const HKEY_CURRENT_USER: isize = -2147483647i32 as isize;
const KEY_WRITE: u32 = 0x0002_0006;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;
const ERROR_SUCCESS: i32 = 0;

const DEFAULT_UNINSTALL_SUBKEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelGateAI";

// Embedded compiled SentinelGateAI.exe (contains Python runtime, UI, Rust cf_validator, Rust sg_seal.dll)
static PAYLOAD_EXE: &[u8] = include_bytes!(env!("SG_PAYLOAD_EXE"));

#[link(name = "user32")]
extern "system" {
    fn MessageBoxW(hwnd: isize, text: *const u16, caption: *const u16, utype: u32) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    fn RegCreateKeyExW(
        hkey: isize,
        lp_sub_key: *const u16,
        reserved: u32,
        lp_class: *const u16,
        dw_options: u32,
        sam_desired: u32,
        lp_security_attributes: *const std::ffi::c_void,
        phk_result: *mut isize,
        lpdw_disposition: *mut u32,
    ) -> i32;

    fn RegSetValueExW(
        hkey: isize,
        lp_value_name: *const u16,
        reserved: u32,
        dw_type: u32,
        lp_data: *const u8,
        cb_data: u32,
    ) -> i32;

    fn RegDeleteTreeW(hkey: isize, lp_sub_key: *const u16) -> i32;
    fn RegCloseKey(hkey: isize) -> i32;
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn show_msg(title: &str, body: &str, flags: u32, silent: bool) -> i32 {
    if silent {
        return IDYES;
    }
    let t = to_wide(title);
    let b = to_wide(body);
    unsafe { MessageBoxW(0, b.as_ptr(), t.as_ptr(), flags) }
}

fn run_ps_hidden(script: &str) -> bool {
    Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn stop_running_app() {
    let _ = Command::new("taskkill")
        .args(["/F", "/IM", "SentinelGateAI.exe"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn has_webview2() -> bool {
    let script = r#"
$k1 = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
$k2 = 'HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
$k3 = 'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
if ((Test-Path $k1) -or (Test-Path $k2) -or (Test-Path $k3)) { exit 0 } else { exit 1 }
"#;
    run_ps_hidden(script)
}

fn ensure_webview2(silent: bool) {
    if has_webview2() {
        return;
    }
    if !silent {
        show_msg(
            "SentinelGate AI Setup",
            "Microsoft Edge WebView2 Runtime was not detected. Setup will attempt to install it automatically.",
            MB_OK | MB_ICONINFORMATION,
            silent,
        );
    }
    let install_script = r#"
$tmp = Join-Path $env:TEMP 'MicrosoftEdgeWebview2Setup.exe'
try {
    Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile $tmp -UseBasicParsing
    Start-Process -FilePath $tmp -ArgumentList '/silent /install' -Wait
} catch {}
"#;
    let _ = run_ps_hidden(install_script);
}

fn ps_escape(p: &Path) -> String {
    p.to_string_lossy().replace('\'', "''")
}

fn create_shortcut(target_exe: &Path, shortcut_path: &Path, arguments: &str, desc: &str) {
    if let Some(parent) = shortcut_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let target_str = ps_escape(target_exe);
    let work_str = target_exe.parent().map(ps_escape).unwrap_or_default();
    let lnk_str = ps_escape(shortcut_path);
    let args_str = arguments.replace('\'', "''");
    let desc_str = desc.replace('\'', "''");

    let script = format!(
        "$ws = New-Object -ComObject WScript.Shell; \
         $s = $ws.CreateShortcut('{lnk_str}'); \
         $s.TargetPath = '{target_str}'; \
         $s.Arguments = '{args_str}'; \
         $s.WorkingDirectory = '{work_str}'; \
         $s.Description = '{desc_str}'; \
         $s.Save()"
    );
    let _ = run_ps_hidden(&script);
}

fn reg_set_sz(hkey: isize, name: &str, value: &str) {
    let name_w = to_wide(name);
    let val_w = to_wide(value);
    let byte_len = (val_w.len() * std::mem::size_of::<u16>()) as u32;
    unsafe {
        RegSetValueExW(
            hkey,
            name_w.as_ptr(),
            0,
            REG_SZ,
            val_w.as_ptr() as *const u8,
            byte_len,
        );
    }
}

fn reg_set_dword(hkey: isize, name: &str, value: u32) {
    let name_w = to_wide(name);
    let bytes = value.to_le_bytes();
    unsafe {
        RegSetValueExW(
            hkey,
            name_w.as_ptr(),
            0,
            REG_DWORD,
            bytes.as_ptr(),
            bytes.len() as u32,
        );
    }
}

fn register_app_metadata(
    install_dir: &Path,
    exe_path: &Path,
    uninstall_exe: &Path,
    reg_subkey: &str,
) {
    let subkey_w = to_wide(reg_subkey);
    let mut hkey: isize = 0;
    unsafe {
        let _ = RegDeleteTreeW(HKEY_CURRENT_USER, subkey_w.as_ptr());
        let status = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey_w.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_WRITE,
            std::ptr::null(),
            &mut hkey,
            std::ptr::null_mut(),
        );
        if status != ERROR_SUCCESS || hkey == 0 {
            return;
        }
    }

    let install_str = install_dir.to_string_lossy().into_owned();
    let exe_str = exe_path.to_string_lossy().into_owned();
    let uninst_str = uninstall_exe.to_string_lossy().into_owned();
    let uninst_cmd = format!("\"{}\" --uninstall", uninst_str);
    let quiet_uninst_cmd = format!("\"{}\" --uninstall --silent", uninst_str);
    let est_kb = ((PAYLOAD_EXE.len().saturating_add(1023)) / 1024).max(1) as u32;

    reg_set_sz(hkey, "DisplayName", "SentinelGate AI");
    reg_set_sz(hkey, "DisplayVersion", "2.0.0");
    reg_set_sz(hkey, "Publisher", "SentinelGate Security");
    reg_set_sz(hkey, "InstallLocation", &install_str);
    reg_set_sz(hkey, "DisplayIcon", &exe_str);
    reg_set_sz(hkey, "UninstallString", &uninst_cmd);
    reg_set_sz(hkey, "QuietUninstallString", &quiet_uninst_cmd);
    reg_set_dword(hkey, "EstimatedSize", est_kb);
    reg_set_dword(hkey, "NoModify", 1);
    reg_set_dword(hkey, "NoRepair", 1);

    unsafe {
        let _ = RegCloseKey(hkey);
    }
}

fn remove_shortcuts() {
    if let Ok(appdata) = env::var("APPDATA") {
        let start_dir = PathBuf::from(appdata)
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs");
        let _ = fs::remove_file(start_dir.join("SentinelGate AI.lnk"));
        let _ = fs::remove_file(start_dir.join("Uninstall SentinelGate AI.lnk"));
    }
    if let Ok(userprofile) = env::var("USERPROFILE") {
        let desktop_lnk = PathBuf::from(userprofile).join("Desktop").join("SentinelGate AI.lnk");
        let _ = fs::remove_file(desktop_lnk);
    }
}

fn remove_registry_entry(reg_subkey: &str) {
    let subkey_w = to_wide(reg_subkey);
    unsafe {
        let _ = RegDeleteTreeW(HKEY_CURRENT_USER, subkey_w.as_ptr());
    }
}

fn default_install_dir() -> PathBuf {
    let local_app = env::var("LOCALAPPDATA").unwrap_or_else(|_| {
        let profile = env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".to_string());
        format!("{}\\AppData\\Local", profile)
    });
    PathBuf::from(local_app)
        .join("Programs")
        .join("SentinelGateAI")
}

fn run_uninstall(
    install_dir: &Path,
    no_shortcuts: bool,
    silent: bool,
    custom_reg_key: Option<&str>,
) {
    if !silent {
        let choice = show_msg(
            "Uninstall SentinelGate AI",
            &format!(
                "Are you sure you want to completely uninstall SentinelGate AI from:\n{}\n\nThis removes application files, desktop/Start Menu shortcuts, and Windows Installed Apps entries.",
                install_dir.display()
            ),
            MB_YESNO | MB_ICONQUESTION,
            silent,
        );
        if choice != IDYES {
            return;
        }
    }

    // Release any directory CWD lock before deleting files or spawning post-exit cleanup
    let _ = env::set_current_dir(env::temp_dir());
    stop_running_app();

    let target_exe = install_dir.join("SentinelGateAI.exe");
    let _ = fs::remove_file(&target_exe);
    let data_dir = install_dir.join("data");
    if data_dir.exists() {
        let _ = fs::remove_dir_all(&data_dir);
    }

    if !no_shortcuts {
        remove_shortcuts();
        remove_registry_entry(custom_reg_key.unwrap_or(DEFAULT_UNINSTALL_SUBKEY));
    } else if let Some(reg_key) = custom_reg_key {
        remove_registry_entry(reg_key);
    }

    let uninstall_exe = install_dir.join("Uninstall.exe");
    let self_inside_target = env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .and_then(|cur| {
            uninstall_exe
                .canonicalize()
                .ok()
                .map(|u| cur == u)
                .or_else(|| install_dir.canonicalize().ok().map(|d| cur.starts_with(d)))
        })
        .unwrap_or(false);

    if !self_inside_target {
        let _ = fs::remove_file(&uninstall_exe);
        let _ = fs::remove_dir_all(install_dir);
    }

    if !silent {
        show_msg(
            "SentinelGate AI Uninstalled",
            "SentinelGate AI has been successfully removed from your computer.",
            MB_OK | MB_ICONINFORMATION,
            silent,
        );
    }

    if self_inside_target {
        // Spawn after any modal dialog closes so Uninstall.exe terminates right away and releases its lock.
        // Uses CREATE_NO_WINDOW only (combining CREATE_NO_WINDOW | DETACHED_PROCESS is invalid on Win32)
        // and env SG_DEL_DIR to avoid cmd/PowerShell path quoting issues.
        let _ = Command::new("cmd")
            .env("SG_DEL_DIR", install_dir)
            .raw_arg(
                r#"/d /s /c "for /L %i in (1,1,15) do @(ping -n 2 127.0.0.1 >nul & del /f /q "%SG_DEL_DIR%\Uninstall.exe" >nul 2>&1 & rmdir /s /q "%SG_DEL_DIR%" >nul 2>&1 & if not exist "%SG_DEL_DIR%" exit 0)""#,
            )
            .current_dir(env::temp_dir())
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let silent = args.iter().any(|a| a == "--silent" || a == "/S" || a == "/silent");

    let invoked_as_uninstaller = env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().eq_ignore_ascii_case("uninstall.exe")))
        .unwrap_or(false);
    let do_uninstall = invoked_as_uninstaller
        || args.iter().any(|a| a == "--uninstall" || a == "/uninstall" || a == "-u");

    let mut custom_dir: Option<PathBuf> = None;
    let mut custom_reg_key: Option<String> = None;
    let mut no_shortcuts = false;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--install-dir" && i + 1 < args.len() {
            custom_dir = Some(PathBuf::from(&args[i + 1]));
            i += 2;
            continue;
        }
        if args[i] == "--reg-key" && i + 1 < args.len() {
            custom_reg_key = Some(args[i + 1].clone());
            i += 2;
            continue;
        }
        if args[i] == "--no-shortcuts" {
            no_shortcuts = true;
        }
        i += 1;
    }

    let install_dir = custom_dir.unwrap_or_else(|| {
        if invoked_as_uninstaller {
            if let Some(parent) = env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())) {
                return parent;
            }
        }
        default_install_dir()
    });

    if do_uninstall {
        run_uninstall(&install_dir, no_shortcuts, silent, custom_reg_key.as_deref());
        return;
    }

    let target_exe = install_dir.join("SentinelGateAI.exe");
    let uninstall_exe = install_dir.join("Uninstall.exe");

    stop_running_app();
    ensure_webview2(silent);

    if let Err(e) = fs::create_dir_all(&install_dir) {
        show_msg(
            "SentinelGate AI Setup Error",
            &format!("Failed to create installation directory:\n{}", e),
            MB_OK | MB_ICONERROR,
            silent,
        );
        std::process::exit(1);
    }

    if let Err(e) = fs::write(&target_exe, PAYLOAD_EXE) {
        show_msg(
            "SentinelGate AI Setup Error",
            &format!("Failed to write application binary:\n{}", e),
            MB_OK | MB_ICONERROR,
            silent,
        );
        std::process::exit(1);
    }

    if let Ok(cur_exe) = env::current_exe() {
        let _ = fs::copy(&cur_exe, &uninstall_exe);
    }

    // Materialize starter editable data/*.json files directly inside install_dir/data
    if !silent {
        let _ = Command::new(&target_exe)
            .arg("--init-data")
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    if !no_shortcuts {
        if let Ok(appdata) = env::var("APPDATA") {
            let start_dir = PathBuf::from(appdata)
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs");
            create_shortcut(
                &target_exe,
                &start_dir.join("SentinelGate AI.lnk"),
                "",
                "SentinelGate AI - Secondary Strict Web Filter",
            );
            create_shortcut(
                &uninstall_exe,
                &start_dir.join("Uninstall SentinelGate AI.lnk"),
                "--uninstall",
                "Uninstall SentinelGate AI",
            );
        }
        if let Ok(userprofile) = env::var("USERPROFILE") {
            let desktop_lnk = PathBuf::from(userprofile).join("Desktop").join("SentinelGate AI.lnk");
            create_shortcut(
                &target_exe,
                &desktop_lnk,
                "",
                "SentinelGate AI - Secondary Strict Web Filter",
            );
        }
        register_app_metadata(
            &install_dir,
            &target_exe,
            &uninstall_exe,
            custom_reg_key.as_deref().unwrap_or(DEFAULT_UNINSTALL_SUBKEY),
        );
    } else if let Some(ref reg_key) = custom_reg_key {
        register_app_metadata(&install_dir, &target_exe, &uninstall_exe, reg_key);
    }

    if !silent {
        let choice = show_msg(
            "SentinelGate AI Installed",
            &format!(
                "SentinelGate AI has been successfully installed to:\n{}\n\nYou can uninstall anytime via Windows Settings -> Apps -> Installed apps or the Start Menu.\n\nLaunch SentinelGate AI now?",
                target_exe.display()
            ),
            MB_YESNO | MB_ICONINFORMATION,
            silent,
        );
        if choice == IDYES {
            let _ = Command::new(&target_exe).spawn();
        }
    }
}
