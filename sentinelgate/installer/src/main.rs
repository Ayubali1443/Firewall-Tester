#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::cell::RefCell;
use std::env;
use std::ffi::c_void;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MB_OK: u32 = 0x0000_0000;
const MB_YESNO: u32 = 0x0000_0004;
const MB_ICONINFORMATION: u32 = 0x0000_0040;
const MB_ICONERROR: u32 = 0x0000_0010;
const IDYES: i32 = 6;

const WS_OVERLAPPED: u32 = 0x0000_0000;
const WS_CAPTION: u32 = 0x00C0_0000;
const WS_SYSMENU: u32 = 0x0008_0000;
const WS_VISIBLE: u32 = 0x1000_0000;
const WS_CHILD: u32 = 0x4000_0000;
const WS_TABSTOP: u32 = 0x0001_0000;
const WS_BORDER: u32 = 0x0080_0000;
const ES_PASSWORD: u32 = 0x0020;
const ES_AUTOHSCROLL: u32 = 0x0080;
const BS_DEFPUSHBUTTON: u32 = 0x0001;
const BS_PUSHBUTTON: u32 = 0x0000;

const WM_COMMAND: u32 = 0x0111;
const WM_CLOSE: u32 = 0x0010;
const WM_DESTROY: u32 = 0x0002;
const WM_SETFONT: u32 = 0x0030;
const DEFAULT_GUI_FONT: i32 = 17;
const SM_CXSCREEN: i32 = 0;
const SM_CYSCREEN: i32 = 1;
const SW_SHOWNORMAL: i32 = 1;
const IDC_ARROW: usize = 32512;
const COLOR_BTNFACE_PLUS1: isize = 16;

const IDC_CF_ACCT: isize = 101;
const IDC_CF_TOKEN: isize = 102;
const IDC_GEM_KEY: isize = 103;
const IDC_BTN_INSTALL: isize = 1001;
const IDC_BTN_CANCEL: isize = 1002;

const HKEY_LOCAL_MACHINE: isize = -2147483646i32 as isize;
const KEY_ALL_ACCESS: u32 = 0x000F_003F;
const REG_OPTION_NON_VOLATILE: u32 = 0;
const REG_SZ: u32 = 1;
const REG_BINARY: u32 = 3;
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

const SE_FILE_OBJECT: u32 = 1;
const SE_REGISTRY_KEY: u32 = 4;
const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x01;
const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x04;

// Embedded compiled SentinelGateAI.exe (contains Python runtime, UI, Rust cf_validator, Rust sg_seal.dll)
static PAYLOAD_EXE: &[u8] = include_bytes!(env!("SG_PAYLOAD_EXE"));

#[repr(C)]
struct DATA_BLOB {
    cb_data: u32,
    pb_data: *mut u8,
}

#[repr(C)]
struct POINT {
    x: i32,
    y: i32,
}

#[repr(C)]
struct MSG {
    hwnd: isize,
    message: u32,
    w_param: usize,
    l_param: isize,
    time: u32,
    pt: POINT,
}

type WndProc = extern "system" fn(isize, u32, usize, isize) -> isize;

#[repr(C)]
struct WNDCLASSW {
    style: u32,
    lpfn_wnd_proc: WndProc,
    cb_cls_extra: i32,
    cb_wnd_extra: i32,
    h_instance: isize,
    h_icon: isize,
    h_cursor: isize,
    hbr_background: isize,
    lpsz_menu_name: *const u16,
    lpsz_class_name: *const u16,
}

#[link(name = "user32")]
extern "system" {
    fn MessageBoxW(hwnd: isize, text: *const u16, caption: *const u16, utype: u32) -> i32;
    fn RegisterClassW(lp_wnd_class: *const WNDCLASSW) -> u16;
    fn CreateWindowExW(
        ex_style: u32,
        class_name: *const u16,
        window_name: *const u16,
        style: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        parent: isize,
        menu: isize,
        instance: isize,
        param: *mut c_void,
    ) -> isize;
    fn DefWindowProcW(hwnd: isize, msg: u32, wp: usize, lp: isize) -> isize;
    fn GetMessageW(lp_msg: *mut MSG, hwnd: isize, min: u32, max: u32) -> i32;
    fn TranslateMessage(lp_msg: *const MSG) -> i32;
    fn DispatchMessageW(lp_msg: *const MSG) -> isize;
    fn IsDialogMessageW(h_dlg: isize, lp_msg: *const MSG) -> i32;
    fn PostQuitMessage(exit_code: i32);
    fn DestroyWindow(hwnd: isize) -> i32;
    fn SetFocus(hwnd: isize) -> isize;
    fn GetSystemMetrics(index: i32) -> i32;
    fn LoadCursorW(instance: isize, name: *const u16) -> isize;
    fn SendMessageW(hwnd: isize, msg: u32, wp: usize, lp: isize) -> isize;
    fn GetWindowTextW(hwnd: isize, text: *mut u16, max_count: i32) -> i32;
}

#[link(name = "gdi32")]
extern "system" {
    fn GetStockObject(i: i32) -> isize;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> isize;
    fn LocalFree(hmem: *mut c_void) -> *mut c_void;
}

#[link(name = "shell32")]
extern "system" {
    fn IsUserAnAdmin() -> i32;
    fn ShellExecuteW(
        hwnd: isize,
        op: *const u16,
        file: *const u16,
        params: *const u16,
        dir: *const u16,
        show: i32,
    ) -> isize;
}

#[link(name = "crypt32")]
extern "system" {
    fn CryptProtectData(
        p_data_in: *const DATA_BLOB,
        sz_data_descr: *const u16,
        p_optional_entropy: *const DATA_BLOB,
        pv_reserved: *mut c_void,
        p_prompt_struct: *mut c_void,
        dw_flags: u32,
        p_data_out: *mut DATA_BLOB,
    ) -> i32;
}

#[link(name = "bcrypt")]
extern "system" {
    fn BCryptGenRandom(h_algorithm: isize, pb_buffer: *mut u8, cb_buffer: u32, dw_flags: u32) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    fn RegCreateKeyExW(
        h_key: isize,
        sub_key: *const u16,
        reserved: u32,
        class: *const u16,
        options: u32,
        sam_desired: u32,
        sec_attr: *mut c_void,
        phk_result: *mut isize,
        disposition: *mut u32,
    ) -> i32;
    fn RegSetValueExW(
        h_key: isize,
        value_name: *const u16,
        reserved: u32,
        dw_type: u32,
        lp_data: *const u8,
        cb_data: u32,
    ) -> i32;
    fn RegCloseKey(h_key: isize) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string_sd: *const u16,
        sd_rev: u32,
        security_descriptor: *mut *mut c_void,
        sd_size: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        sd: *mut c_void,
        present: *mut i32,
        dacl: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    fn GetSecurityDescriptorOwner(
        sd: *mut c_void,
        owner: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    fn SetNamedSecurityInfoW(
        obj_name: *const u16,
        obj_type: u32,
        sec_info: u32,
        psid_owner: *mut c_void,
        psid_group: *mut c_void,
        pdacl: *mut c_void,
        psacl: *mut c_void,
    ) -> u32;
    fn SetSecurityInfo(
        handle: isize,
        obj_type: u32,
        sec_info: u32,
        psid_owner: *mut c_void,
        psid_group: *mut c_void,
        pdacl: *mut c_void,
        psacl: *mut c_void,
    ) -> u32;
}

#[derive(Default)]
struct FormHandles {
    hwnd_acct: isize,
    hwnd_token: isize,
    hwnd_gemini: isize,
    confirmed: bool,
    acct_val: String,
    token_val: String,
    gemini_val: String,
}

thread_local! {
    static FORM: RefCell<FormHandles> = RefCell::new(FormHandles::default());
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wipe_string(s: &mut String) {
    unsafe {
        let vec = s.as_mut_vec();
        for b in vec.iter_mut() {
            ptr::write_volatile(b, 0);
        }
        vec.clear();
    }
}

fn wipe_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { ptr::write_volatile(b, 0) };
    }
}

fn show_msg(title: &str, body: &str, flags: u32, silent: bool) -> i32 {
    if silent {
        return IDYES;
    }
    let t = to_wide(title);
    let b = to_wide(body);
    unsafe { MessageBoxW(0, b.as_ptr(), t.as_ptr(), flags) }
}

fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

fn elevate_self(args: &[String]) -> ! {
    let exe = match env::current_exe() {
        Ok(p) => p,
        Err(_) => std::process::exit(1),
    };
    let exe_w = to_wide(&exe.to_string_lossy());
    let op_w = to_wide("runas");
    let joined = args
        .iter()
        .map(|a| {
            if a.contains(' ') {
                format!("\"{}\"", a.replace('"', "\\\""))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let params_w = to_wide(&joined);

    let rc = unsafe { ShellExecuteW(0, op_w.as_ptr(), exe_w.as_ptr(), params_w.as_ptr(), ptr::null(), SW_SHOWNORMAL) };
    if rc <= 32 {
        show_msg(
            "Administrator Access Required",
            "SentinelGate AI Setup requires Windows Administrator elevation so Cloudflare API credentials can be locked away from non-admin desktop users.",
            MB_OK | MB_ICONERROR,
            false,
        );
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn read_hwnd_text(hwnd: isize) -> String {
    let mut buf = [0u16; 512];
    let n = unsafe { GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
    if n <= 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..n as usize]).trim().to_string()
}

extern "system" fn wizard_wnd_proc(hwnd: isize, msg: u32, wp: usize, lp: isize) -> isize {
    match msg {
        WM_COMMAND => {
            let id = (wp & 0xFFFF) as isize;
            if id == IDC_BTN_INSTALL {
                FORM.with(|cell| {
                    let mut f = cell.borrow_mut();
                    f.acct_val = read_hwnd_text(f.hwnd_acct);
                    f.token_val = read_hwnd_text(f.hwnd_token);
                    f.gemini_val = read_hwnd_text(f.hwnd_gemini);
                    f.confirmed = true;
                });
                unsafe { DestroyWindow(hwnd) };
                return 0;
            }
            if id == IDC_BTN_CANCEL {
                unsafe { DestroyWindow(hwnd) };
                return 0;
            }
            unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
        }
        WM_CLOSE => {
            unsafe { DestroyWindow(hwnd) };
            0
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
    }
}

fn prompt_credentials_dialog() -> Option<(String, String, String)> {
    unsafe {
        let h_inst = GetModuleHandleW(ptr::null());
        let cls_name = to_wide("SGSetupWizardClass");
        let title_w = to_wide("SentinelGate AI — Administrator Setup");
        let wc = WNDCLASSW {
            style: 0,
            lpfn_wnd_proc: wizard_wnd_proc,
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance: h_inst,
            h_icon: 0,
            h_cursor: LoadCursorW(0, IDC_ARROW as *const u16),
            hbr_background: COLOR_BTNFACE_PLUS1,
            lpsz_menu_name: ptr::null(),
            lpsz_class_name: cls_name.as_ptr(),
        };
        RegisterClassW(&wc);

        let win_w = 540;
        let win_h = 370;
        let x = (GetSystemMetrics(SM_CXSCREEN) - win_w) / 2;
        let y = (GetSystemMetrics(SM_CYSCREEN) - win_h) / 2;
        let hwnd = CreateWindowExW(
            0,
            cls_name.as_ptr(),
            title_w.as_ptr(),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            x,
            y,
            win_w,
            win_h,
            0,
            0,
            h_inst,
            ptr::null_mut(),
        );
        if hwnd == 0 {
            return None;
        }

        let font = GetStockObject(DEFAULT_GUI_FONT);
        let c_static = to_wide("STATIC");
        let c_edit = to_wide("EDIT");
        let c_button = to_wide("BUTTON");

        let make_ctrl = |cls: &[u16], text: &str, style: u32, cx: i32, cy: i32, cw: i32, ch: i32, id: isize| -> isize {
            let tw = to_wide(text);
            let h = CreateWindowExW(0, cls.as_ptr(), tw.as_ptr(), WS_CHILD | WS_VISIBLE | style, cx, cy, cw, ch, hwnd, id, h_inst, ptr::null_mut());
            SendMessageW(h, WM_SETFONT, font as usize, 1);
            h
        };

        make_ctrl(
            &c_static,
            "Enter Cloudflare API & Gemini API credentials for installation.\nCloudflare credentials will be encrypted with Windows Machine DPAPI and locked so ONLY Desktop Administrators / SYSTEM can access them.",
            0,
            20,
            16,
            490,
            46,
            0,
        );

        make_ctrl(&c_static, "Cloudflare Account ID:", 0, 20, 74, 220, 18, 0);
        let h_acct = make_ctrl(&c_edit, "", WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 20, 95, 485, 24, IDC_CF_ACCT);

        make_ctrl(&c_static, "Cloudflare API Token (Admin-Locked & Masked):", 0, 20, 130, 320, 18, 0);
        let h_tok = make_ctrl(&c_edit, "", WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD, 20, 151, 485, 24, IDC_CF_TOKEN);

        make_ctrl(&c_static, "Gemini AI API Key (Editable in App Vault):", 0, 20, 186, 320, 18, 0);
        let h_gem = make_ctrl(&c_edit, "", WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD, 20, 207, 485, 24, IDC_GEM_KEY);

        make_ctrl(
            &c_static,
            "Tip: Leave blank only if keeping previously sealed credentials already stored on this PC.",
            0,
            20,
            242,
            485,
            18,
            0,
        );

        make_ctrl(&c_button, "Install & Lock Credentials", WS_TABSTOP | BS_DEFPUSHBUTTON, 225, 276, 175, 32, IDC_BTN_INSTALL);
        make_ctrl(&c_button, "Cancel", WS_TABSTOP | BS_PUSHBUTTON, 410, 276, 95, 32, IDC_BTN_CANCEL);

        FORM.with(|cell| {
            let mut f = cell.borrow_mut();
            f.hwnd_acct = h_acct;
            f.hwnd_token = h_tok;
            f.hwnd_gemini = h_gem;
            f.confirmed = false;
        });

        SetFocus(h_acct);

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, 0, 0, 0) > 0 {
            if IsDialogMessageW(hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        FORM.with(|cell| {
            let mut f = cell.borrow_mut();
            if f.confirmed {
                Some((
                    std::mem::take(&mut f.acct_val),
                    std::mem::take(&mut f.token_val),
                    std::mem::take(&mut f.gemini_val),
                ))
            } else {
                wipe_string(&mut f.acct_val);
                wipe_string(&mut f.token_val);
                wipe_string(&mut f.gemini_val);
                None
            }
        })
    }
}

fn dpapi_encrypt(plain: &[u8], entropy: &[u8], local_machine: bool) -> Result<Vec<u8>, String> {
    let in_blob = DATA_BLOB {
        cb_data: plain.len() as u32,
        pb_data: plain.as_ptr() as *mut u8,
    };
    let ent_blob = DATA_BLOB {
        cb_data: entropy.len() as u32,
        pb_data: entropy.as_ptr() as *mut u8,
    };
    let mut out_blob = DATA_BLOB {
        cb_data: 0,
        pb_data: ptr::null_mut(),
    };
    let desc = to_wide("SentinelGateAI");
    let flags = CRYPTPROTECT_UI_FORBIDDEN | if local_machine { CRYPTPROTECT_LOCAL_MACHINE } else { 0 };

    let ok = unsafe {
        CryptProtectData(
            &in_blob,
            desc.as_ptr(),
            &ent_blob,
            ptr::null_mut(),
            ptr::null_mut(),
            flags,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return Err("CryptProtectData failed".to_string());
    }
    let slice = unsafe { std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize) };
    let res = slice.to_vec();
    unsafe { LocalFree(out_blob.pb_data as *mut c_void) };
    Ok(res)
}

fn apply_admin_sddl(target_path: Option<&str>, target_handle: Option<isize>, obj_type: u32, sddl: &str) -> Result<(), String> {
    let sddl_w = to_wide(sddl);
    let mut p_sd: *mut c_void = ptr::null_mut();
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl_w.as_ptr(), 1, &mut p_sd, ptr::null_mut()) == 0 {
            return Err("Failed building Windows Admin SDDL descriptor".to_string());
        }
        let mut present = 0i32;
        let mut defaulted = 0i32;
        let mut p_dacl: *mut c_void = ptr::null_mut();
        let mut p_owner: *mut c_void = ptr::null_mut();

        let dacl_ok = GetSecurityDescriptorDacl(p_sd, &mut present, &mut p_dacl, &mut defaulted);
        let owner_ok = GetSecurityDescriptorOwner(p_sd, &mut p_owner, &mut defaulted);
        if dacl_ok == 0 || owner_ok == 0 {
            LocalFree(p_sd);
            return Err("Failed extracting Windows Admin DACL/Owner".to_string());
        }

        let sec_info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        let rc = if let Some(h) = target_handle {
            SetSecurityInfo(h, obj_type, sec_info, p_owner, ptr::null_mut(), p_dacl, ptr::null_mut())
        } else if let Some(p) = target_path {
            let pw = to_wide(p);
            SetNamedSecurityInfoW(pw.as_ptr(), obj_type, sec_info, p_owner, ptr::null_mut(), p_dacl, ptr::null_mut())
        } else {
            1
        };
        LocalFree(p_sd);
        if rc != 0 {
            return Err(format!("Failed applying Windows Admin ACL (Win32 code {})", rc));
        }
    }
    Ok(())
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {}
            c => out.push(c),
        }
    }
    out
}

fn save_admin_cf_store(account_id: &str, api_token: &str, worker_url: &str, worker_token: &str) -> Result<(), String> {
    if !is_admin() {
        return Err("Administrator privileges required to seal Cloudflare credentials.".to_string());
    }

    let is_worker = !worker_url.is_empty() && !worker_token.is_empty();
    let mode = if is_worker { "worker" } else { "direct" };

    let mut reg_entropy = [0u8; 32];
    let status = unsafe { BCryptGenRandom(0, reg_entropy.as_mut_ptr(), reg_entropy.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status != 0 {
        return Err("System CSPRNG failure generating registry entropy".to_string());
    }

    let subkey_w = to_wide(r"SOFTWARE\SentinelGateAI");
    let mut h_key: isize = 0;
    let mut disp: u32 = 0;
    let rc_open = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey_w.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            ptr::null_mut(),
            &mut h_key,
            &mut disp,
        )
    };
    if rc_open != 0 {
        wipe_bytes(&mut reg_entropy);
        return Err(format!("Failed opening HKLM\\SOFTWARE\\SentinelGateAI (code {})", rc_open));
    }

    let ent_name = to_wide("SealEntropy");
    let mode_name = to_wide("Mode");
    let mode_w = to_wide(mode);
    unsafe {
        RegSetValueExW(h_key, ent_name.as_ptr(), 0, REG_BINARY, reg_entropy.as_ptr(), reg_entropy.len() as u32);
        RegSetValueExW(h_key, mode_name.as_ptr(), 0, REG_SZ, mode_w.as_ptr() as *const u8, (mode_w.len() * 2) as u32);
    }
    let reg_lock = apply_admin_sddl(None, Some(h_key), SE_REGISTRY_KEY, "O:BAD:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)");
    unsafe { RegCloseKey(h_key) };
    reg_lock?;

    let mut json_str = if is_worker {
        format!(
            "{{\"mode\":\"worker\",\"account_id\":\"\",\"api_token\":\"\",\"worker_url\":\"{}\",\"worker_token\":\"{}\"}}",
            json_escape(worker_url.trim_end_matches('/')),
            json_escape(worker_token)
        )
    } else {
        format!(
            "{{\"mode\":\"direct\",\"account_id\":\"{}\",\"api_token\":\"{}\",\"worker_url\":\"\",\"worker_token\":\"\"}}",
            json_escape(account_id),
            json_escape(api_token)
        )
    };

    let mut full_entropy = Vec::with_capacity(64);
    full_entropy.extend_from_slice(b"SentinelGateAI::CF_ADMIN::v1");
    full_entropy.extend_from_slice(&reg_entropy);
    wipe_bytes(&mut reg_entropy);

    let cipher_res = dpapi_encrypt(json_str.as_bytes(), &full_entropy, true);
    wipe_string(&mut json_str);
    wipe_bytes(&mut full_entropy);
    let cipher = cipher_res?;

    let prog_data = env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let admin_dir = PathBuf::from(prog_data).join("SentinelGateAI").join("AdminLock");
    fs::create_dir_all(&admin_dir).map_err(|e| e.to_string())?;
    apply_admin_sddl(
        Some(&admin_dir.to_string_lossy()),
        None,
        SE_FILE_OBJECT,
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
    )?;

    let admin_file = admin_dir.join("cf_admin.dpapi");
    fs::write(&admin_file, &cipher).map_err(|e| e.to_string())?;
    apply_admin_sddl(
        Some(&admin_file.to_string_lossy()),
        None,
        SE_FILE_OBJECT,
        "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
    )?;
    Ok(())
}

fn save_gemini_credentials(gemini_key: &str) -> Result<(), String> {
    if gemini_key.trim().is_empty() {
        return Ok(());
    }
    let mut json_str = format!("{{\"GEMINI_API_KEY\":\"{}\",\"GEMINI_API_KEY_BACKUP\":\"\"}}", json_escape(gemini_key.trim()));

    // 1. Shared machine seed so any standard desktop user inherits initial Gemini AI key cleanly
    let prog_data = env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let seed_dir = PathBuf::from(prog_data).join("SentinelGateAI");
    fs::create_dir_all(&seed_dir).map_err(|e| e.to_string())?;
    let seed_cipher = dpapi_encrypt(json_str.as_bytes(), b"SentinelGateAI::GeminiSeed::v1", true)?;
    fs::write(seed_dir.join("gemini_seed.dpapi"), seed_cipher).map_err(|e| e.to_string())?;

    // 2. Also populate installer's local user DPAPI vault
    if let Ok(local_app) = env::var("LOCALAPPDATA") {
        let user_dir = PathBuf::from(local_app).join("SentinelGateAI");
        fs::create_dir_all(&user_dir).map_err(|e| e.to_string())?;
        if let Ok(user_cipher) = dpapi_encrypt(json_str.as_bytes(), b"SentinelGateAI::DPAPI::v2", false) {
            let _ = fs::write(user_dir.join("vault.dpapi"), user_cipher);
        }
    }
    wipe_string(&mut json_str);
    Ok(())
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

fn create_shortcut(target_exe: &Path, shortcut_path: &Path) {
    if let Some(parent) = shortcut_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let target_str = target_exe.to_string_lossy().replace('\'', "''");
    let work_str = target_exe
        .parent()
        .map(|p| p.to_string_lossy().replace('\'', "''"))
        .unwrap_or_default();
    let lnk_str = shortcut_path.to_string_lossy().replace('\'', "''");

    let script = format!(
        "$ws = New-Object -ComObject WScript.Shell; \
         $s = $ws.CreateShortcut('{lnk_str}'); \
         $s.TargetPath = '{target_str}'; \
         $s.WorkingDirectory = '{work_str}'; \
         $s.Description = 'SentinelGate AI - Secondary Strict Web Filter'; \
         $s.Save()"
    );
    let _ = run_ps_hidden(&script);
}

fn register_app_metadata(install_dir: &Path, exe_path: &Path, admin_scope: bool) {
    let dir_str = install_dir.to_string_lossy().replace('\'', "''");
    let exe_str = exe_path.to_string_lossy().replace('\'', "''");
    let hive = if admin_scope { "HKLM:" } else { "HKCU:" };
    let script = format!(
        "$reg = '{hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SentinelGateAI'; \
         New-Item -Path $reg -Force | Out-Null; \
         Set-ItemProperty -Path $reg -Name 'DisplayName' -Value 'SentinelGate AI'; \
         Set-ItemProperty -Path $reg -Name 'DisplayVersion' -Value '2.0.0'; \
         Set-ItemProperty -Path $reg -Name 'Publisher' -Value 'SentinelGate Security'; \
         Set-ItemProperty -Path $reg -Name 'InstallLocation' -Value '{dir_str}'; \
         Set-ItemProperty -Path $reg -Name 'DisplayIcon' -Value '{exe_str}'; \
         Set-ItemProperty -Path $reg -Name 'NoModify' -Value 1 -Type DWord; \
         Set-ItemProperty -Path $reg -Name 'NoRepair' -Value 1 -Type DWord"
    );
    let _ = run_ps_hidden(&script);
}

fn default_install_dir(elevated: bool) -> PathBuf {
    if elevated {
        let prog_files = env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string());
        return PathBuf::from(prog_files).join("SentinelGateAI");
    }
    let local_app = env::var("LOCALAPPDATA").unwrap_or_else(|_| {
        let profile = env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Public".to_string());
        format!("{}\\AppData\\Local", profile)
    });
    PathBuf::from(local_app).join("Programs").join("SentinelGateAI")
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let silent = args.iter().any(|a| a == "--silent" || a == "/S" || a == "/silent");

    let mut custom_dir: Option<PathBuf> = None;
    let mut no_shortcuts = false;
    let mut cli_cf_acct = String::new();
    let mut cli_cf_token = String::new();
    let mut cli_cf_worker_url = String::new();
    let mut cli_cf_worker_tok = String::new();
    let mut cli_gemini = String::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--install-dir" if i + 1 < args.len() => {
                custom_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--no-shortcuts" => {
                no_shortcuts = true;
                i += 1;
            }
            "--cf-account" if i + 1 < args.len() => {
                cli_cf_acct = args[i + 1].trim().to_string();
                i += 2;
            }
            "--cf-token" if i + 1 < args.len() => {
                cli_cf_token = args[i + 1].trim().to_string();
                i += 2;
            }
            "--cf-worker-url" if i + 1 < args.len() => {
                cli_cf_worker_url = args[i + 1].trim().to_string();
                i += 2;
            }
            "--cf-worker-token" if i + 1 < args.len() => {
                cli_cf_worker_tok = args[i + 1].trim().to_string();
                i += 2;
            }
            "--gemini-key" if i + 1 < args.len() => {
                cli_gemini = args[i + 1].trim().to_string();
                i += 2;
            }
            _ => i += 1,
        }
    }

    let has_cli_cf = (!cli_cf_acct.is_empty() && !cli_cf_token.is_empty()) || (!cli_cf_worker_url.is_empty() && !cli_cf_worker_tok.is_empty());

    // Enforce Windows Administrator UAC elevation for interactive installs or Admin Vault writes
    if !is_admin() {
        if !silent {
            elevate_self(&args);
        } else if has_cli_cf || custom_dir.is_none() {
            std::process::exit(5);
        }
    }

    let elevated = is_admin();
    let install_dir = custom_dir.unwrap_or_else(|| default_install_dir(elevated));
    let target_exe = install_dir.join("SentinelGateAI.exe");

    let (mut cf_acct, mut cf_tok, mut gem_key) = if !silent && !has_cli_cf {
        match prompt_credentials_dialog() {
            Some(vals) => vals,
            None => std::process::exit(0),
        }
    } else {
        (cli_cf_acct, cli_cf_token, cli_gemini)
    };

    // Stop any running instance cleanly before replacing binary
    let _ = Command::new("taskkill")
        .args(["/F", "/IM", "SentinelGateAI.exe"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    ensure_webview2(silent);

    if let Err(e) = fs::create_dir_all(&install_dir) {
        show_msg("SentinelGate AI Setup Error", &format!("Failed to create directory:\n{}", e), MB_OK | MB_ICONERROR, silent);
        std::process::exit(1);
    }

    if let Err(e) = fs::write(&target_exe, PAYLOAD_EXE) {
        show_msg("SentinelGate AI Setup Error", &format!("Failed to write application binary:\n{}", e), MB_OK | MB_ICONERROR, silent);
        std::process::exit(1);
    }

    let want_cf_seal = (!cf_acct.is_empty() && !cf_tok.is_empty()) || (!cli_cf_worker_url.is_empty() && !cli_cf_worker_tok.is_empty());
    if want_cf_seal {
        if let Err(e) = save_admin_cf_store(&cf_acct, &cf_tok, &cli_cf_worker_url, &cli_cf_worker_tok) {
            show_msg(
                "Cloudflare Admin Lock Error",
                &format!("Failed to lock Cloudflare credentials to Administrator/SYSTEM store:\n{}", e),
                MB_OK | MB_ICONERROR,
                silent,
            );
            std::process::exit(1);
        }
    }
    if !gem_key.is_empty() {
        if let Err(e) = save_gemini_credentials(&gem_key) {
            show_msg("Gemini Vault Notice", &format!("Could not save Gemini API key seed:\n{}", e), MB_OK | MB_ICONINFORMATION, silent);
        }
    }

    wipe_string(&mut cf_acct);
    wipe_string(&mut cf_tok);
    wipe_string(&mut gem_key);

    if !no_shortcuts {
        if elevated {
            if let Ok(prog_data) = env::var("ProgramData") {
                let start_lnk = PathBuf::from(prog_data)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs")
                    .join("SentinelGate AI.lnk");
                create_shortcut(&target_exe, &start_lnk);
            }
            let pub_desktop = env::var("PUBLIC")
                .map(|p| PathBuf::from(p).join("Desktop").join("SentinelGate AI.lnk"))
                .ok();
            if let Some(d_lnk) = pub_desktop {
                create_shortcut(&target_exe, &d_lnk);
            }
        } else {
            if let Ok(appdata) = env::var("APPDATA") {
                let start_lnk = PathBuf::from(appdata)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs")
                    .join("SentinelGate AI.lnk");
                create_shortcut(&target_exe, &start_lnk);
            }
            if let Ok(userprofile) = env::var("USERPROFILE") {
                let desktop_lnk = PathBuf::from(userprofile).join("Desktop").join("SentinelGate AI.lnk");
                create_shortcut(&target_exe, &desktop_lnk);
            }
        }
        register_app_metadata(&install_dir, &target_exe, elevated);
    }

    if !silent {
        let cf_note = if want_cf_seal {
            "Cloudflare API: SEALED & LOCKED (Desktop Administrator + SYSTEM access only)."
        } else {
            "Cloudflare API: Preserved existing configuration (Admin-locked)."
        };
        let choice = show_msg(
            "SentinelGate AI Installed",
            &format!(
                "SentinelGate AI has been installed to:\n{}\n\n{}\n\nLaunch SentinelGate AI now (with Administrator access)?",
                target_exe.display(),
                cf_note
            ),
            MB_YESNO | MB_ICONINFORMATION,
            silent,
        );
        if choice == IDYES {
            let _ = Command::new(&target_exe).spawn();
        }
    }
}
