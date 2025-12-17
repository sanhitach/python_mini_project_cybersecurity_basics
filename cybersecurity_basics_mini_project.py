import os
import re
import wx

credsfile = "newusercreds.txt"

# ============================================================================
# PROJECT 1: PASSWORD STRENGTH CHECKER
# ============================================================================
# Functions: password_strength_checker(), prompt_for_strong_password()
# This project validates password strength based on length, character types,
# and special characters. Provides feedback on what's missing.
# ============================================================================


def password_strength_checker(password):
    score, feedback = 0, []
    MIN_NUMBERS, MIN_SPECIALS = 2, 1
    length = len(password)

    if length >= 12:
        score += 3
    elif length >= 8:
        score += 2
    else:
        feedback.append("Password must be minimum 8 characters or more.")

    if length >= 12:
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Missing lowercase letters")
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Missing uppercase letters")
    if len(re.findall(r"[^a-zA-Z0-9\s]", password)) >= MIN_SPECIALS:
        score += 2
    else:
        feedback.append(
            f"Needs a minimum of {MIN_SPECIALS} special characters.")
    if len(re.findall(r"\d", password)) >= MIN_NUMBERS:
        score += 1
    else:
        feedback.append(f"Needs a minimum of {MIN_NUMBERS} numbers.")
    if re.search(r"\s", password):
        score += 1
    else:
        feedback.append("Spaces help make the password stronger.")

    strength = ["Weak", "Moderate", "Strong", "Very Strong"][(
        score >= 4) + (score >= 6) + (score >= 8)]
    return strength, feedback


def prompt_for_strong_password(parent, title="Enter password", initial=""):
    while True:
        dlg = wx.TextEntryDialog(parent, "Provide a strong password:",
                                 title, value=initial, style=wx.OK | wx.CANCEL | wx.TE_PASSWORD)
        if dlg.ShowModal() != wx.ID_OK:
            dlg.Destroy()
            return None
        pw = dlg.GetValue()
        dlg.Destroy()
        strength, fb = password_strength_checker(pw)
        if strength in ("Strong", "Very Strong"):
            return pw
        wx.MessageBox("Password too weak:\n\n" + "\n".join(fb),
                      "Weak password", wx.OK | wx.ICON_WARNING)

# ============================================================================
# PROJECT 4: SIMPLE LOGIN SYSTEM WITH CREDENTIALS STORAGE
# ============================================================================
# Functions: read_creds(), write_creds(), check_username_exists()
# This project manages user credentials (username, password, phone) stored
# in a text file. Provides read/write operations for the login system.
# ============================================================================


def read_creds():
    d = {}
    if not os.path.exists(credsfile):
        return d
    try:
        with open(credsfile, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                parts = line.split(":", 2)
                u, p = (parts[0], parts[1]) if len(
                    parts) == 2 else (parts[0], parts[1])
                ph = parts[2] if len(parts) == 3 else ""
                d[u] = {"pwd": p, "phone": ph}
    except:
        pass
    return d


def write_creds(d):
    try:
        with open(credsfile, "w", encoding="utf-8") as f:
            for u, info in d.items():
                f.write(f"{u}:{info.get('pwd', '')}:{info.get('phone', '')}\n")
    except:
        pass


def check_username_exists(username): return username in read_creds()

# ============================================================================
# THEME SYSTEM (Used by all projects)
# ============================================================================
# Class: Themes
# Functions: apply_theme_to_panel()
# Provides 6 color themes (Blue, Green, Red, Black, Purple, White) that can
# be applied to any GUI panel to customize the appearance.
# ============================================================================


class Themes:
    LIST = [("Blue", {"bg": "#dff0ff", "fg": "#000000", "btn": "#9fd3ff"}),
            ("Green", {"bg": "#e9ffef", "fg": "#000000", "btn": "#8fe5a1"}),
            ("Red", {"bg": "#ffe9e9", "fg": "#000000", "btn": "#ff9f9f"}),
            ("Black", {"bg": "#1e1e1e", "fg": "#ffffff", "btn": "#333333"}),
            ("Purple", {"bg": "#f3e9ff", "fg": "#000000", "btn": "#c59bff"}),
            ("White", {"bg": "#ffffff", "fg": "#000000", "btn": "#e8e8e8"})]


def apply_theme_to_panel(panel, theme):
    bg, fg, btn = theme["bg"], theme["fg"], theme["btn"]
    try:
        panel.SetBackgroundColour(bg)
    except:
        pass
    for ch in panel.GetChildren():
        try:
            ch.SetForegroundColour(fg)
        except:
            pass
        if isinstance(ch, (wx.Button, wx.CheckBox, wx.RadioButton)):
            try:
                ch.SetBackgroundColour(btn)
            except:
                pass
        else:
            try:
                ch.SetBackgroundColour(bg)
            except:
                pass
    try:
        panel.Refresh()
    except:
        pass

# ============================================================================
# PROJECT 2: ENCRYPT/DECRYPT USING CAESAR CIPHER
# ============================================================================
# Function: caesar_process_text()
# Class: CaesarFrame
# This project encrypts/decrypts text using Caesar cipher. Allows users to
# load files, apply shift encryption, and save results. Has theme support.
# ============================================================================


def caesar_process_text(text, shift, mode):
    shift = -shift if mode == 'decrypt' else shift
    out = []
    for ch in text:
        if 'A' <= ch <= 'Z':
            out.append(chr((ord(ch)-ord('A')+shift) % 26 + ord('A')))
        elif 'a' <= ch <= 'z':
            out.append(chr((ord(ch)-ord('a')+shift) % 26 + ord('a')))
        else:
            out.append(ch)
    return "".join(out)


class CaesarFrame(wx.Frame):
    def __init__(self, parent_theme_index=5):
        super().__init__(None, title="Caesar Cipher Tool", size=(640, 480))
        self.panel, self.theme_index = wx.Panel(self), parent_theme_index
        s = wx.BoxSizer(wx.VERTICAL)

        fh = wx.BoxSizer(wx.HORIZONTAL)
        self.filepath = wx.TextCtrl(self.panel)
        self.btn_browse = wx.Button(self.panel, label="Browse")
        fh.Add(self.filepath, 1, wx.EXPAND | wx.RIGHT, 6)
        fh.Add(self.btn_browse, 0)
        s.Add(fh, flag=wx.ALL | wx.EXPAND, border=8)

        self.txt = wx.TextCtrl(self.panel, style=wx.TE_MULTILINE)
        s.Add(self.txt, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 8)

        options = wx.BoxSizer(wx.HORIZONTAL)
        self.rb_encrypt = wx.RadioButton(
            self.panel, label="Encrypt", style=wx.RB_GROUP)
        self.rb_decrypt = wx.RadioButton(self.panel, label="Decrypt")
        options.Add(self.rb_encrypt, 0, wx.RIGHT, 8)
        options.Add(self.rb_decrypt, 0, wx.RIGHT, 16)
        options.Add(wx.StaticText(self.panel, label="Shift:"),
                    0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 6)
        self.spin_shift = wx.SpinCtrl(self.panel, value="3", min=0, max=25)
        options.Add(self.spin_shift, 0)
        s.Add(options, flag=wx.ALL, border=8)

        hb = wx.BoxSizer(wx.HORIZONTAL)
        self.btn_process = wx.Button(self.panel, label="Process & Save")
        self.btn_reload = wx.Button(self.panel, label="Load File")
        self.btn_theme = wx.Button(self.panel, label="Theme")
        self.btn_close = wx.Button(self.panel, label="Close")
        for btn in [self.btn_process, self.btn_reload, self.btn_theme, self.btn_close]:
            hb.Add(btn, 0, wx.RIGHT, 6)
        s.Add(hb, flag=wx.ALIGN_RIGHT | wx.ALL, border=8)

        self.panel.SetSizer(s)
        self.apply_theme()

        self.btn_browse.Bind(wx.EVT_BUTTON, self.on_browse)
        self.btn_reload.Bind(wx.EVT_BUTTON, self.on_load_file)
        self.btn_process.Bind(wx.EVT_BUTTON, self.on_process_and_save)
        self.btn_close.Bind(wx.EVT_BUTTON, lambda e: self.Close())
        self.btn_theme.Bind(wx.EVT_BUTTON, self.on_cycle_theme)

    def apply_theme(self):
        name, th = Themes.LIST[self.theme_index]
        apply_theme_to_panel(self.panel, th)
        self.btn_theme.SetLabel(
            f"Theme: {name} ▶️ Next: {Themes.LIST[(self.theme_index+1) % len(Themes.LIST)][0]}")

    def on_cycle_theme(self, evt):
        self.theme_index = (self.theme_index + 1) % len(Themes.LIST)
        self.apply_theme()

    def on_browse(self, evt):
        with wx.FileDialog(self, "Choose text file", wildcard="Text files (*.txt)|*.txt|All files|*.*", style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) as dlg:
            if dlg.ShowModal() == wx.ID_OK:
                self.filepath.SetValue(dlg.GetPath())
                self.load_file(dlg.GetPath())

    def on_load_file(self, evt):
        p = self.filepath.GetValue().strip()
        if not p:
            wx.MessageBox("Select a file first",
                          "Error", wx.OK | wx.ICON_ERROR)
            return
        self.load_file(p)

    def load_file(self, path):
        if not os.path.exists(path):
            wx.MessageBox("File not found", "Error", wx.OK | wx.ICON_ERROR)
            return
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                self.txt.SetValue(f.read())
        except Exception as e:
            wx.MessageBox(f"Failed to read: {e}",
                          "Error", wx.OK | wx.ICON_ERROR)

    def on_process_and_save(self, evt):
        p = self.filepath.GetValue().strip()
        if not p or not os.path.exists(p):
            wx.MessageBox("Select an existing file to save to",
                          "Error", wx.OK | wx.ICON_ERROR)
            return
        mode, shift, orig = ('encrypt' if self.rb_encrypt.GetValue() else 'decrypt'), int(
            self.spin_shift.GetValue()), self.txt.GetValue()
        if not orig:
            wx.MessageBox("Text area is empty.", "Info",
                          wx.OK | wx.ICON_INFORMATION)
            return
        try:
            processed = caesar_process_text(orig, shift, mode)
            with open(p, 'w', encoding='utf-8') as f:
                f.write(
                    f"\n{mode.capitalize()}ion Result (Shift: {shift})\n{processed}")
            wx.MessageBox("Processed and saved to file.",
                          "OK", wx.OK | wx.ICON_INFORMATION)
            self.txt.SetValue(processed)
        except Exception as e:
            wx.MessageBox(f"Error: {e}", "Error", wx.OK | wx.ICON_ERROR)

# ============================================================================
# PROJECT 3 & 4: LOGIN SYSTEM WITH SUSPICIOUS ATTEMPT DETECTION
# ============================================================================
# Class: LoginFrame
# This combines Projects 3 & 4:
# - PROJECT 3: Detects suspicious login attempts (tracks failed attempts,
#   locks after 3 failures, requires phone verification for unlock)
# - PROJECT 4: Full login/register system with credentials file storage,
#   password strength validation, change password, forgot password features
# ============================================================================


class LoginFrame(wx.Frame):
    def __init__(self):
        super().__init__(None, title="Login / Register", size=(600, 520))
        self.panel, self.theme_index = wx.Panel(self), 5
        self._syncing, self.attempts = False, {}
        s = wx.BoxSizer(wx.VERTICAL)

        for label, attr in [("Username:", "user")]:
            s.Add(wx.StaticText(self.panel, label=label),
                  flag=wx.LEFT | wx.TOP, border=10)
            setattr(self, attr, wx.TextCtrl(
                self.panel, style=wx.TE_PROCESS_ENTER))
            s.Add(getattr(self, attr), flag=wx.EXPAND |
                  wx.LEFT | wx.RIGHT, border=10)

        s.Add(wx.StaticText(self.panel, label="Password:"),
              flag=wx.LEFT | wx.TOP, border=10)
        self.pwd_mask = wx.TextCtrl(
            self.panel, style=wx.TE_PASSWORD | wx.TE_PROCESS_ENTER)
        self.pwd_plain = wx.TextCtrl(self.panel, style=wx.TE_PROCESS_ENTER)
        self.pwd_plain.Hide()
        s.Add(self.pwd_mask, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=10)
        s.Add(self.pwd_plain, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=10)

        self.show_pwd_cb = wx.CheckBox(self.panel, label="Show password")
        s.Add(self.show_pwd_cb, flag=wx.LEFT | wx.TOP, border=8)

        s.Add(wx.StaticText(self.panel, label="Phone (10 digits):"),
              flag=wx.LEFT | wx.TOP, border=10)
        self.phone = wx.TextCtrl(self.panel)
        s.Add(self.phone, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=10)

        hb = wx.BoxSizer(wx.HORIZONTAL)
        for btn_attr, label in [("btn_login", "Login"), ("btn_reg", "Register"), ("btn_chpwd", "Change Password"), ("btn_forgot", "Forgot Password")]:
            setattr(self, btn_attr, wx.Button(self.panel, label=label))
            hb.Add(getattr(self, btn_attr), 1, wx.RIGHT, 5)
        s.Add(hb, flag=wx.ALL | wx.EXPAND, border=10)

        hb2 = wx.BoxSizer(wx.HORIZONTAL)
        self.btn_caesar, self.btn_clear, self.btn_theme = wx.Button(self.panel, label="Open Caesar Tool"), wx.Button(
            self.panel, label="Clear Fields"), wx.Button(self.panel, label="Theme")
        hb2.Add(self.btn_caesar, 0, wx.RIGHT, 8)
        hb2.Add(self.btn_clear, 0, wx.RIGHT, 8)
        hb2.Add(self.btn_theme, 0)
        s.Add(hb2, flag=wx.ALIGN_CENTER | wx.BOTTOM, border=8)

        self.panel.SetSizer(s)
        self.apply_theme()

        for btn, handler in [(self.btn_login, self.on_login), (self.btn_reg, self.on_register), (self.btn_chpwd, self.on_change_password), (self.btn_forgot, self.on_forgot_password), (self.btn_caesar, self.on_open_caesar), (self.btn_clear, self.on_manual_clear), (self.btn_theme, self.on_cycle_theme)]:
            btn.Bind(wx.EVT_BUTTON, handler)

        self.show_pwd_cb.Bind(wx.EVT_CHECKBOX, self.on_toggle_show)
        for ctrl in [self.user, self.pwd_mask, self.pwd_plain]:
            ctrl.Bind(wx.EVT_TEXT_ENTER, self.on_enter_password)
        self.pwd_mask.Bind(wx.EVT_TEXT, self._sync_mask_to_plain)
        self.pwd_plain.Bind(wx.EVT_TEXT, self._sync_plain_to_mask)

    def apply_theme(self):
        name, th = Themes.LIST[self.theme_index]
        apply_theme_to_panel(self.panel, th)
        self.btn_theme.SetLabel(
            f"Theme: {name} ▶️ Next: {Themes.LIST[(self.theme_index+1) % len(Themes.LIST)][0]}")

    def on_cycle_theme(self, evt):
        self.theme_index = (self.theme_index + 1) % len(Themes.LIST)
        self.apply_theme()

    def get_pwd(self): return self.pwd_plain.GetValue(
    ) if self.show_pwd_cb.GetValue() else self.pwd_mask.GetValue()

    def set_pwd(self, val):
        self._syncing = True
        self.pwd_mask.SetValue(val)
        self.pwd_plain.SetValue(val)
        self._syncing = False

    def focus_pwd(self):
        ctrl = self.pwd_plain if self.show_pwd_cb.GetValue() else self.pwd_mask
        ctrl.SetFocus()
        ctrl.SetSelection(0, len(ctrl.GetValue()))

    def _sync_mask_to_plain(self, evt):
        if not self._syncing:
            self._syncing = True
            self.pwd_plain.SetValue(evt.GetString())
            self._syncing = False

    def _sync_plain_to_mask(self, evt):
        if not self._syncing:
            self._syncing = True
            self.pwd_mask.SetValue(evt.GetString())
            self._syncing = False

    def on_toggle_show(self, evt):
        show, cur_val = self.show_pwd_cb.GetValue(), self.get_pwd()
        if show:
            self.pwd_mask.Hide()
            self.pwd_plain.Show()
        else:
            self.pwd_plain.Hide()
            self.pwd_mask.Show()
        self.set_pwd(cur_val)
        self.focus_pwd()
        self.panel.Layout()

    def clear_fields(self):
        self._syncing = True
        self.user.SetValue("")
        self.pwd_mask.SetValue("")
        self.pwd_plain.SetValue("")
        self.phone.SetValue("")
        self._syncing = False
        self.user.SetFocus()

    def on_manual_clear(self, evt): self.clear_fields()

    def on_register(self, evt):
        u, p, ph = self.user.GetValue().strip(), self.get_pwd(), self.phone.GetValue().strip()
        if not u or not p or not ph:
            wx.MessageBox("Provide username, password and phone",
                          "Error", wx.OK | wx.ICON_ERROR)
            return
        if check_username_exists(u):
            wx.MessageBox("Username exists", "Error", wx.OK | wx.ICON_ERROR)
            return
        if not re.fullmatch(r"\d{10}", ph):
            wx.MessageBox("Phone must be exactly 10 digits",
                          "Error", wx.OK | wx.ICON_ERROR)
            return
        strength, fb = password_strength_checker(p)
        if strength not in ("Strong", "Very Strong"):
            new_pw = prompt_for_strong_password(
                self, title="Create strong password", initial=p)
            if not new_pw:
                wx.MessageBox("Registration cancelled.",
                              "Cancelled", wx.OK | wx.ICON_INFORMATION)
                return
            p = new_pw
        d = read_creds()
        d[u] = {"pwd": p, "phone": ph}
        write_creds(d)
        wx.MessageBox("Registered", "Success", wx.OK | wx.ICON_INFORMATION)
        self.clear_fields()

    def on_login(self, evt):
        u, p, ph = self.user.GetValue().strip(), self.get_pwd(), self.phone.GetValue().strip()
        if not u or not p or not ph:
            wx.MessageBox("Enter username, password and phone",
                          "Error", wx.OK | wx.ICON_ERROR)
            return
        d, rec = read_creds(), read_creds().get(u)
        if rec and rec.get("pwd") == p and rec.get("phone") == ph:
            wx.MessageBox("Login successful", "OK",
                          wx.OK | wx.ICON_INFORMATION)
            self.attempts[u] = 0
            self.clear_fields()
            return
        self.attempts[u] = self.attempts.get(u, 0) + 1
        if self.attempts[u] >= 3:
            if not rec:
                wx.MessageBox("Unknown username.", "Error",
                              wx.OK | wx.ICON_ERROR)
                return
            phone_dlg = wx.TextEntryDialog(
                self, "Too many failed attempts.\nEnter your registered 10-digit phone:", "Verify Phone")
            if phone_dlg.ShowModal() != wx.ID_OK:
                phone_dlg.Destroy()
                wx.MessageBox("Verification required.",
                              "Locked", wx.OK | wx.ICON_ERROR)
                return
            phone_in = phone_dlg.GetValue().strip()
            phone_dlg.Destroy()
            if phone_in == rec.get("phone"):
                wx.MessageBox("Phone verified. Set new password.",
                              "OK", wx.OK | wx.ICON_INFORMATION)
                self._open_change_password_dialog(
                    prefill_user=u, require_current=False)
                self.attempts[u] = 0
            else:
                wx.MessageBox("Phone verification failed.",
                              "Locked", wx.OK | wx.ICON_ERROR)
        else:
            wx.MessageBox(
                f"Invalid credentials. {3-self.attempts[u]} attempt(s) left.", "Error", wx.OK | wx.ICON_ERROR)
            self.focus_pwd()

    def _open_change_password_dialog(self, prefill_user=None, require_current=True):
        dlg = wx.Dialog(self, title="Change Password", size=(420, 260))
        pnl, s = wx.Panel(dlg), wx.BoxSizer(wx.VERTICAL)
        s.Add(wx.StaticText(pnl, label="Username:"),
              flag=wx.LEFT | wx.TOP, border=8)
        tu = wx.TextCtrl(pnl)
        s.Add(tu, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=8)
        if require_current:
            s.Add(wx.StaticText(pnl, label="Current Password:"),
                  flag=wx.LEFT | wx.TOP, border=8)
            to = wx.TextCtrl(pnl, style=wx.TE_PASSWORD)
            s.Add(to, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=8)
        else:
            to = None
        s.Add(wx.StaticText(pnl, label="New Password:"),
              flag=wx.LEFT | wx.TOP, border=8)
        tn = wx.TextCtrl(pnl, style=wx.TE_PASSWORD)
        s.Add(tn, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=8)
        hb = wx.BoxSizer(wx.HORIZONTAL)
        ok, cancel = wx.Button(pnl, wx.ID_OK), wx.Button(pnl, wx.ID_CANCEL)
        hb.Add(ok)
        hb.Add(cancel, flag=wx.LEFT, border=8)
        s.Add(hb, flag=wx.ALIGN_CENTER | wx.TOP | wx.BOTTOM, border=10)
        pnl.SetSizer(s)
        tu.SetValue(prefill_user or "")
        if dlg.ShowModal() == wx.ID_OK:
            uval, old, new = tu.GetValue().strip(), (to.GetValue() if to else ""), tn.GetValue()
            dlg.Destroy()
            d, rec = read_creds(), read_creds().get(uval)
            if not rec:
                wx.MessageBox("User not found", "Error", wx.OK | wx.ICON_ERROR)
                return
            if require_current and rec.get("pwd") != old:
                wx.MessageBox("Invalid current password",
                              "Error", wx.OK | wx.ICON_ERROR)
                return
            strength, fb = password_strength_checker(new)
            if strength not in ("Strong", "Very Strong"):
                new_pw = prompt_for_strong_password(
                    self, title="Choose stronger password", initial=new)
                if not new_pw:
                    wx.MessageBox("Cancelled.", "Cancelled",
                                  wx.OK | wx.ICON_INFORMATION)
                    return
                new = new_pw
            rec["pwd"] = new
            d[uval] = rec
            write_creds(d)
            wx.MessageBox("Password changed", "OK",
                          wx.OK | wx.ICON_INFORMATION)
            self.clear_fields()
        else:
            dlg.Destroy()

    def on_change_password(self, evt): self._open_change_password_dialog(
        require_current=True)

    def on_forgot_password(self, evt):
        dlg = wx.Dialog(self, title="Forgot Password", size=(420, 300))
        pnl, s = wx.Panel(dlg), wx.BoxSizer(wx.VERTICAL)
        s.Add(wx.StaticText(pnl, label="Username:"),
              flag=wx.LEFT | wx.TOP, border=8)
        tu = wx.TextCtrl(pnl)
        s.Add(tu, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=8)
        s.Add(wx.StaticText(pnl, label="Registered Phone (10 digits):"),
              flag=wx.LEFT | wx.TOP, border=8)
        tph = wx.TextCtrl(pnl)
        s.Add(tph, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=8)
        s.Add(wx.StaticText(pnl, label="New Password:"),
              flag=wx.LEFT | wx.TOP, border=8)
        tn = wx.TextCtrl(pnl, style=wx.TE_PASSWORD)
        s.Add(tn, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=8)
        hb = wx.BoxSizer(wx.HORIZONTAL)
        ok, cancel = wx.Button(pnl, wx.ID_OK), wx.Button(pnl, wx.ID_CANCEL)
        hb.Add(ok)
        hb.Add(cancel, flag=wx.LEFT, border=8)
        s.Add(hb, flag=wx.ALIGN_CENTER | wx.TOP | wx.BOTTOM, border=10)
        pnl.SetSizer(s)
        if dlg.ShowModal() == wx.ID_OK:
            uval, phone_in, new = tu.GetValue().strip(), tph.GetValue().strip(), tn.GetValue()
            dlg.Destroy()
            d, rec = read_creds(), read_creds().get(uval)
            if not rec:
                wx.MessageBox("Username not found", "Error",
                              wx.OK | wx.ICON_ERROR)
                return
            if phone_in != rec.get("phone"):
                wx.MessageBox("Phone mismatch", "Error", wx.OK | wx.ICON_ERROR)
                return
            strength, fb = password_strength_checker(new)
            if strength not in ("Strong", "Very Strong"):
                new_pw = prompt_for_strong_password(
                    self, title="Choose stronger password", initial=new)
                if not new_pw:
                    wx.MessageBox("Cancelled.", "Cancelled",
                                  wx.OK | wx.ICON_INFORMATION)
                    return
                new = new_pw
            rec["pwd"] = new
            d[uval] = rec
            write_creds(d)
            wx.MessageBox("Password reset", "OK", wx.OK | wx.ICON_INFORMATION)
            self.clear_fields()
        else:
            dlg.Destroy()

    def on_enter_password(self, evt): self.on_login(evt)

    def on_open_caesar(self, evt): CaesarFrame(
        parent_theme_index=self.theme_index).Show()


def start_gui():
    app = wx.App(False)
    LoginFrame().Show()
    app.MainLoop()


if __name__ == "__main__":
    start_gui()
