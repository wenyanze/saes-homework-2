"""Tkinter GUI for all five S-AES assignment levels."""

from __future__ import annotations

import re
import queue
from concurrent.futures import CancelledError
import secrets
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from saes import (
    ascii_decrypt,
    ascii_encrypt,
    bytes_to_display,
    cbc_decrypt,
    cbc_encrypt,
    decrypt_block,
    double_decrypt,
    double_encrypt,
    encrypt_block,
    encrypt_trace,
    format_hex,
    meet_in_the_middle,
    parse_hex,
    tamper_ciphertext,
    triple_decrypt,
    triple_encrypt,
)


COLORS = {
    "shell": "#081426",
    "sidebar": "#0D1F38",
    "sidebar_active": "#173A66",
    "sidebar_hover": "#13304F",
    "sidebar_muted": "#8EA9C8",
    "accent": "#4D8DFF",
    "accent_text": "#A9C8FF",
    "accent_pressed": "#2E6FD8",
    "accent_pressed_deep": "#235EB5",
    "accent_soft": "#18365E",
    "page": "#0B1B31",
    "card": "#102743",
    "ink": "#E7F0FF",
    "muted": "#9AB0CB",
    "line": "#25476D",
    "output": "#0A203B",
    "focus": "#123459",
    "button_hover": "#183A63",
    "button_pressed": "#1B4778",
    "disabled": "#607895",
    "on_dark": "#E7F0FF",
    "subtle_dark": "#88A2C1",
    "divider": "#234363",
    "badge": "#143458",
    "success": "#55D39A",
}


def _hex_bytes(text: str) -> bytes:
    normalized = re.sub(r"\s+", "", text.strip())
    if normalized.lower().startswith("0x"):
        normalized = normalized[2:]
    if not normalized or len(normalized) % 2 or any(character not in "0123456789abcdefABCDEF" for character in normalized):
        raise ValueError("请输入偶数位十六进制字节串")
    return bytes.fromhex(normalized)


class SaesApplication(tk.Tk):
    """Desktop application with reproducible inputs and visible intermediate data."""

    def __init__(self) -> None:
        super().__init__()
        self.configure(bg=COLORS["shell"])
        self.title("S-AES 简化 AES 实验平台")
        self.geometry("980x720")
        self.minsize(840, 600)
        self._configure_style()
        self.status_var = tk.StringVar(value="就绪。所有十六进制数据均按大端顺序解释。")
        self._build_window()

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=COLORS["page"])
        style.configure("TLabel", background=COLORS["card"], foreground=COLORS["ink"])
        style.configure("Subtitle.TLabel", background=COLORS["page"], foreground=COLORS["muted"])
        style.configure("Card.TLabel", background=COLORS["card"], foreground=COLORS["ink"])
        style.configure("CardMuted.TLabel", background=COLORS["card"], foreground=COLORS["muted"])
        style.configure("Status.TLabel", background=COLORS["shell"], foreground=COLORS["on_dark"])
        style.configure("TEntry", fieldbackground=COLORS["card"], foreground=COLORS["ink"], padding=(8, 6))
        style.configure("TCombobox", fieldbackground=COLORS["card"], foreground=COLORS["ink"], padding=(6, 4))
        style.map("TCombobox", fieldbackground=[("readonly", COLORS["card"])],
                  foreground=[("readonly", COLORS["ink"])],
                  selectbackground=[("readonly", COLORS["card"])],
                  selectforeground=[("readonly", COLORS["ink"])])
        style.map("TEntry", fieldbackground=[("focus", COLORS["focus"])])
        style.configure(
            "TButton",
            background=COLORS["card"],
            foreground=COLORS["ink"],
            bordercolor=COLORS["line"],
            padding=(12, 7),
            font=("Segoe UI", 9),
        )
        style.map(
            "TButton",
            background=[("active", COLORS["button_hover"]), ("pressed", COLORS["button_pressed"])],
            foreground=[("disabled", COLORS["disabled"])],
        )
        style.configure(
            "Primary.TButton",
            background=COLORS["accent"],
            foreground=COLORS["on_dark"],
            bordercolor=COLORS["accent"],
            padding=(14, 8),
            font=("Segoe UI", 9, "bold"),
        )
        style.map("Primary.TButton", background=[("active", COLORS["accent_pressed"]), ("pressed", COLORS["accent_pressed_deep"])])
        style.configure(
            "Section.TLabelframe",
            background=COLORS["card"],
            foreground=COLORS["ink"],
            bordercolor=COLORS["line"],
            relief="solid",
            borderwidth=1,
            padding=14,
        )
        style.configure("Section.TLabelframe.Label", background=COLORS["card"], foreground=COLORS["accent_text"])
        style.configure("Hidden.TNotebook", background=COLORS["page"], borderwidth=0, tabmargins=0)
        try:
            style.layout("Hidden.TNotebook.Tab", [])
        except tk.TclError:
            pass

    def _build_window(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self.page_meta = (
            ("01", "基础分组", "PRIMITIVES", "单分组加解密 · 轮状态"),
            ("02", "ASCII 字符串", "DATA EXTENSION", "2 bytes 分组 · 填充"),
            ("03", "多重加密", "KEY COMPOSITION", "E-E · E-D-E · EDE2"),
            ("04", "中间相遇攻击", "ATTACK LAB", "2^16 × 2 的密钥搜索"),
            ("05", "CBC 模式", "MODE LAB", "IV · 链式分组 · 篡改"),
        )
        self.page_title_var = tk.StringVar(value="01 / 基础分组")
        self.page_hint_var = tk.StringVar(value="单分组加解密 · 轮状态")
        self.page_kicker_var = tk.StringVar(value="PRIMITIVES")

        header = tk.Frame(self, bg=COLORS["shell"], height=82)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        header.columnconfigure(1, weight=1)
        tk.Frame(header, bg=COLORS["accent"], width=5).grid(row=0, column=0, rowspan=2, sticky="nsw")
        brand = tk.Frame(header, bg=COLORS["shell"])
        brand.grid(row=0, column=1, sticky="nsew", padx=(22, 10), pady=(15, 8))
        tk.Label(brand, text="S-AES LAB", bg=COLORS["shell"], fg=COLORS["accent"], font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(
            brand,
            text="简化 AES 算法实验平台",
            bg=COLORS["shell"],
            fg=COLORS["on_dark"],
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w", pady=(1, 0))
        tk.Label(
            header,
            text="APPENDIX D  /  16-BIT BLOCK  /  GF(2^4)",
            bg=COLORS["shell"],
            fg=COLORS["sidebar_muted"],
            font=("Consolas", 9),
        ).grid(row=0, column=2, padx=(10, 24), pady=(18, 0), sticky="e")
        tk.Label(
            header,
            text="●  STANDARD READY",
            bg=COLORS["badge"],
            fg=COLORS["success"],
            padx=12,
            pady=6,
            font=("Consolas", 9, "bold"),
        ).grid(row=1, column=2, padx=(10, 24), pady=(0, 14), sticky="e")

        shell = tk.Frame(self, bg=COLORS["shell"])
        shell.grid(row=1, column=0, sticky="nsew")
        shell.columnconfigure(1, weight=1)
        shell.rowconfigure(0, weight=1)

        sidebar = tk.Frame(shell, bg=COLORS["sidebar"], width=238)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        tk.Label(
            sidebar,
            text="WORKBENCH",
            bg=COLORS["sidebar"],
            fg=COLORS["sidebar_muted"],
            font=("Consolas", 9, "bold"),
        ).pack(anchor="w", padx=22, pady=(22, 12))
        self.nav_buttons: list[tk.Button] = []
        for index, (number, title, _kicker, hint) in enumerate(self.page_meta):
            button = tk.Button(
                sidebar,
                text=f"{number}   {title}\n          {hint}",
                anchor="w",
                justify="left",
                relief="flat",
                bd=0,
                cursor="hand2",
                bg=COLORS["sidebar"],
                fg=COLORS["on_dark"],
            activebackground=COLORS["sidebar_active"],
            activeforeground=COLORS["accent_text"],
                padx=20,
                pady=10,
                font=("Segoe UI", 10, "bold"),
                command=lambda page=index: self._select_page(page),
            )
            button.pack(fill="x", padx=10, pady=3)
            button.bind("<Enter>", lambda _event, item=button, page=index: self._nav_hover(item, page, True))
            button.bind("<Leave>", lambda _event, item=button, page=index: self._nav_hover(item, page, False))
            self.nav_buttons.append(button)
        tk.Frame(sidebar, bg=COLORS["divider"], height=1).pack(fill="x", padx=22, pady=(22, 14))
        tk.Label(
            sidebar,
            text="交互提示\n输入区保持可编辑\n输出区使用规范 HEX\n\n快捷入口\npython demo.py",
            justify="left",
            anchor="w",
            bg=COLORS["sidebar"],
            fg=COLORS["sidebar_muted"],
            font=("Segoe UI", 9),
            padx=22,
            pady=4,
        ).pack(fill="x")

        workspace = tk.Frame(shell, bg=COLORS["page"])
        workspace.grid(row=0, column=1, sticky="nsew")
        workspace.columnconfigure(0, weight=1)
        workspace.rowconfigure(1, weight=1)
        page_bar = tk.Frame(workspace, bg=COLORS["page"], height=76)
        page_bar.grid(row=0, column=0, sticky="ew")
        page_bar.grid_propagate(False)
        heading = tk.Frame(page_bar, bg=COLORS["page"])
        heading.pack(side="left", padx=(28, 10), pady=(13, 0))
        tk.Frame(heading, bg=COLORS["accent"], width=3, height=39).pack(side="left", padx=(0, 11))
        heading_text = tk.Frame(heading, bg=COLORS["page"])
        heading_text.pack(side="left")
        tk.Label(
            heading_text,
            textvariable=self.page_kicker_var,
            bg=COLORS["page"],
            fg=COLORS["accent"],
            font=("Consolas", 8, "bold"),
        ).pack(anchor="w")
        tk.Label(
            heading_text,
            textvariable=self.page_title_var,
            bg=COLORS["page"],
            fg=COLORS["ink"],
            font=("Segoe UI", 15, "bold"),
        ).pack(anchor="w", pady=(1, 0))
        tk.Label(
            page_bar,
            textvariable=self.page_hint_var,
            bg=COLORS["page"],
            fg=COLORS["muted"],
            font=("Segoe UI", 9),
        ).pack(side="left", pady=(22, 0))
        tk.Label(
            page_bar,
            text="STANDARD\n16 BIT",
            justify="left",
            bg=COLORS["accent_soft"],
            fg=COLORS["accent_text"],
            padx=10,
            pady=4,
            font=("Consolas", 8, "bold"),
        ).pack(side="right", padx=(8, 28), pady=(15, 0))

        notebook = ttk.Notebook(workspace, style="Hidden.TNotebook")
        notebook.grid(row=1, column=0, sticky="nsew", padx=(14, 18), pady=(0, 14))
        self.notebook = notebook
        self._build_block_tab(notebook)
        self._build_text_tab(notebook)
        self._build_multi_tab(notebook)
        self._build_mitm_tab(notebook)
        self._build_cbc_tab(notebook)
        self._select_page(0)

        footer = tk.Frame(self, bg=COLORS["shell"], height=34)
        footer.grid(row=2, column=0, sticky="ew")
        footer.grid_propagate(False)
        tk.Label(footer, text="●", bg=COLORS["shell"], fg=COLORS["success"], font=("Consolas", 10)).pack(side="left", padx=(20, 6))
        tk.Label(footer, textvariable=self.status_var, bg=COLORS["shell"], fg=COLORS["on_dark"], font=("Segoe UI", 9)).pack(
            side="left", pady=8
        )
        tk.Label(footer, text="CTRL+1..5  /  NO EXTERNAL DEPENDENCIES", bg=COLORS["shell"], fg=COLORS["subtle_dark"], font=("Consolas", 8)).pack(
            side="right", padx=22
        )
        for page in range(len(self.page_meta)):
            self.bind_all(f"<Control-Key-{page + 1}>", lambda _event, item=page: self._select_page(item))

    def _select_page(self, index: int) -> None:
        self.notebook.select(index)
        number, title, kicker, hint = self.page_meta[index]
        self.page_title_var.set(f"{number} / {title}")
        self.page_hint_var.set(hint)
        self.page_kicker_var.set(kicker)
        for current, button in enumerate(self.nav_buttons):
            active = current == index
            button.configure(
                bg=COLORS["sidebar_active"] if active else COLORS["sidebar"],
                fg=COLORS["accent_text"] if active else COLORS["on_dark"],
                relief="solid" if active else "flat",
                highlightthickness=1 if active else 0,
                highlightbackground=COLORS["accent"] if active else COLORS["sidebar"],
            )

    def _nav_hover(self, button: tk.Button, page: int, entering: bool) -> None:
        if page == self.notebook.index(self.notebook.select()):
            return
        button.configure(bg=COLORS["sidebar_hover"] if entering else COLORS["sidebar"])

    @staticmethod
    def _intro(parent: ttk.Frame, eyebrow: str, description: str) -> None:
        intro = tk.Frame(parent, bg=COLORS["page"], height=44)
        intro.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        intro.grid_propagate(False)
        tk.Frame(intro, bg=COLORS["accent"], width=3).pack(side="left", fill="y", padx=(0, 10))
        text = tk.Frame(intro, bg=COLORS["page"])
        text.pack(side="left", fill="both", expand=True)
        tk.Label(text, text=eyebrow, bg=COLORS["page"], fg=COLORS["accent"], font=("Consolas", 8, "bold")).pack(anchor="w")
        tk.Label(text, text=description, bg=COLORS["page"], fg=COLORS["muted"], font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))

    @staticmethod
    def _entry(parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, width: int = 24) -> ttk.Entry:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 10), pady=5)
        entry = ttk.Entry(parent, textvariable=variable, width=width)
        entry.grid(row=row, column=1, sticky="ew", pady=5)
        return entry

    @staticmethod
    def _text_output(parent: ttk.Frame, row: int, column: int, height: int = 12) -> tk.Text:
        output = tk.Text(
            parent,
            height=height,
            wrap="word",
            font=("Consolas", 10),
            relief="solid",
            borderwidth=1,
            background=COLORS["output"],
            foreground=COLORS["ink"],
            insertbackground=COLORS["accent"],
            selectbackground=COLORS["accent_soft"],
            selectforeground=COLORS["ink"],
            highlightbackground=COLORS["line"],
            highlightcolor=COLORS["accent"],
            highlightthickness=1,
            padx=10,
            pady=8,
        )
        output.grid(row=row, column=column, sticky="nsew", pady=(4, 0))
        output.configure(state="disabled")
        return output

    @staticmethod
    def _write_text(output: tk.Text, text: str) -> None:
        output.configure(state="normal")
        output.delete("1.0", "end")
        output.insert("1.0", text)
        output.configure(state="disabled")

    def _report_error(self, error: Exception) -> None:
        self.status_var.set(f"输入或操作错误：{error}")
        messagebox.showerror("操作未完成", str(error), parent=self)

    def _build_block_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=16)
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        notebook.add(tab, text="1. 基础分组")
        self._intro(tab, "STANDARD VECTOR / TWO ROUNDS", "输入 16 bit 明文/密文和密钥；右侧实时查看每个轮变换状态。")

        body = ttk.Frame(tab)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        controls = ttk.LabelFrame(body, text="输入与操作", style="Section.TLabelframe")
        controls.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        controls.columnconfigure(1, weight=1)
        self.block_input_var = tk.StringVar(value="D728")
        self.block_key_var = tk.StringVar(value="4AF5")
        self.block_output_var = tk.StringVar()
        self._entry(controls, 0, "数据（hex）", self.block_input_var)
        self._entry(controls, 1, "密钥（hex）", self.block_key_var)
        ttk.Label(controls, text="输出（hex）").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=5)
        ttk.Entry(controls, textvariable=self.block_output_var, state="readonly", width=24).grid(
            row=2, column=1, sticky="ew", pady=5
        )
        buttons = ttk.Frame(controls)
        buttons.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(12, 4))
        ttk.Button(buttons, text="加密", style="Primary.TButton", command=self._encrypt_block).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="解密", command=self._decrypt_block).pack(side="left")
        ttk.Label(
            controls,
            text="标准向量：P=D728, K=4AF5, C=24EC\n密钥扩展：K0=4AF5, K1=DD28, K2=87AF",
            style="CardMuted.TLabel",
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(18, 0))

        trace_frame = ttk.LabelFrame(body, text="加密过程可视化", style="Section.TLabelframe")
        trace_frame.grid(row=0, column=1, sticky="nsew")
        trace_frame.rowconfigure(0, weight=1)
        trace_frame.columnconfigure(0, weight=1)
        self.block_trace = self._text_output(trace_frame, 0, 0, height=16)

    def _encrypt_block(self) -> None:
        try:
            plaintext = parse_hex(self.block_input_var.get(), 16, "数据")
            key = parse_hex(self.block_key_var.get(), 16, "密钥")
            ciphertext, trace = encrypt_trace(plaintext, key)
            self.block_output_var.set(format_hex(ciphertext))
            self._write_text(self.block_trace, "\n".join(f"{name:<28} {format_hex(value)}" for name, value in trace))
            self.status_var.set("基础分组加密完成。")
        except (TypeError, ValueError) as error:
            self._report_error(error)

    def _decrypt_block(self) -> None:
        try:
            ciphertext = parse_hex(self.block_input_var.get(), 16, "数据")
            key = parse_hex(self.block_key_var.get(), 16, "密钥")
            plaintext = decrypt_block(ciphertext, key)
            self.block_output_var.set(format_hex(plaintext))
            self._write_text(self.block_trace, f"Ciphertext                 {format_hex(ciphertext)}\nDecrypt result              {format_hex(plaintext)}")
            self.status_var.set("基础分组解密完成。")
        except (TypeError, ValueError) as error:
            self._report_error(error)

    def _build_text_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=16)
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        notebook.add(tab, text="2. ASCII 字符串")
        self._intro(tab, "DATA EXTENSION / ASCII", "按 2 bytes 分组并自动填充；密文使用规范 HEX，避免不可打印字符造成丢失。")
        body = ttk.Frame(tab)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(1, weight=1)
        body.rowconfigure(4, weight=1)
        self.text_plain_var = tk.StringVar(value="S-AES demo")
        self.text_key_var = tk.StringVar(value="4AF5")
        self.text_cipher_var = tk.StringVar()
        self.text_decrypted_var = tk.StringVar()
        self._entry(body, 0, "ASCII 明文", self.text_plain_var, 50)
        self._entry(body, 1, "密钥（hex）", self.text_key_var)
        ttk.Label(body, text="密文（hex，可编辑）").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=5)
        ttk.Entry(body, textvariable=self.text_cipher_var, width=60).grid(row=2, column=1, sticky="ew", pady=5)
        buttons = ttk.Frame(body)
        buttons.grid(row=3, column=0, columnspan=2, sticky="w", pady=(10, 10))
        ttk.Button(buttons, text="ASCII 加密", style="Primary.TButton", command=self._encrypt_text).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="密文解密", command=self._decrypt_text).pack(side="left")
        result = ttk.LabelFrame(body, text="结果", style="Section.TLabelframe")
        result.grid(row=4, column=0, columnspan=2, sticky="nsew")
        result.columnconfigure(1, weight=1)
        ttk.Label(result, text="密文显示").grid(row=0, column=0, sticky="nw", padx=(0, 10), pady=6)
        self.text_display_var = tk.StringVar()
        ttk.Label(result, textvariable=self.text_display_var, font=("Consolas", 10), wraplength=700).grid(
            row=0, column=1, sticky="w", pady=6
        )
        ttk.Label(result, text="解密结果").grid(row=1, column=0, sticky="nw", padx=(0, 10), pady=6)
        ttk.Label(result, textvariable=self.text_decrypted_var, font=("Consolas", 10), wraplength=700).grid(
            row=1, column=1, sticky="w", pady=6
        )

    def _encrypt_text(self) -> None:
        try:
            key = parse_hex(self.text_key_var.get(), 16, "密钥")
            ciphertext = ascii_encrypt(self.text_plain_var.get(), key)
            self.text_cipher_var.set(ciphertext.hex().upper())
            self.text_display_var.set(bytes_to_display(ciphertext))
            self.text_decrypted_var.set("")
            self.status_var.set("ASCII 字符串加密完成。")
        except (TypeError, ValueError) as error:
            self._report_error(error)

    def _decrypt_text(self) -> None:
        try:
            key = parse_hex(self.text_key_var.get(), 16, "密钥")
            plaintext = ascii_decrypt(_hex_bytes(self.text_cipher_var.get()), key)
            self.text_decrypted_var.set(plaintext)
            self.status_var.set("ASCII 字符串解密完成。")
        except (TypeError, ValueError) as error:
            self._report_error(error)

    def _build_multi_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=16)
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        notebook.add(tab, text="3. 多重加密")
        self._intro(tab, "KEY COMPOSITION / CASCADE", "在同一 16 bit 分组上组合 E-E、E-E-E、E-D-E 和两密钥 EDE2。")
        body = ttk.Frame(tab)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(1, weight=1)
        self.multi_mode_var = tk.StringVar(value="double")
        self.multi_data_var = tk.StringVar(value="1234")
        self.multi_key1_var = tk.StringVar(value="1A2B")
        self.multi_key2_var = tk.StringVar(value="3C4D")
        self.multi_key3_var = tk.StringVar(value="5E6F")
        ttk.Label(body, text="模式").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=5)
        ttk.Combobox(
            body,
            textvariable=self.multi_mode_var,
            values=("double", "eee", "ede", "ede2"),
            state="readonly",
            width=20,
        ).grid(row=0, column=1, sticky="w", pady=5)
        self._entry(body, 1, "数据（hex）", self.multi_data_var)
        self._entry(body, 2, "K1（hex）", self.multi_key1_var)
        self._entry(body, 3, "K2（hex）", self.multi_key2_var)
        self.multi_key3_entry = self._entry(body, 4, "K3（仅 EEE/EDE）", self.multi_key3_var)
        self.multi_mode_var.trace_add("write", self._update_multi_mode)
        self._update_multi_mode()
        ttk.Label(body, text="结果（hex）").grid(row=5, column=0, sticky="w", padx=(0, 10), pady=5)
        self.multi_output_var = tk.StringVar()
        ttk.Entry(body, textvariable=self.multi_output_var, state="readonly", width=24).grid(
            row=5, column=1, sticky="ew", pady=5
        )
        buttons = ttk.Frame(body)
        buttons.grid(row=6, column=0, columnspan=2, sticky="w", pady=(12, 0))
        ttk.Button(buttons, text="多重加密", style="Primary.TButton", command=self._encrypt_multi).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="多重解密", command=self._decrypt_multi).pack(side="left")

    def _update_multi_mode(self, *_args: str) -> None:
        self.multi_key3_entry.configure(
            state="disabled" if self.multi_mode_var.get() in ("double", "ede2") else "normal"
        )

    def _multi_operation(self, decrypt: bool) -> int:
        mode = self.multi_mode_var.get()
        data = parse_hex(self.multi_data_var.get(), 16, "数据")
        key1 = parse_hex(self.multi_key1_var.get(), 16, "K1")
        key2 = parse_hex(self.multi_key2_var.get(), 16, "K2")
        if mode == "double":
            return double_decrypt(data, key1, key2) if decrypt else double_encrypt(data, key1, key2)
        key3 = None if mode == "ede2" else parse_hex(self.multi_key3_var.get(), 16, "K3")
        return (
            triple_decrypt(data, key1, key2, key3, mode)
            if decrypt
            else triple_encrypt(data, key1, key2, key3, mode)
        )

    def _encrypt_multi(self) -> None:
        try:
            self.multi_output_var.set(format_hex(self._multi_operation(False)))
            self.status_var.set("多重加密完成。")
        except (TypeError, ValueError) as error:
            self._report_error(error)

    def _decrypt_multi(self) -> None:
        try:
            self.multi_output_var.set(format_hex(self._multi_operation(True)))
            self.status_var.set("多重解密完成。")
        except (TypeError, ValueError) as error:
            self._report_error(error)

    def _build_mitm_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=16)
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        notebook.add(tab, text="4. 中间相遇攻击")
        self._intro(tab, "ATTACK LAB / MITM", "输入已知明密文对；程序从两端枚举并用全部样本复核候选密钥。")
        body = ttk.Frame(tab)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(1, weight=1)
        left = ttk.LabelFrame(body, text="已知明密文对", style="Section.TLabelframe")
        left.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, 10))
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self.mitm_pairs_text = tk.Text(
            left,
            height=10,
            width=32,
            font=("Consolas", 10),
            relief="solid",
            borderwidth=1,
            background=COLORS["output"],
            foreground=COLORS["ink"],
            insertbackground=COLORS["accent"],
            selectbackground=COLORS["accent_soft"],
            highlightbackground=COLORS["line"],
            highlightcolor=COLORS["accent"],
            highlightthickness=1,
            padx=10,
            pady=8,
        )
        self.mitm_pairs_text.grid(row=0, column=0, sticky="nsew")
        self.mitm_pairs_text.insert("1.0", "1234 F04D\nBEEF 62E6\nCAFE 8ACE")
        ttk.Label(left, text="默认数据对应 K1=1A2B, K2=3C4D。", style="CardMuted.TLabel").grid(
            row=1, column=0, sticky="w", pady=(8, 0)
        )
        right = ttk.LabelFrame(body, text="攻击结果", style="Section.TLabelframe")
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)
        self.mitm_progress_var = tk.StringVar(value="等待执行")
        ttk.Label(right, textvariable=self.mitm_progress_var, style="CardMuted.TLabel").grid(row=0, column=0, sticky="w")
        self.mitm_output = self._text_output(right, 1, 0, height=10)
        self.mitm_button = ttk.Button(right, text="开始 MITM 搜索", style="Primary.TButton", command=self._run_mitm)
        self.mitm_button.grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.mitm_cancel_button = ttk.Button(right, text="取消搜索", command=self._cancel_mitm, state="disabled")
        self.mitm_cancel_button.grid(row=3, column=0, sticky="w", pady=5)
        paging = ttk.Frame(right)
        paging.grid(row=4, column=0, sticky="ew")
        self.mitm_prev_button = ttk.Button(paging, text="上一页", command=lambda: self._show_mitm_page(-1), state="disabled")
        self.mitm_prev_button.pack(side="left")
        self.mitm_next_button = ttk.Button(paging, text="下一页", command=lambda: self._show_mitm_page(1), state="disabled")
        self.mitm_next_button.pack(side="left")
        self.mitm_page_var = tk.StringVar(value="每页最多 100 个候选")
        ttk.Label(right, textvariable=self.mitm_page_var).grid(row=5, column=0, sticky="w", pady=5)
        self._mitm_candidates: list[tuple[int, int]] = []
        self._mitm_page = 0


    def _read_pairs(self) -> list[tuple[int, int]]:
        pairs: list[tuple[int, int]] = []
        for line in self.mitm_pairs_text.get("1.0", "end").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = [field for field in re.split(r"[\s,:]+", line) if field]
            if len(fields) != 2:
                raise ValueError("每行必须有两个十六进制值：明文和密文")
            pairs.append((parse_hex(fields[0], 16, "明文"), parse_hex(fields[1], 16, "密文")))
        if not pairs:
            raise ValueError("至少输入一个明密文对")
        return pairs

    def _run_mitm(self) -> None:
        try:
            pairs = self._read_pairs()
        except (TypeError, ValueError) as error:
            self._report_error(error)
            return
        self.mitm_button.configure(state="disabled")
        self._write_text(self.mitm_output, "正在搜索 2^16 个 K1 和 2^16 个 K2，请稍候……")
        self.mitm_progress_var.set("初始化")
        self.mitm_prev_button.configure(state="disabled")
        self.mitm_next_button.configure(state="disabled")
        self.mitm_page_var.set("搜索中")

        self._mitm_cancel = threading.Event()
        self._mitm_events = queue.Queue()
        self.mitm_cancel_button.configure(state="normal")
        self.protocol("WM_DELETE_WINDOW", self._close_window)

        def progress(stage: str, current: int, total: int) -> None:
            self._mitm_events.put(("progress", f"{stage} 阶段：{current * 100 // total}%"))

        def worker() -> None:
            try:
                candidates = meet_in_the_middle(
                    pairs, progress=progress, cancelled=self._mitm_cancel.is_set
                )
                self._mitm_events.put(("done", candidates))
            except CancelledError:
                self._mitm_events.put(("cancelled", "搜索已取消；未返回完整候选列表。"))
            except Exception as error:
                self._mitm_events.put(("error", str(error)))

        threading.Thread(target=worker, daemon=True).start()
        self.after(50, self._poll_mitm)

    def _close_window(self) -> None:
        self._mitm_cancel.set()
        self.destroy()

    def _cancel_mitm(self) -> None:
        self._mitm_cancel.set()
        self.mitm_cancel_button.configure(state="disabled")

    def _poll_mitm(self) -> None:
        # Only the Tk thread touches widgets; the worker communicates via a queue.
        try:
            while True:
                kind, payload = self._mitm_events.get_nowait()
                if kind == "progress":
                    self.mitm_progress_var.set(payload)
                    continue
                self.mitm_button.configure(state="normal")
                self.mitm_cancel_button.configure(state="disabled")
                if kind == "done":
                    self._mitm_candidates = payload
                    self._mitm_page = 0
                    self._show_mitm_page()
                    self.mitm_progress_var.set(f"完成：{len(payload)} 个候选")
                    self.status_var.set("搜索完成；候选密钥仍应使用其他明密文对复核。")
                else:
                    self._write_text(self.mitm_output, payload)
                    self.mitm_progress_var.set("已取消" if kind == "cancelled" else "搜索失败")
                    self.status_var.set(payload)
                return
        except queue.Empty:
            self.after(50, self._poll_mitm)

    def _show_mitm_page(self, delta: int = 0) -> None:
        candidates = self._mitm_candidates
        pages = max(1, (len(candidates) + 99) // 100)
        self._mitm_page = min(max(0, self._mitm_page + delta), pages - 1)
        start = self._mitm_page * 100
        result = "\n".join(
            f"K1={format_hex(key1)}  K2={format_hex(key2)}"
            for key1, key2 in candidates[start:start + 100]
        )
        self._write_text(self.mitm_output, result or "没有找到满足全部明密文对的密钥对。")
        self.mitm_page_var.set(f"第 {self._mitm_page + 1}/{pages} 页 · 共 {len(candidates)} 个")
        self.mitm_prev_button.configure(state="normal" if self._mitm_page else "disabled")
        self.mitm_next_button.configure(state="normal" if self._mitm_page + 1 < pages else "disabled")

    def _build_cbc_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=16)
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        notebook.add(tab, text="5. CBC 模式")
        self._intro(tab, "MODE LAB / CBC", "共享 16 bit IV，观察链式分组和密文 XOR 篡改造成的明文变化。")
        body = ttk.Frame(tab)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(1, weight=1)
        body.rowconfigure(8, weight=1)
        self.cbc_plain_var = tk.StringVar(value="CBC tamper demonstration")
        self.cbc_key_var = tk.StringVar(value="4AF5")
        self.cbc_iv_var = tk.StringVar(value="1234")
        self.cbc_cipher_var = tk.StringVar()
        self.cbc_tampered_var = tk.StringVar()
        self.cbc_index_var = tk.StringVar(value="0")
        self.cbc_mask_var = tk.StringVar(value="0001")
        self.cbc_original_var = tk.StringVar()
        self.cbc_modified_var = tk.StringVar()
        self._entry(body, 0, "ASCII 明文", self.cbc_plain_var, 50)
        self._entry(body, 1, "密钥（hex）", self.cbc_key_var)
        iv_frame = ttk.Frame(body)
        iv_frame.grid(row=2, column=1, sticky="ew", pady=5)
        iv_frame.columnconfigure(0, weight=1)
        ttk.Label(body, text="IV（hex）").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=5)
        ttk.Entry(iv_frame, textvariable=self.cbc_iv_var, width=24).grid(row=0, column=0, sticky="w")
        ttk.Button(iv_frame, text="随机生成", command=self._random_iv).grid(row=0, column=1, padx=(8, 0))
        ttk.Label(body, text="原始密文（hex）").grid(row=3, column=0, sticky="w", padx=(0, 10), pady=5)
        ttk.Entry(body, textvariable=self.cbc_cipher_var, width=70).grid(row=3, column=1, sticky="ew", pady=5)
        tamper_frame = ttk.Frame(body)
        tamper_frame.grid(row=4, column=1, sticky="w", pady=5)
        ttk.Label(body, text="篡改参数").grid(row=4, column=0, sticky="w", padx=(0, 10), pady=5)
        ttk.Label(tamper_frame, text="分组索引（0-based）").pack(side="left")
        ttk.Entry(tamper_frame, textvariable=self.cbc_index_var, width=6).pack(side="left", padx=(5, 12))
        ttk.Label(tamper_frame, text="XOR mask").pack(side="left")
        ttk.Entry(tamper_frame, textvariable=self.cbc_mask_var, width=8).pack(side="left", padx=(5, 0))
        ttk.Label(body, text="篡改后密文（hex）").grid(row=5, column=0, sticky="w", padx=(0, 10), pady=5)
        ttk.Entry(body, textvariable=self.cbc_tampered_var, state="readonly", width=70).grid(
            row=5, column=1, sticky="ew", pady=5
        )
        buttons = ttk.Frame(body)
        buttons.grid(row=6, column=0, columnspan=2, sticky="w", pady=(10, 10))
        ttk.Button(buttons, text="加密并生成篡改样本", style="Primary.TButton", command=self._encrypt_cbc).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="比较解密结果", command=self._compare_cbc).pack(side="left")
        result = ttk.LabelFrame(body, text="篡改前后对比", style="Section.TLabelframe")
        result.grid(row=8, column=0, columnspan=2, sticky="nsew")
        result.columnconfigure(1, weight=1)
        ttk.Label(result, text="原始解密").grid(row=0, column=0, sticky="nw", padx=(0, 10), pady=6)
        ttk.Label(result, textvariable=self.cbc_original_var, font=("Consolas", 10), wraplength=700).grid(
            row=0, column=1, sticky="w", pady=6
        )
        ttk.Label(result, text="篡改解密").grid(row=1, column=0, sticky="nw", padx=(0, 10), pady=6)
        ttk.Label(result, textvariable=self.cbc_modified_var, font=("Consolas", 10), wraplength=700).grid(
            row=1, column=1, sticky="w", pady=6
        )

    def _random_iv(self) -> None:
        self.cbc_iv_var.set(format_hex(secrets.randbits(16)))
        self.status_var.set("已生成新的 16 bit IV；请将它与密文一起共享给解密方。")

    def _cbc_values(self) -> tuple[int, int, bytes]:
        key = parse_hex(self.cbc_key_var.get(), 16, "密钥")
        iv = parse_hex(self.cbc_iv_var.get(), 16, "IV")
        ciphertext = _hex_bytes(self.cbc_cipher_var.get())
        return key, iv, ciphertext

    def _clear_cbc_results(self) -> None:
        self.cbc_tampered_var.set("")
        self.cbc_original_var.set("")
        self.cbc_modified_var.set("")

    def _encrypt_cbc(self) -> None:
        self._clear_cbc_results()
        self.cbc_cipher_var.set("")
        try:
            key = parse_hex(self.cbc_key_var.get(), 16, "密钥")
            iv = parse_hex(self.cbc_iv_var.get(), 16, "IV")
            ciphertext = cbc_encrypt(self.cbc_plain_var.get().encode("ascii"), key, iv)
            modified = self._tamper_cbc_ciphertext(ciphertext)
            # Publish both ciphertexts only after all input validation succeeds.
            self.cbc_cipher_var.set(ciphertext.hex().upper())
            self.cbc_tampered_var.set(modified.hex().upper())
            self.status_var.set("CBC 加密和篡改样本生成完成。")
        except (TypeError, ValueError, UnicodeEncodeError) as error:
            self._report_error(error)

    def _tamper_cbc_ciphertext(self, ciphertext: bytes) -> bytes:
        index = int(self.cbc_index_var.get())
        mask = parse_hex(self.cbc_mask_var.get(), 16, "XOR mask")
        return tamper_ciphertext(ciphertext, index, mask)

    def _compare_cbc(self) -> None:
        self._clear_cbc_results()
        try:
            key, iv, ciphertext = self._cbc_values()
            modified = self._tamper_cbc_ciphertext(ciphertext)
            original = cbc_decrypt(ciphertext, key, iv)
            try:
                changed = cbc_decrypt(modified, key, iv)
                changed_display = bytes_to_display(changed)
            except ValueError as error:
                changed_display = f"解密失败（篡改破坏了填充）：{error}"
            self.cbc_tampered_var.set(modified.hex().upper())
            self.cbc_original_var.set(bytes_to_display(original))
            self.cbc_modified_var.set(changed_display)
            self.status_var.set("CBC 原始/篡改密文对比完成。")
        except (TypeError, ValueError) as error:
            self._report_error(error)


def main() -> None:
    application = SaesApplication()
    application.mainloop()


if __name__ == "__main__":
    main()
