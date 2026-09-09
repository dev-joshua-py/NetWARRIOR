#!/usr/bin/env python3
"""
NetWARRIOR — Desktop GUI
========================

A Tkinter front-end for the NetWARRIOR async network-security testing suite.

This module does NOT reimplement any attack, recon, pentest, payload, report,
safety-rail or audit-log logic. It drives the *exact* same command dispatcher
the terminal UI uses (``UI._process_command``) on a background asyncio event
loop, so every capability of ``netwarrior.py`` — and every guard rail
(``safe_mode``, scope allowlist, authorization gate, audit trail, pps clamp) —
behaves identically whether you run the CLI or this GUI. The attack catalog, the
recon/pentest command set and the payload generators are all pulled straight
from ``netwarrior`` so the two can never drift apart.

Usage
-----
    python netwarrior_gui.py [--safe] [--scope CIDR ...] [--iface NAME]
                             [--yes] [--no-audit]

The command-line flags mean exactly what they mean for ``netwarrior.py``.
Requires the same dependencies as the CLI, plus Tk (bundled with CPython).

Legal: authorized penetration testing / security research / education only.
See DISCLAIMER.md. The first run asks you to acknowledge authorization before
the engine will accept any target — the same gate the CLI enforces.
"""

from __future__ import annotations

import asyncio
import queue
import re
import threading
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, scrolledtext, ttk

# The GUI is a thin shell over the real tool. Importing it runs its dependency
# check; a missing package prints the same install hint the CLI shows and exits.
import netwarrior as nw
from netwarrior import (
    _ACK_NOTICE,
    _ACK_PHRASE,
    ATTACK_BY_KEY,
    ATTACK_CATALOG,
    ATTACK_CATEGORY_COLOR,
    ATTACK_REDIRECT,
    UI,
    AttackEngine,
    AttackRegistry,
    AuditLog,
    Config,
    LogBus,
    NetworkContext,
    Utils,
    __version__,
    _parse_args,
    _safe_save,
)

# ──────────────────────────────────────────────────────────────────────────────
# Theme  –  dark, cyan/red accents to echo the terminal UI
# ──────────────────────────────────────────────────────────────────────────────
BG      = "#0d1117"   # window background
PANEL   = "#161b22"   # raised panels / inputs
PANEL2  = "#1c2330"   # alt rows
BORDER  = "#30363d"
FG      = "#c9d1d9"   # primary text
MUTED   = "#8b949e"   # secondary text
ACCENT  = "#22d3ee"   # cyan (structure / active)
RED     = "#ff6b6b"   # attack / error
GREEN   = "#3fb950"   # success
YELLOW  = "#e3b341"   # warning
BLUE    = "#6cb6ff"   # info
MAGENTA = "#d2a8ff"

# Category accent (rich colour name -> hex) so the attack list is colour-coded
# the same way the terminal menu is.
_CAT_HEX = {
    "bright_red": RED, "red": "#e5534b", "bright_yellow": YELLOW,
    "bright_magenta": MAGENTA, "bright_blue": BLUE, "magenta": "#c678dd",
    "bright_cyan": ACCENT, "cyan": "#39c5cf", "green": GREEN,
    "bright_green": "#56d364", "yellow": "#d4a72c",
}


def _cat_color(category: str) -> str:
    return _CAT_HEX.get(ATTACK_CATEGORY_COLOR.get(category, "cyan"), ACCENT)


# ──────────────────────────────────────────────────────────────────────────────
# Rich-markup → plain text + level
#
# ``_process_command`` returns strings that may carry a few Rich style tags
# (e.g. ``[green]…[/]``). The terminal UI shows them literally; here we strip the
# known tags and use the first one to colour the console line. The whitelist is
# deliberate so bracketed data like a port list ``[80, 443]`` is left untouched.
# ──────────────────────────────────────────────────────────────────────────────
_STYLES = (r"(?:red|green|yellow|dim|cyan|magenta|blue|white|"
           r"bright_[a-z_]+|grey\d+|bold(?:\s+[a-z_]+)*)")
# A bare/named closing tag ([/] or [/green]) or a named opening tag ([green]).
# The opening form requires a known style name, so bracketed *data* such as a
# port list "[80, 443]" is never mistaken for markup and stripped.
_TAG_RE = re.compile(rf"\[/{_STYLES}?\]|\[{_STYLES}\]")
_LEVEL_BY_COLOR = {
    "red": "err", "green": "ok", "yellow": "warn",
    "cyan": "info", "blue": "info", "magenta": "info",
}


def render_output(text: str) -> tuple[str, str]:
    """Return ``(clean_text, level)`` for a ``_process_command`` result string."""
    if not text:
        return "", "plain"
    m = re.search(r"\[(red|green|yellow|cyan|blue|magenta)\]", text)
    level = _LEVEL_BY_COLOR.get(m.group(1), "plain") if m else "plain"
    return _TAG_RE.sub("", text), level


# ──────────────────────────────────────────────────────────────────────────────
# AsyncCore  –  hosts the real tool on a background event loop
# ──────────────────────────────────────────────────────────────────────────────
class AsyncCore:
    """
    Owns a dedicated asyncio event loop on a background thread and builds the
    genuine NetWARRIOR object graph inside it (``AttackEngine`` must be created
    with a running loop). The GUI thread submits commands with
    ``run_coroutine_threadsafe`` and observes the thread-safe registry/log.
    """

    def __init__(self, argv=None):
        self.args = _parse_args(argv if argv is not None else [])
        self.config = Config()
        # Apply the same CLI overrides main() applies.
        if self.args.safe:
            self.config.safe_mode = True
        if self.args.scope:
            self.config.scope = list(self.args.scope)
        if self.args.iface:
            self.config.interface = self.args.iface
        if self.args.no_audit:
            self.config.audit_log = False
        if self.args.yes:                       # skip the first-run auth gate
            self.config.authorized = True

        self.loop: asyncio.AbstractEventLoop | None = None
        self.ui: UI | None = None
        self.net = self.registry = self.log = self.engine = self.audit = None
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._err: BaseException | None = None

    # ---- lifecycle -----------------------------------------------------------
    @property
    def authorized(self) -> bool:
        return bool(self.config.authorized) or not self.config.require_ack

    def authorize(self) -> None:
        self.config.authorized = True
        _safe_save(self.config)

    def start(self, timeout: float = 15.0) -> None:
        self._thread = threading.Thread(
            target=self._thread_main, name="netwarrior-loop", daemon=True
        )
        self._thread.start()
        if not self._ready.wait(timeout):
            raise RuntimeError("engine did not start in time")
        if self._err:
            raise self._err

    def _thread_main(self) -> None:
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self._init())
        except BaseException as e:            # surface init failures to start()
            self._err = e
            self._ready.set()
            return
        self._ready.set()
        try:
            self.loop.run_forever()
        finally:
            self.loop.close()

    async def _init(self) -> None:
        cfg = self.config
        self.net = NetworkContext()
        self.registry = AttackRegistry()
        self.log = LogBus()
        self.audit = AuditLog(cfg)
        self.audit.record(
            "session.start", version=__version__, safe_mode=cfg.safe_mode,
            scope=cfg.scope or None, interface=cfg.interface, ui="gui",
        )
        self.engine = AttackEngine(cfg, self.registry, self.log, self.net)
        self.ui = UI(cfg, self.net, self.registry, self.log, self.engine, self.audit)
        if cfg.safe_mode:
            self.log.add("safe_mode ON — spoofing disabled, reserved targets blocked", tag="SAFE")
        if cfg.scope:
            self.log.add(f"scope: {', '.join(cfg.scope)}", tag="SAFE")
        self.log.add(f"NetWARRIOR {__version__} GUI ready", tag="INIT")

    # ---- command submission --------------------------------------------------
    def run_command(self, cmd: str, on_done) -> None:
        """Dispatch a command on the loop; ``on_done(output)`` runs on the loop
        thread — the caller is responsible for marshalling back to Tk."""
        if not self.loop:
            on_done("[red]Engine not ready[/]")
            return
        fut = asyncio.run_coroutine_threadsafe(self._dispatch(cmd), self.loop)

        def _cb(f):
            try:
                on_done(f.result())
            except Exception as e:            # noqa: BLE001 - report, don't crash
                on_done(f"[red]Error: {e}[/]")

        fut.add_done_callback(_cb)

    async def _dispatch(self, cmd: str) -> str:
        # _process_command sets self.cmd_output as its final, await-free step,
        # so reading it right after the await yields exactly this command's output.
        await self.ui._process_command(cmd)
        return self.ui.cmd_output

    def stop_all(self) -> None:
        if self.loop and self.ui:
            self.loop.call_soon_threadsafe(self.ui._stop_attacks)

    def shutdown(self) -> None:
        if not self.loop:
            return
        try:
            if self.ui:
                fut = asyncio.run_coroutine_threadsafe(self.ui._shutdown(), self.loop)
                fut.result(timeout=5)
        except Exception:
            pass
        try:
            if self.audit and self.registry:
                self.audit.record("session.end", packets=self.registry.total_packets())
        except Exception:
            pass
        self.loop.call_soon_threadsafe(self.loop.stop)


# ──────────────────────────────────────────────────────────────────────────────
# Small reusable form helper
# ──────────────────────────────────────────────────────────────────────────────
class Field:
    """A labelled entry that lives in a grid, with an optional default."""

    def __init__(self, parent, row, label, default="", width=24, show=None):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=4)
        self.var = tk.StringVar(value=default)
        self.entry = ttk.Entry(parent, textvariable=self.var, width=width, show=show)
        self.entry.grid(row=row, column=1, sticky="ew", pady=4)

    def get(self) -> str:
        return self.var.get().strip()

    def set(self, v) -> None:
        self.var.set(v)


# ──────────────────────────────────────────────────────────────────────────────
# The application
# ──────────────────────────────────────────────────────────────────────────────
class NetWarriorGUI:
    def __init__(self, root: tk.Tk, core: AsyncCore):
        self.root = root
        self.core = core
        self.msg_q: queue.Queue[tuple[str, str]] = queue.Queue()
        self._last_log = None
        self._active_rows: dict = {}

        root.title(f"NetWARRIOR {__version__}")
        root.geometry("1180x760")
        root.minsize(940, 620)
        root.configure(bg=BG)

        self._init_fonts()
        self._init_style()
        self._build_menubar()
        self._build_header()
        self._build_body()
        self._build_statusbar()

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._pump()       # drain console messages
        self._refresh()    # live stats / logs / active table

    # ---- fonts & ttk style ---------------------------------------------------
    def _init_fonts(self):
        fam_mono = "Consolas"
        fam_ui = "Segoe UI"
        self.f_ui = tkfont.Font(family=fam_ui, size=10)
        self.f_ui_b = tkfont.Font(family=fam_ui, size=10, weight="bold")
        self.f_logo = tkfont.Font(family=fam_mono, size=17, weight="bold")
        self.f_sub = tkfont.Font(family=fam_ui, size=9)
        self.f_mono = tkfont.Font(family=fam_mono, size=10)
        self.f_mono_s = tkfont.Font(family=fam_mono, size=9)

    def _init_style(self):
        st = ttk.Style(self.root)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=BG, foreground=FG, fieldbackground=PANEL,
                     bordercolor=BORDER, font=self.f_ui)
        st.configure("TFrame", background=BG)
        st.configure("Panel.TFrame", background=PANEL)
        st.configure("Header.TFrame", background=PANEL)
        st.configure("TLabel", background=BG, foreground=FG)
        st.configure("Panel.TLabel", background=PANEL, foreground=FG)
        st.configure("Muted.TLabel", background=BG, foreground=MUTED, font=self.f_sub)
        st.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED, font=self.f_sub)
        st.configure("Logo.TLabel", background=PANEL, foreground=ACCENT, font=self.f_logo)
        st.configure("Stat.TLabel", background=PANEL, foreground=ACCENT, font=self.f_ui_b)
        st.configure("StatVal.TLabel", background=PANEL, foreground=FG, font=self.f_ui_b)
        st.configure("Heading.TLabel", background=BG, foreground=FG, font=self.f_ui_b)

        st.configure("TButton", background=PANEL2, foreground=FG, borderwidth=1,
                     focusthickness=1, padding=(10, 5))
        st.map("TButton",
               background=[("active", BORDER), ("pressed", BORDER)],
               foreground=[("disabled", MUTED)])
        st.configure("Accent.TButton", background=ACCENT, foreground="#08131a",
                     font=self.f_ui_b)
        st.map("Accent.TButton", background=[("active", "#4de1f2"), ("pressed", "#1aa5bd")])
        st.configure("Danger.TButton", background=RED, foreground="#1a0000",
                     font=self.f_ui_b)
        st.map("Danger.TButton", background=[("active", "#ff8888"), ("pressed", "#d64545")])

        st.configure("TEntry", fieldbackground=PANEL, foreground=FG,
                     insertcolor=ACCENT, bordercolor=BORDER, padding=3)
        st.configure("TCombobox", fieldbackground=PANEL, background=PANEL2,
                     foreground=FG, arrowcolor=ACCENT, padding=3)
        st.map("TCombobox", fieldbackground=[("readonly", PANEL)],
               foreground=[("readonly", FG)])
        st.configure("TCheckbutton", background=BG, foreground=FG)
        st.map("TCheckbutton", background=[("active", BG)])
        st.configure("Panel.TCheckbutton", background=PANEL, foreground=FG)
        st.map("Panel.TCheckbutton", background=[("active", PANEL)])

        st.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(4, 4, 4, 0))
        st.configure("TNotebook.Tab", background=PANEL, foreground=MUTED,
                     padding=(14, 7), font=self.f_ui)
        st.map("TNotebook.Tab",
               background=[("selected", BG)],
               foreground=[("selected", ACCENT)])

        st.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                     foreground=FG, borderwidth=0, rowheight=22, font=self.f_mono_s)
        st.configure("Treeview.Heading", background=PANEL2, foreground=ACCENT,
                     font=self.f_ui_b, relief="flat")
        st.map("Treeview", background=[("selected", "#243244")],
               foreground=[("selected", "#ffffff")])
        st.configure("TPanedwindow", background=BG)
        st.configure("TLabelframe", background=BG, foreground=ACCENT, bordercolor=BORDER)
        st.configure("TLabelframe.Label", background=BG, foreground=ACCENT, font=self.f_ui_b)

    # ---- menu bar ------------------------------------------------------------
    def _build_menubar(self):
        m = tk.Menu(self.root, tearoff=0, bg=PANEL, fg=FG, activebackground=BORDER,
                    activeforeground=ACCENT)
        filem = tk.Menu(m, tearoff=0, bg=PANEL, fg=FG, activebackground=BORDER,
                        activeforeground=ACCENT)
        filem.add_command(label="Save HTML report", command=lambda: self.submit("report save"))
        filem.add_command(label="Save settings", command=self._save_settings)
        filem.add_separator()
        filem.add_command(label="Quit", command=self._on_close)
        m.add_cascade(label="File", menu=filem)

        helpm = tk.Menu(m, tearoff=0, bg=PANEL, fg=FG, activebackground=BORDER,
                        activeforeground=ACCENT)
        helpm.add_command(label="Authorization notice", command=self._show_notice)
        helpm.add_command(label="Command reference", command=self._show_help)
        helpm.add_command(label="About", command=self._show_about)
        m.add_cascade(label="Help", menu=helpm)
        self.root.config(menu=m)

    # ---- header --------------------------------------------------------------
    def _build_header(self):
        hdr = ttk.Frame(self.root, style="Header.TFrame", padding=(14, 10))
        hdr.pack(side="top", fill="x")
        hdr.columnconfigure(1, weight=1)

        left = ttk.Frame(hdr, style="Header.TFrame")
        left.grid(row=0, column=0, sticky="w")
        ttk.Label(left, text="NetWARRIOR", style="Logo.TLabel").pack(side="left")
        ttk.Label(left, text=f"  v{__version__}  ·  network security testing suite",
                  style="PanelMuted.TLabel").pack(side="left", padx=(2, 0))

        # live stat strip (center)
        stats = ttk.Frame(hdr, style="Header.TFrame")
        stats.grid(row=0, column=1, sticky="e", padx=12)
        self.stat_vars = {k: tk.StringVar(value="—") for k in
                          ("ip", "iface", "pkts", "traf", "active")}
        for label, key in (("IP", "ip"), ("IFACE", "iface"), ("PKTS", "pkts"),
                           ("TRAFFIC", "traf"), ("ACTIVE", "active")):
            cell = ttk.Frame(stats, style="Header.TFrame")
            cell.pack(side="left", padx=9)
            ttk.Label(cell, text=label, style="Stat.TLabel").pack(anchor="e")
            ttk.Label(cell, textvariable=self.stat_vars[key],
                      style="StatVal.TLabel").pack(anchor="e")

        # controls (right)
        right = ttk.Frame(hdr, style="Header.TFrame")
        right.grid(row=0, column=2, sticky="e")
        self.safe_var = tk.BooleanVar(value=bool(self.core.config.safe_mode))
        self.safe_chk = ttk.Checkbutton(
            right, text="SAFE MODE", style="Panel.TCheckbutton",
            variable=self.safe_var, command=self._toggle_safe)
        self.safe_chk.pack(side="left", padx=(0, 10))
        ttk.Button(right, text="STOP ALL", style="Danger.TButton",
                   command=self._stop_all).pack(side="left")

        sep = tk.Frame(self.root, bg=BORDER, height=1)
        sep.pack(side="top", fill="x")

    # ---- body ----------------------------------------------------------------
    def _build_body(self):
        outer = ttk.Panedwindow(self.root, orient="horizontal")
        outer.pack(side="top", fill="both", expand=True, padx=8, pady=8)

        # left: control notebook
        left = ttk.Frame(outer)
        outer.add(left, weight=3)
        self.nb = ttk.Notebook(left)
        self.nb.pack(fill="both", expand=True)
        self._build_tab_attacks()
        self._build_tab_recon()
        self._build_tab_pentest()
        self._build_tab_payloads()
        self._build_tab_report()
        self._build_tab_settings()

        # right: live panels
        right = ttk.Panedwindow(outer, orient="vertical")
        outer.add(right, weight=4)

        # active attacks
        act = ttk.Labelframe(right, text="Active attacks", padding=6)
        right.add(act, weight=1)
        cols = ("state", "pkts", "bytes", "err", "dur")
        self.active_tree = ttk.Treeview(act, columns=cols, show="tree headings", height=5)
        self.active_tree.heading("#0", text="name")
        self.active_tree.column("#0", width=190, anchor="w")
        for c, txt, w in (("state", "state", 70), ("pkts", "packets", 80),
                          ("bytes", "traffic", 80), ("err", "err", 50),
                          ("dur", "dur", 60)):
            self.active_tree.heading(c, text=txt)
            self.active_tree.column(c, width=w, anchor="e")
        self.active_tree.tag_configure("run", foreground=GREEN)
        self.active_tree.tag_configure("done", foreground=MUTED)
        self.active_tree.pack(side="left", fill="both", expand=True)
        asb = ttk.Scrollbar(act, orient="vertical", command=self.active_tree.yview)
        asb.pack(side="right", fill="y")
        self.active_tree.configure(yscrollcommand=asb.set)

        # output console
        outf = ttk.Labelframe(right, text="Output", padding=(6, 4))
        right.add(outf, weight=3)
        self.console = scrolledtext.ScrolledText(
            outf, wrap="word", bg="#0a0e14", fg=FG, insertbackground=ACCENT,
            font=self.f_mono, relief="flat", borderwidth=0, height=12,
            padx=8, pady=6, state="disabled")
        self.console.pack(fill="both", expand=True)
        for tag, col in (("ok", GREEN), ("err", RED), ("warn", YELLOW),
                         ("info", BLUE), ("plain", FG), ("cmd", ACCENT),
                         ("dim", MUTED)):
            self.console.tag_configure(tag, foreground=col)
        self.console.tag_configure("cmd", foreground=ACCENT, font=self.f_mono)

        # command entry (full parity: any CLI command works here)
        cmdrow = ttk.Frame(outf)
        cmdrow.pack(fill="x", pady=(6, 0))
        ttk.Label(cmdrow, text=">>", style="TLabel",
                  foreground=ACCENT, font=self.f_mono).pack(side="left", padx=(0, 6))
        self.cmd_var = tk.StringVar()
        e = ttk.Entry(cmdrow, textvariable=self.cmd_var, font=self.f_mono)
        e.pack(side="left", fill="x", expand=True)
        e.bind("<Return>", self._on_cmd_enter)
        ttk.Button(cmdrow, text="Run", command=self._on_cmd_enter).pack(side="left", padx=(6, 0))

        # logs
        logf = ttk.Labelframe(right, text="Log", padding=(6, 4))
        right.add(logf, weight=2)
        self.logbox = scrolledtext.ScrolledText(
            logf, wrap="none", bg="#0a0e14", fg=MUTED, font=self.f_mono_s,
            relief="flat", borderwidth=0, height=8, padx=8, pady=4, state="disabled")
        self.logbox.pack(fill="both", expand=True)
        self.logbox.tag_configure("ts", foreground="#5c6773")
        self.logbox.tag_configure("tag", foreground=ACCENT)
        self.logbox.tag_configure("ok", foreground=GREEN)
        self.logbox.tag_configure("error", foreground=RED)
        self.logbox.tag_configure("warn", foreground=YELLOW)
        self.logbox.tag_configure("info", foreground=FG)

    # ---- status bar ----------------------------------------------------------
    def _build_statusbar(self):
        sep = tk.Frame(self.root, bg=BORDER, height=1)
        sep.pack(side="bottom", fill="x")
        bar = ttk.Frame(self.root, style="Header.TFrame", padding=(12, 4))
        bar.pack(side="bottom", fill="x")
        cfg = self.core.config
        mode = "SAFE MODE" if cfg.safe_mode else "LIVE"
        scope = f"scope: {', '.join(cfg.scope)}" if cfg.scope else "scope: unrestricted"
        self.status_var = tk.StringVar(
            value=f"Authorized for testing only · {mode} · {scope} · "
                  f"type a command in the >> box, or use the tabs")
        ttk.Label(bar, textvariable=self.status_var, style="PanelMuted.TLabel"
                  ).pack(side="left")

    # ---- tab: attacks --------------------------------------------------------
    def _build_tab_attacks(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="  Attacks  ")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(0, weight=1)

        # catalog tree grouped by category
        treef = ttk.Frame(tab)
        treef.grid(row=0, column=0, sticky="nsew")
        self.atk_tree = ttk.Treeview(treef, show="tree", selectmode="browse", height=14)
        self.atk_tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(treef, orient="vertical", command=self.atk_tree.yview)
        sb.pack(side="right", fill="y")
        self.atk_tree.configure(yscrollcommand=sb.set)

        cat_labels = {
            "flood": "Volumetric floods", "amp": "Reflection / amplification",
            "app": "Application layer", "l2": "Layer 2 / LAN",
            "ipv6": "IPv6 neighbor discovery", "poison": "Name-resolution poisoning",
            "wifi": "Wireless", "recon": "Recon / discovery / replay",
            "monitor": "Monitoring", "tool": "External tools", "social": "Social engineering",
        }
        self._atk_by_iid: dict[str, str] = {}
        seen: dict[str, str] = {}
        for spec in ATTACK_CATALOG:
            if spec.category not in seen:
                pid = self.atk_tree.insert(
                    "", "end", text=cat_labels.get(spec.category, spec.category),
                    open=spec.category in ("flood", "app", "recon"))
                self.atk_tree.item(pid, tags=("cat",))
                seen[spec.category] = pid
            iid = self.atk_tree.insert(
                seen[spec.category], "end",
                text=f"{spec.key:<12}  {spec.desc}", tags=(spec.category,))
            self._atk_by_iid[iid] = spec.key
        self.atk_tree.tag_configure("cat", foreground=ACCENT, font=self.f_ui_b)
        for cat in seen:
            self.atk_tree.tag_configure(cat, foreground=_cat_color(cat))
        self.atk_tree.bind("<<TreeviewSelect>>", self._on_atk_select)

        # form
        form = ttk.Frame(tab, padding=(0, 12, 0, 0))
        form.grid(row=1, column=0, sticky="ew")
        form.columnconfigure(1, weight=1)
        self.atk_desc = tk.StringVar(value="Select an attack from the catalog above.")
        ttk.Label(form, textvariable=self.atk_desc, style="Heading.TLabel",
                  wraplength=430, justify="left").grid(row=0, column=0, columnspan=2,
                                                       sticky="w", pady=(0, 2))
        self.atk_hint = tk.StringVar(value="")
        ttk.Label(form, textvariable=self.atk_hint, style="Muted.TLabel",
                  wraplength=430, justify="left").grid(row=1, column=0, columnspan=2,
                                                       sticky="w", pady=(0, 8))
        self.f_target = Field(form, 2, "Target / BSSID / URL", "")
        self.f_port = Field(form, 3, "Port", "80", width=10)
        self.f_dur = Field(form, 4, "Duration (s)", "30", width=10)
        self.f_pps = Field(form, 5, "Packets / sec", "1000", width=10)

        btns = ttk.Frame(form)
        btns.grid(row=6, column=0, columnspan=2, sticky="w", pady=(12, 0))
        self.launch_btn = ttk.Button(btns, text="Launch attack", style="Accent.TButton",
                                     command=self._launch_attack, state="disabled")
        self.launch_btn.pack(side="left")
        ttk.Button(btns, text="Stop all", style="Danger.TButton",
                   command=self._stop_all).pack(side="left", padx=(8, 0))
        self._selected_atk = None

    def _on_atk_select(self, _evt=None):
        sel = self.atk_tree.selection()
        if not sel or sel[0] not in self._atk_by_iid:
            self._selected_atk = None
            self.launch_btn.configure(state="disabled")
            return
        key = self._atk_by_iid[sel[0]]
        spec = ATTACK_BY_KEY[key]
        self._selected_atk = key
        tgt = "requires a target" if spec.needs_target else "no target needed"
        self.atk_desc.set(f"{spec.key} — {spec.desc}")
        self.atk_hint.set(f"attack {spec.key} {spec.args}    ({tgt}; '_' skips a slot)")
        self.launch_btn.configure(state="normal")

    def _launch_attack(self):
        if not self._selected_atk:
            return
        key = self._selected_atk
        spec = ATTACK_BY_KEY[key]
        target = self.f_target.get()
        if spec.needs_target and not target:
            messagebox.showwarning("Target required",
                                   f"The '{key}' attack needs a target.")
            return
        # Positional command mirrors the CLI; '_' preserves later slots when a
        # field is blank (exactly the convention the ATTACK menu documents).
        parts = ["attack", key,
                 target or "_",
                 self.f_port.get() or "_",
                 self.f_dur.get() or "_",
                 self.f_pps.get() or "_"]
        self.submit(" ".join(parts))

    # ---- tab: recon ----------------------------------------------------------
    def _build_tab_recon(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="  Recon  ")
        tab.columnconfigure(0, weight=1)

        f1 = ttk.Labelframe(tab, text="Scan", padding=10)
        f1.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        f1.columnconfigure(1, weight=1)
        self.rc_scan = Field(f1, 0, "Host or CIDR", "")
        ttk.Label(f1, text="An IP runs a port scan; a CIDR maps the network.",
                  style="Muted.TLabel").grid(row=1, column=0, columnspan=2, sticky="w")
        ttk.Button(f1, text="Scan", style="Accent.TButton",
                   command=lambda: self._need(self.rc_scan, "scan {}")
                   ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))

        f2 = ttk.Labelframe(tab, text="Fingerprint & vuln", padding=10)
        f2.grid(row=1, column=0, sticky="ew", pady=8)
        f2.columnconfigure(1, weight=1)
        self.rc_fp = Field(f2, 0, "Host", "")
        row = ttk.Frame(f2)
        row.grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Button(row, text="Fingerprint",
                   command=lambda: self._need(self.rc_fp, "fingerprint {}")).pack(side="left")
        ttk.Button(row, text="Vuln scan",
                   command=lambda: self._need(self.rc_fp, "vuln {}")).pack(side="left", padx=(8, 0))

        f3 = ttk.Labelframe(tab, text="DNS", padding=10)
        f3.grid(row=2, column=0, sticky="ew", pady=8)
        f3.columnconfigure(1, weight=1)
        self.rc_dns = Field(f3, 0, "Domain", "")
        self.rc_rtype = Field(f3, 1, "Record type", "A", width=10)
        self.rc_ns = Field(f3, 2, "Nameserver (zone xfer)", "")
        row3 = ttk.Frame(f3)
        row3.grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Button(row3, text="Lookup", command=self._dns_lookup).pack(side="left")
        ttk.Button(row3, text="Reverse (IP)",
                   command=lambda: self._need(self.rc_dns, "dnsrev {}")).pack(side="left", padx=(8, 0))
        ttk.Button(row3, text="Zone transfer", command=self._zone).pack(side="left", padx=(8, 0))

    def _dns_lookup(self):
        d = self.rc_dns.get()
        if not d:
            return self._warn("Enter a domain.")
        rt = self.rc_rtype.get() or "A"
        self.submit(f"dns {d} {rt}")

    def _zone(self):
        d, ns = self.rc_dns.get(), self.rc_ns.get()
        if not d or not ns:
            return self._warn("Zone transfer needs a domain and a nameserver.")
        self.submit(f"zone {d} {ns}")

    # ---- tab: pentest --------------------------------------------------------
    def _build_tab_pentest(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="  Pentest  ")
        tab.columnconfigure(0, weight=1)

        f1 = ttk.Labelframe(tab, text="Credential attacks", padding=10)
        f1.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        f1.columnconfigure(1, weight=1)
        self.pt_host = Field(f1, 0, "Host / URL", "")
        self.pt_user = Field(f1, 1, "User or userlist", "")
        self.pt_word = Field(f1, 2, "Password / wordlist", "")
        row = ttk.Frame(f1)
        row.grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Button(row, text="SSH brute",
                   command=lambda: self._cred("sshbrute")).pack(side="left")
        ttk.Button(row, text="FTP brute",
                   command=lambda: self._cred("ftpbrute")).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="HTTP basic",
                   command=lambda: self._cred("httpbasic")).pack(side="left", padx=(8, 0))

        f2 = ttk.Labelframe(tab, text="SSH exec (recovered creds)", padding=10)
        f2.grid(row=1, column=0, sticky="ew", pady=8)
        f2.columnconfigure(1, weight=1)
        self.se_host = Field(f2, 0, "Host", "")
        self.se_user = Field(f2, 1, "User", "")
        self.se_pass = Field(f2, 2, "Password", "", show="•")
        self.se_cmd = Field(f2, 3, "Command", "id")
        ttk.Button(f2, text="Run over SSH", style="Accent.TButton",
                   command=self._sshexec).grid(row=4, column=0, columnspan=2,
                                               sticky="w", pady=(8, 0))

        f3 = ttk.Labelframe(tab, text="Web vulnerability probes", padding=10)
        f3.grid(row=2, column=0, sticky="ew", pady=8)
        f3.columnconfigure(1, weight=1)
        self.web_url = Field(f3, 0, "URL", "")
        self.web_param = Field(f3, 1, "Parameter", "")
        self.web_kind = tk.StringVar(value="sql")
        krow = ttk.Frame(f3)
        krow.grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(krow, text="Probe:").pack(side="left", padx=(0, 6))
        ttk.Combobox(krow, textvariable=self.web_kind, state="readonly", width=10,
                     values=("sql", "xss", "lfi", "ssrf", "cmdinj")).pack(side="left")
        ttk.Button(krow, text="Run probe", style="Accent.TButton",
                   command=self._webprobe).pack(side="left", padx=(10, 0))

    def _cred(self, cmd):
        host, user, word = self.pt_host.get(), self.pt_user.get(), self.pt_word.get()
        if not (host and user and word):
            return self._warn(f"{cmd} needs host, user/list and wordlist.")
        self.submit(f"{cmd} {host} {user} {word}")

    def _sshexec(self):
        h, u, p = self.se_host.get(), self.se_user.get(), self.se_pass.get()
        c = self.se_cmd.get() or "id"
        if not (h and u and p):
            return self._warn("sshexec needs host, user and password.")
        self.submit(f"sshexec {h} {u} {p} {c}")

    def _webprobe(self):
        url, param = self.web_url.get(), self.web_param.get()
        if not (url and param):
            return self._warn("Web probes need a URL and a parameter.")
        self.submit(f"{self.web_kind.get()} {url} {param}")

    # ---- tab: payloads -------------------------------------------------------
    def _build_tab_payloads(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="  Payloads  ")
        tab.columnconfigure(0, weight=1)

        f1 = ttk.Labelframe(tab, text="Reverse shell one-liner", padding=10)
        f1.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        f1.columnconfigure(1, weight=1)
        self.rs_host = Field(f1, 0, "LHOST", "")
        self.rs_port = Field(f1, 1, "LPORT", "4444", width=10)
        self.rs_shell = tk.StringVar(value="bash")
        ttk.Label(f1, text="Shell").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Combobox(f1, textvariable=self.rs_shell, state="readonly", width=10,
                     values=("bash", "python", "nc")).grid(row=2, column=1, sticky="w")
        ttk.Button(f1, text="Generate", style="Accent.TButton",
                   command=self._revshell).grid(row=3, column=0, columnspan=2,
                                                sticky="w", pady=(8, 0))

        f2 = ttk.Labelframe(tab, text="Persistence one-liner", padding=10)
        f2.grid(row=1, column=0, sticky="ew", pady=8)
        f2.columnconfigure(1, weight=1)
        self.ps_method = tk.StringVar(value="cron")
        ttk.Label(f2, text="Method").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Combobox(f2, textvariable=self.ps_method, state="readonly", width=10,
                     values=("cron", "systemd")).grid(row=0, column=1, sticky="w")
        self.ps_cmd = Field(f2, 1, "Command", "")
        ttk.Button(f2, text="Generate", style="Accent.TButton",
                   command=self._persist).grid(row=2, column=0, columnspan=2,
                                               sticky="w", pady=(8, 0))
        ttk.Label(tab, text="Generated payloads appear in the Output panel; "
                           "select the text there to copy.",
                  style="Muted.TLabel").grid(row=2, column=0, sticky="w", pady=(4, 0))

    def _revshell(self):
        h, p = self.rs_host.get(), self.rs_port.get()
        if not (h and p):
            return self._warn("Reverse shell needs LHOST and LPORT.")
        self.submit(f"payload revshell {h} {p} {self.rs_shell.get()}")

    def _persist(self):
        c = self.ps_cmd.get()
        if not c:
            return self._warn("Enter a command to persist.")
        self.submit(f"payload persist {self.ps_method.get()} {c}")

    # ---- tab: report ---------------------------------------------------------
    def _build_tab_report(self):
        tab = ttk.Frame(self.nb, padding=10)
        self.nb.add(tab, text="  Report  ")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        row = ttk.Frame(tab)
        row.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(row, text="Save HTML report", style="Accent.TButton",
                   command=lambda: self.submit("report save")).pack(side="left")
        ttk.Button(row, text="Refresh summary",
                   command=self._refresh_report).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="Status", command=lambda: self.submit("status")
                   ).pack(side="left", padx=(8, 0))

        sumf = ttk.Labelframe(tab, text="Session summary", padding=6)
        sumf.grid(row=1, column=0, sticky="nsew")
        cols = ("pkts", "bytes", "err", "found", "dur")
        self.rep_tree = ttk.Treeview(sumf, columns=cols, show="tree headings")
        self.rep_tree.heading("#0", text="attack")
        self.rep_tree.column("#0", width=200, anchor="w")
        for c, t, w in (("pkts", "packets", 90), ("bytes", "traffic", 90),
                        ("err", "errors", 70), ("found", "findings", 80),
                        ("dur", "dur (s)", 70)):
            self.rep_tree.heading(c, text=t)
            self.rep_tree.column(c, width=w, anchor="e")
        self.rep_tree.pack(fill="both", expand=True)

    def _refresh_report(self):
        reg = self.core.registry
        if not reg:
            return
        self.rep_tree.delete(*self.rep_tree.get_children())
        for a in reg.snapshot():
            self.rep_tree.insert(
                "", "end", text=a.name,
                values=(f"{a.packets_sent:,}", Utils.human_size(a.bytes_sent),
                        a.errors, len(a.findings), f"{a.duration:.0f}"))

    # ---- tab: settings -------------------------------------------------------
    def _build_tab_settings(self):
        tab = ttk.Frame(self.nb, padding=12)
        self.nb.add(tab, text="  Settings  ")
        tab.columnconfigure(1, weight=1)
        cfg = self.core.config

        self.set_safe = tk.BooleanVar(value=bool(cfg.safe_mode))
        self.set_spoof = tk.BooleanVar(value=bool(cfg.spoof_source))
        self.set_audit = tk.BooleanVar(value=bool(cfg.audit_log))
        ttk.Checkbutton(tab, text="safe_mode  (no source spoofing, block reserved/loopback)",
                        variable=self.set_safe).grid(row=0, column=0, columnspan=2, sticky="w", pady=3)
        ttk.Checkbutton(tab, text="spoof_source  (forge source address; ignored while safe_mode)",
                        variable=self.set_spoof).grid(row=1, column=0, columnspan=2, sticky="w", pady=3)
        ttk.Checkbutton(tab, text="audit_log  (append every launch to reports/audit.log)",
                        variable=self.set_audit).grid(row=2, column=0, columnspan=2, sticky="w", pady=3)

        self.set_maxpps = Field(tab, 3, "max_pps (hard cap)", str(cfg.max_pps), width=14)
        self.set_dur = Field(tab, 4, "default_duration (s)", str(cfg.default_duration), width=14)
        self.set_iface = Field(tab, 5, "interface", cfg.interface or "", width=24)
        self.set_scope = Field(tab, 6, "scope (space/comma CIDRs)", ", ".join(cfg.scope), width=40)
        self.set_dns = Field(tab, 7, "dns_servers", ", ".join(cfg.dns_servers), width=40)

        ttk.Button(tab, text="Save settings", style="Accent.TButton",
                   command=self._save_settings).grid(row=8, column=0, sticky="w", pady=(12, 0))
        ttk.Label(tab, text=f"Config file: {cfg._path}", style="Muted.TLabel"
                  ).grid(row=9, column=0, columnspan=2, sticky="w", pady=(10, 0))

    def _save_settings(self):
        cfg = self.core.config
        try:
            cfg.max_pps = max(1, int(self.set_maxpps.get() or cfg.max_pps))
        except ValueError:
            pass
        try:
            cfg.default_duration = max(1, int(self.set_dur.get() or cfg.default_duration))
        except ValueError:
            pass
        cfg.safe_mode = bool(self.set_safe.get())
        cfg.spoof_source = bool(self.set_spoof.get())
        cfg.audit_log = bool(self.set_audit.get())
        cfg.interface = self.set_iface.get() or None
        cfg.scope = [c for c in re.split(r"[,\s]+", self.set_scope.get()) if c]
        dns = [c for c in re.split(r"[,\s]+", self.set_dns.get()) if c]
        if dns:
            cfg.dns_servers = dns
        _safe_save(cfg)
        # keep header + settings toggles in sync
        self.safe_var.set(cfg.safe_mode)
        if self.core.log:
            self.core.log.add("settings saved", tag="CFG")
        self._console_line("Settings saved.", "ok")

    # ---- header controls -----------------------------------------------------
    def _toggle_safe(self):
        cfg = self.core.config
        cfg.safe_mode = bool(self.safe_var.get())
        if hasattr(self, "set_safe"):
            self.set_safe.set(cfg.safe_mode)
        _safe_save(cfg)
        if self.core.log:
            state = "ON — spoofing disabled, reserved targets blocked" if cfg.safe_mode else "OFF"
            self.core.log.add(f"safe_mode {state}", tag="SAFE")
        self._console_line(f"safe_mode {'enabled' if cfg.safe_mode else 'disabled'}.",
                           "warn" if not cfg.safe_mode else "ok")

    def _stop_all(self):
        self.core.stop_all()
        self._console_line("Stop signal sent to all running attacks.", "warn")

    # ---- command plumbing ----------------------------------------------------
    def _on_cmd_enter(self, _evt=None):
        cmd = self.cmd_var.get().strip()
        if not cmd:
            return
        self.cmd_var.set("")
        if cmd.lower() in ("q", "quit", "exit"):
            self._on_close()
            return
        self.submit(cmd)

    def submit(self, cmd: str):
        """Echo the command and dispatch it on the async core."""
        self._console_line(f"> {cmd}", "cmd")
        # on_done runs on the loop thread → push to the Tk queue.
        self.core.run_command(cmd, lambda out: self.msg_q.put(("result", out)))

    # ---- console helpers -----------------------------------------------------
    def _console_line(self, text: str, level: str = "plain"):
        self.console.configure(state="normal")
        self.console.insert("end", text + "\n", level)
        self.console.see("end")
        self.console.configure(state="disabled")

    def _warn(self, text: str):
        self._console_line(text, "warn")

    def _need(self, field: Field, template: str):
        v = field.get()
        if not v:
            return self._warn("This action needs a value in the field above.")
        self.submit(template.format(v))

    # ---- periodic pumps ------------------------------------------------------
    def _pump(self):
        """Drain command results posted from the loop thread into the console."""
        try:
            while True:
                kind, payload = self.msg_q.get_nowait()
                if kind == "result":
                    clean, level = render_output(payload)
                    if clean.strip():
                        self._console_line(clean, level)
        except queue.Empty:
            pass
        self.root.after(80, self._pump)

    def _refresh(self):
        reg, net = self.core.registry, self.core.net
        if reg and net:
            self.stat_vars["ip"].set(net.ip or "N/A")
            self.stat_vars["iface"].set((self.core.config.interface or net.interface or "auto")[:14])
            self.stat_vars["pkts"].set(f"{reg.total_packets():,}")
            self.stat_vars["traf"].set(Utils.human_size(reg.total_bytes()))
            active = reg.active()
            self.stat_vars["active"].set(str(len(active)))
            self._refresh_active(reg)
        if self.core.log:
            self._refresh_logs(self.core.log)
        cfg = self.core.config
        mode = "SAFE MODE" if cfg.safe_mode else "LIVE"
        scope = f"scope: {', '.join(cfg.scope)}" if cfg.scope else "scope: unrestricted"
        self.status_var.set(f"Authorized for testing only · {mode} · {scope} · "
                            f"type a command in the >> box, or use the tabs")
        self.root.after(600, self._refresh)

    def _refresh_active(self, reg):
        snap = reg.snapshot()
        current = {a.name for a in snap}
        for name in list(self._active_rows):
            if name not in current:
                self.active_tree.delete(self._active_rows.pop(name))
        for a in snap:
            vals = (("running" if a.running else "done"),
                    f"{a.packets_sent:,}", Utils.human_size(a.bytes_sent),
                    a.errors, f"{a.duration:.0f}s")
            tag = "run" if a.running else "done"
            if a.name in self._active_rows:
                iid = self._active_rows[a.name]
                self.active_tree.item(iid, values=vals, tags=(tag,))
            else:
                iid = self.active_tree.insert("", "end", text=a.name,
                                              values=vals, tags=(tag,))
                self._active_rows[a.name] = iid

    def _refresh_logs(self, log):
        snap = log.get(200)
        if not snap:
            return
        # Identity, not equality: LogBus never copies its entries, so two
        # distinct messages with identical text/timestamp must not be
        # mistaken for the same one and skipped.
        idx = next((i for i, e in enumerate(snap) if e is self._last_log), None) \
            if self._last_log is not None else None
        new = snap[idx + 1:] if idx is not None else snap
        if not new:
            return
        self.logbox.configure(state="normal")
        for e in new:
            lvl = e.get("level", "info")
            tagname = {"error": "error", "warn": "warn", "warning": "warn",
                       "ok": "ok", "success": "ok"}.get(lvl, "info")
            self.logbox.insert("end", e["time"] + " ", "ts")
            if e.get("tag"):
                self.logbox.insert("end", f"[{e['tag']}] ", "tag")
            self.logbox.insert("end", e["msg"] + "\n", tagname)
        self.logbox.see("end")
        self.logbox.configure(state="disabled")
        self._last_log = snap[-1]

    # ---- dialogs -------------------------------------------------------------
    def _show_notice(self):
        messagebox.showinfo("Authorization notice", _ACK_NOTICE)

    def _show_about(self):
        messagebox.showinfo(
            "About NetWARRIOR",
            f"NetWARRIOR {__version__}\n\n"
            "Async network security testing suite — GUI front-end.\n"
            "Authorized penetration testing and research only.\n\n"
            "This GUI drives the same engine as the terminal UI; every attack, "
            "safety rail and audit-log entry behaves identically.")

    def _show_help(self):
        win = tk.Toplevel(self.root)
        win.title("Command reference")
        win.configure(bg=BG)
        win.geometry("640x520")
        txt = scrolledtext.ScrolledText(win, wrap="word", bg="#0a0e14", fg=FG,
                                        font=self.f_mono_s, relief="flat",
                                        padx=10, pady=8)
        txt.pack(fill="both", expand=True)
        lines = ["Every command below also works in the >> box under Output.\n",
                 "NAVIGATION / STATE",
                 "  status                 packet / traffic stats",
                 "  list                   active attacks",
                 "  stop                   stop all running attacks",
                 "  report save            write an HTML session report",
                 "",
                 "RECON",
                 "  scan <ip|cidr>         port scan or network map",
                 "  fingerprint <ip>       OS + banner grab",
                 "  vuln <ip>              banner-based vuln check",
                 "  dns <domain> [type]    DNS lookup",
                 "  dnsrev <ip>            reverse DNS",
                 "  zone <domain> <ns>     zone transfer attempt",
                 "",
                 "PENTEST",
                 "  sshbrute <host> <user> <wordlist>",
                 "  ftpbrute <host> <user> <wordlist>",
                 "  httpbasic <url> <userlist> <passlist>",
                 "  sshexec <host> <user> <pass> [cmd]",
                 "  sql|xss|lfi|ssrf|cmdinj <url> <param>",
                 "",
                 "PAYLOADS",
                 "  payload revshell <host> <port> [bash|python|nc]",
                 "  payload persist <cron|systemd> <command>",
                 "",
                 "ATTACKS  (attack <type> <target> [port] [dur] [pps])"]
        for spec in ATTACK_CATALOG:
            lines.append(f"  {spec.key:<12} {spec.desc:<34} {spec.args}")
        lines += ["", "Types with their own command:"]
        for usage in ATTACK_REDIRECT.values():
            lines.append(f"  {usage}")
        txt.insert("1.0", "\n".join(lines))
        txt.configure(state="disabled")

    # ---- shutdown ------------------------------------------------------------
    def _on_close(self):
        try:
            n = len(self.core.registry.active()) if self.core.registry else 0
        except Exception:
            n = 0
        if n and not messagebox.askokcancel(
                "Quit", f"{n} attack(s) still running. Stop them and quit?"):
            return
        try:
            self.core.shutdown()
        except Exception:
            pass
        self.root.destroy()


# ──────────────────────────────────────────────────────────────────────────────
# Authorization gate (mirrors the CLI first-run acknowledgement)
# ──────────────────────────────────────────────────────────────────────────────
def _authorize_gui(root: tk.Tk, core: AsyncCore) -> bool:
    if core.authorized:
        return True
    dlg = tk.Toplevel(root)
    dlg.title("Authorization required")
    dlg.configure(bg=BG)
    dlg.geometry("560x300")
    dlg.transient(root)
    dlg.grab_set()
    result = {"ok": False}

    tk.Label(dlg, text="AUTHORIZATION REQUIRED", bg=BG, fg=RED,
             font=("Segoe UI", 13, "bold")).pack(pady=(16, 6))
    tk.Message(dlg, text=_ACK_NOTICE, bg=BG, fg=FG, width=520,
               font=("Segoe UI", 10)).pack(padx=20)
    tk.Label(dlg, text=f'Type "{_ACK_PHRASE}" to continue:',
             bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(pady=(10, 4))
    var = tk.StringVar()
    ent = tk.Entry(dlg, textvariable=var, width=40, bg=PANEL, fg=FG,
                   insertbackground=ACCENT, relief="flat", font=("Consolas", 11))
    ent.pack(ipady=4)
    ent.focus_set()
    msg = tk.Label(dlg, text="", bg=BG, fg=RED, font=("Segoe UI", 9))
    msg.pack(pady=(4, 0))

    def _accept():
        if var.get().strip() == _ACK_PHRASE:
            core.authorize()
            result["ok"] = True
            dlg.destroy()
        else:
            msg.configure(text="Phrase does not match. Exiting requires the exact text.")

    def _decline():
        result["ok"] = False
        dlg.destroy()

    btns = tk.Frame(dlg, bg=BG)
    btns.pack(pady=12)
    b_ok = ttk.Button(btns, text="I have authorization", style="Accent.TButton", command=_accept)
    b_ok.pack(side="left", padx=6)
    ttk.Button(btns, text="Cancel", command=_decline).pack(side="left", padx=6)
    ent.bind("<Return>", lambda _e: _accept())
    dlg.protocol("WM_DELETE_WINDOW", _decline)
    root.wait_window(dlg)
    return result["ok"]


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────
def main(argv=None):
    if nw._UVLOOP:
        # GUI runs the loop in a background thread; uvloop's policy is fine there.
        try:
            nw.uvloop.install()
        except Exception:
            pass

    core = AsyncCore(argv)

    root = tk.Tk()
    # Minimal ttk style so the auth dialog matches before the full app builds.
    _st = ttk.Style(root)
    try:
        _st.theme_use("clam")
    except tk.TclError:
        pass
    _st.configure("Accent.TButton", background=ACCENT, foreground="#08131a")

    if not _authorize_gui(root, core):
        root.destroy()
        return

    try:
        core.start()
    except Exception as e:
        messagebox.showerror("Startup failed", f"Could not start the engine:\n{e}")
        root.destroy()
        return

    NetWarriorGUI(root, core)
    root.mainloop()


if __name__ == "__main__":
    main()
