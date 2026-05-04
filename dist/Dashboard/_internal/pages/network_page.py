"""
Network Page — Traffic Scan & Live Scan
"""

from __future__ import annotations

import csv
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox
import tkinter as tk
from tkinter import ttk

from pages.security_data import (
    load_network_data,
    record_ml_scan_result,
    format_timestamp,
    get_network_threat_level,
)

from auth import get_logged_in_user, notifications_enabled
from email_notifier import send_attack_email

# Root of the project — writable persistent dir when frozen (next to exe),
# or two levels up from this file in normal dev mode.
if getattr(sys, "frozen", False):
    PROJECT_ROOT = Path(sys.executable).resolve().parent
else:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent

ML_SCRIPT      = PROJECT_ROOT / "ml_classifier.py"
DEEP_ML_SCRIPT = PROJECT_ROOT / "deep_classifier.py"
MODEL_DIR      = PROJECT_ROOT / "models"


def _worker_cmd(script: Path) -> list:
    """Return the command prefix to invoke a classifier script."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "--worker", script.stem]
    return [sys.executable, str(script)]


# ── NSL-KDD port → service name lookup (subset) ───────────────────────────────
_PORT_SERVICE: dict[int, str] = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "domain_u", 79: "finger", 80: "http",
    110: "pop_3", 119: "nntp", 143: "imap4", 194: "IRC",
    443: "http_443", 512: "exec", 513: "login", 514: "shell",
    515: "printer", 540: "uucp", 3306: "sql_net",
    8080: "http_8001", 8443: "http_443",
}


def _tcp_flag_str(flags) -> str:
    """Map scapy TCP flags bitmask to an NSL-KDD flag string."""
    f = int(flags)
    if f & 0x04:   # RST set
        return "REJ"
    if f & 0x01:   # FIN set
        return "SF"
    if f & 0x02:   # SYN only
        return "S0"
    return "OTH"


def _packets_to_temp_csv(packets) -> str | None:
    """
    Convert a list of Scapy packets to a temporary CSV file that the ML
    classifiers can ingest.  Returns the temp-file path, or None if no
    parseable IP packets were found.  The caller is responsible for deleting
    the file after use.
    """
    rows: list[dict] = []

    for pkt in packets:
        # Only handle IP packets
        if not pkt.haslayer("IP"):
            continue

        ip = pkt["IP"]
        row: dict = {
            "duration":       0,
            "protocol_type":  "other",
            "service":        "other",
            "flag":           "OTH",
            "src_bytes":      0,
            "dst_bytes":      0,
            "land":           int(ip.src == ip.dst),
            "wrong_fragment": int(getattr(ip, "frag", 0) > 0),
            "urgent":         0,
            # Extra cols used by the classifier for event reporting
            "src_ip":  ip.src,
            "dst_ip":  ip.dst,
        }

        if pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            row["protocol_type"] = "tcp"
            row["service"]       = _PORT_SERVICE.get(tcp.dport, "private")
            row["flag"]          = _tcp_flag_str(tcp.flags)
            row["src_bytes"]     = len(bytes(tcp.payload))
            row["urgent"]        = int(getattr(tcp, "urgptr", 0) > 0)

        elif pkt.haslayer("UDP"):
            udp = pkt["UDP"]
            row["protocol_type"] = "udp"
            row["service"]       = _PORT_SERVICE.get(udp.dport, "private")
            row["src_bytes"]     = len(bytes(udp.payload))

        elif pkt.haslayer("ICMP"):
            row["protocol_type"] = "icmp"
            row["service"]       = "eco_i"

        else:
            continue   # skip non-TCP/UDP/ICMP IP packets

        rows.append(row)

    if not rows:
        return None

    fd, tmp_path = tempfile.mkstemp(suffix=".csv")
    try:
        with os.fdopen(fd, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    except Exception:
        os.close(fd)
        raise

    return tmp_path


# ─────────────────────────────────────────────────────────────────────────────
class NetworkPage(tk.Frame):
    def __init__(self, parent, colors):
        super().__init__(parent, bg=colors["bg_dark"])
        self.colors = colors
        self._poll_job = None

        # ── Outer scrollable wrapper so content never clips vertically ────
        outer_canvas = tk.Canvas(self, bg=colors["bg_dark"], highlightthickness=0)
        outer_scrollbar = tk.Scrollbar(self, orient="vertical", command=outer_canvas.yview)
        self._scroll_frame = tk.Frame(outer_canvas, bg=colors["bg_dark"])

        self._scroll_frame.bind(
            "<Configure>",
            lambda e: outer_canvas.configure(
                scrollregion=outer_canvas.bbox("all")
            ),
        )

        self._scroll_win = outer_canvas.create_window(
            (0, 0), window=self._scroll_frame, anchor="nw"
        )
        outer_canvas.configure(yscrollcommand=outer_scrollbar.set)

        # Keep scroll_frame width in sync with canvas width
        outer_canvas.bind(
            "<Configure>",
            lambda e: outer_canvas.itemconfig(self._scroll_win, width=e.width),
        )

        # Mousewheel on the outer canvas and scroll frame
        def _outer_scroll(event):
            outer_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        outer_canvas.bind("<MouseWheel>", _outer_scroll)
        self._scroll_frame.bind("<MouseWheel>", _outer_scroll)

        outer_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        outer_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # ── All page content lives in self._scroll_frame ──────────────────
        self._build_content()

    def _build_content(self):
        """Build all page widgets inside the scrollable frame."""
        parent = self._scroll_frame

        # ── Header ────────────────────────────────────────────────────────
        header = tk.Frame(parent, bg=self.colors["bg_dark"], height=80)
        header.pack(fill=tk.X, padx=30, pady=(20, 10))
        header.pack_propagate(False)

        tk.Label(
            header,
            text="Network",
            font=("Segoe UI", 28, "bold"),
            bg=self.colors["bg_dark"],
            fg=self.colors["text_white"],
        ).pack(side=tk.LEFT, anchor="w")

        tk.Label(
            parent,
            text="Choose a scan mode for network threat detection.",
            font=("Segoe UI", 11),
            bg=self.colors["bg_dark"],
            fg=self.colors["text_gray"],
            anchor="w",
        ).pack(fill=tk.X, padx=30, pady=(0, 20))

        # ── Scan option cards ──────────────────────────────────────────────
        cards_frame = tk.Frame(parent, bg=self.colors["bg_dark"])
        cards_frame.pack(fill=tk.X, padx=30, pady=(0, 20))

        self.create_option_card(
            cards_frame,
            title="Quick Scan",
            icon="⚡",
            description=(
                "Uses a Random Forest classifier — an ensemble of decision trees — "
                "to vote on whether traffic patterns are likely benign or malicious. "
                "Select a .csv capture file or use Live Scan to capture 30 seconds "
                "of live traffic."
            ),
            column=0,
            on_traffic_scan=lambda: self._start_ml_scan("Quick Scan"),
            on_live_scan=lambda: self._start_live_scan("Quick Scan"),
        )

        self.create_option_card(
            cards_frame,
            title="Deep Scan",
            icon="🔍",
            description=(
                "Combines a Random Forest classifier with a KMeans clustering model. "
                "RF handles known attack patterns; KMeans flags traffic that looks "
                "anomalous even if it doesn't match prior signatures. "
                "Slower than Quick Scan but catches novel threats RF alone may miss."
            ),
            column=1,
            on_traffic_scan=lambda: self._start_ml_scan("Deep Scan"),
            on_live_scan=lambda: self._start_live_scan("Deep Scan"),
        )

        # ── Status / results panel ─────────────────────────────────────────
        self._build_results_panel(parent)
        self._refresh_results_panel()

    # ──────────────────────────────────────────────────────────────────────
    # Card builder
    # ──────────────────────────────────────────────────────────────────────

    def create_option_card(self, parent, title, icon, description,
                           column, on_traffic_scan, on_live_scan):
        card = tk.Frame(
            parent,
            bg=self.colors["bg_medium"],
            highlightbackground=self.colors["bg_light"],
            highlightthickness=1,
        )
        card.grid(row=0, column=column, padx=10, sticky="nsew")
        parent.grid_columnconfigure(column, weight=1, uniform="option")
        parent.grid_rowconfigure(0, weight=1)

        content = tk.Frame(card, bg=self.colors["bg_medium"])
        content.pack(fill=tk.BOTH, expand=True, padx=25, pady=25)

        icon_frame = tk.Frame(content, bg=self.colors["bg_light"], width=52, height=52)
        icon_frame.pack(anchor="w", pady=(0, 15))
        icon_frame.pack_propagate(False)

        tk.Label(
            icon_frame,
            text=icon,
            font=("Segoe UI Emoji", 20),
            bg=self.colors["bg_light"],
            fg=self.colors["text_white"],
        ).place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(
            content,
            text=title,
            font=("Segoe UI", 15, "bold"),
            bg=self.colors["bg_medium"],
            fg=self.colors["text_white"],
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 10))

        # Description label with dynamic wraplength
        desc_label = tk.Label(
            content,
            text=description,
            font=("Segoe UI", 10),
            bg=self.colors["bg_medium"],
            fg=self.colors["text_gray"],
            justify="left",
            wraplength=420,
            anchor="w",
        )
        desc_label.pack(fill=tk.X, pady=(0, 22))

        # Update wraplength whenever the card resizes
        desc_label.bind(
            "<Configure>",
            lambda e, lbl=desc_label: lbl.configure(wraplength=max(100, e.width - 10)),
        )

        # Two-button row: Traffic Scan | Live Scan
        btn_row = tk.Frame(content, bg=self.colors["bg_medium"])
        btn_row.pack(fill=tk.X)

        traffic_btn = tk.Button(
            btn_row,
            text="📁  Traffic Scan",
            font=("Segoe UI", 10),
            bg=self.colors["bg_light"],
            fg=self.colors["text_white"],
            activebackground=self.colors["orange_primary"],
            activeforeground=self.colors["text_white"],
            relief=tk.FLAT,
            cursor="hand2",
            padx=12,
            pady=10,
            command=on_traffic_scan,
        )
        traffic_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))

        live_btn = tk.Button(
            btn_row,
            text="📡  Live Scan",
            font=("Segoe UI", 10),
            bg=self.colors["bg_light"],
            fg=self.colors["text_white"],
            activebackground=self.colors["orange_secondary"],
            activeforeground=self.colors["text_white"],
            relief=tk.FLAT,
            cursor="hand2",
            padx=12,
            pady=10,
            command=on_live_scan,
        )
        live_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 0))

        for btn in (traffic_btn, live_btn):
            hover_bg = (self.colors["orange_primary"]
                        if btn is traffic_btn
                        else self.colors["orange_secondary"])
            btn.bind("<Enter>", lambda _, b=btn, c=hover_bg: b.configure(bg=c))
            btn.bind("<Leave>", lambda _, b=btn: b.configure(bg=self.colors["bg_light"]))

    # ──────────────────────────────────────────────────────────────────────
    # Results panel
    # ──────────────────────────────────────────────────────────────────────

    def _build_results_panel(self, parent):
        panel = tk.Frame(
            parent,
            bg=self.colors["bg_medium"],
            highlightbackground=self.colors["bg_light"],
            highlightthickness=1,
        )
        panel.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 30))

        inner = tk.Frame(panel, bg=self.colors["bg_medium"])
        inner.pack(fill=tk.BOTH, expand=True, padx=25, pady=20)

        # Title row
        title_row = tk.Frame(inner, bg=self.colors["bg_medium"])
        title_row.pack(fill=tk.X, pady=(0, 12))

        tk.Label(
            title_row,
            text="Last Scan Results",
            font=("Segoe UI", 13, "bold"),
            bg=self.colors["bg_medium"],
            fg=self.colors["text_white"],
        ).pack(side=tk.LEFT)

        self._status_badge = tk.Label(
            title_row,
            text="",
            font=("Segoe UI", 9, "bold"),
            bg=self.colors["bg_medium"],
            fg=self.colors["text_gray"],
            padx=10,
            pady=3,
        )
        self._status_badge.pack(side=tk.LEFT, padx=(10, 0))

        self._run_info_label = tk.Label(
            inner,
            text="",
            font=("Segoe UI", 10),
            bg=self.colors["bg_medium"],
            fg=self.colors["text_gray"],
        )
        self._run_info_label.pack(anchor="w", pady=(6, 10))

        # Progress bar (hidden until scan running)
        self._progress_frame = tk.Frame(inner, bg=self.colors["bg_medium"])
        self._progress_frame.pack(fill=tk.X, pady=(0, 8))
        self._progress_frame.pack_forget()

        self._progress_label = tk.Label(
            self._progress_frame,
            text="Running…",
            font=("Segoe UI", 10),
            bg=self.colors["bg_medium"],
            fg=self.colors["orange_primary"],
        )
        self._progress_label.pack(anchor="w", pady=(0, 6))

        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Orange.Horizontal.TProgressbar",
            troughcolor=self.colors["bg_light"],
            background=self.colors["orange_primary"],
            bordercolor=self.colors["bg_light"],
            lightcolor=self.colors["orange_primary"],
            darkcolor=self.colors["orange_secondary"],
        )

        # No fixed length= — fill=tk.X handles width dynamically
        self._progress_bar = ttk.Progressbar(
            self._progress_frame,
            style="Orange.Horizontal.TProgressbar",
            orient="horizontal",
            mode="indeterminate",
        )
        self._progress_bar.pack(fill=tk.X, pady=(0, 4))

        self._progress_sublabel = tk.Label(
            self._progress_frame,
            text="",
            font=("Segoe UI", 9),
            bg=self.colors["bg_medium"],
            fg=self.colors["text_gray"],
        )
        self._progress_sublabel.pack(anchor="w")

        # Stats grid
        stats_frame = tk.Frame(inner, bg=self.colors["bg_medium"])
        stats_frame.pack(fill=tk.X, pady=(0, 16))

        self._stat_labels: dict[str, tk.Label] = {}
        stat_defs = [
            ("scan_time",  "Last scan",       "—"),
            ("scan_type",  "Scan type",        "—"),
            ("total_rows", "Rows analysed",    "—"),
            ("attacks",    "Threats detected", "—"),
            ("pct",        "Attack %",         "—"),
            ("gpu",        "GPU accelerated",  "—"),
        ]

        for col_idx, (key, label_text, default) in enumerate(stat_defs):
            cell = tk.Frame(stats_frame, bg=self.colors["bg_light"], padx=14, pady=10)
            cell.grid(row=0, column=col_idx, padx=5, sticky="nsew")
            stats_frame.grid_columnconfigure(col_idx, weight=1)

            tk.Label(
                cell,
                text=label_text,
                font=("Segoe UI", 8),
                bg=self.colors["bg_light"],
                fg=self.colors["text_gray"],
            ).pack(anchor="w")

            val = tk.Label(
                cell,
                text=default,
                font=("Segoe UI", 13, "bold"),
                bg=self.colors["bg_light"],
                fg=self.colors["text_white"],
            )
            val.pack(anchor="w", pady=(4, 0))
            self._stat_labels[key] = val

        # Row weight so stat cells can grow vertically too
        stats_frame.grid_rowconfigure(0, weight=1)

        # Recent events — scrollable
        tk.Label(
            inner,
            text="Recent events",
            font=("Segoe UI", 10, "bold"),
            bg=self.colors["bg_medium"],
            fg=self.colors["text_gray"],
        ).pack(anchor="w", pady=(0, 6))

        # Scrollable container
        scroll_outer = tk.Frame(inner, bg=self.colors["bg_medium"])
        scroll_outer.pack(fill=tk.BOTH, expand=True)

        self._events_canvas = tk.Canvas(
            scroll_outer,
            bg=self.colors["bg_medium"],
            highlightthickness=0,
            height=180,
        )
        events_scrollbar = ttk.Scrollbar(
            scroll_outer, orient="vertical", command=self._events_canvas.yview
        )
        self._events_frame = tk.Frame(self._events_canvas, bg=self.colors["bg_medium"])

        self._events_frame.bind(
            "<Configure>",
            lambda e: self._events_canvas.configure(
                scrollregion=self._events_canvas.bbox("all")
            ),
        )

        self._events_win = self._events_canvas.create_window(
            (0, 0), window=self._events_frame, anchor="nw"
        )
        self._events_canvas.configure(yscrollcommand=events_scrollbar.set)
        self._events_canvas.bind(
            "<Configure>",
            lambda e: self._events_canvas.itemconfig(self._events_win, width=e.width),
        )

        self._events_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        events_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Mousewheel — forward to events canvas
        def _scroll(event):
            self._events_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        self._events_canvas.bind("<MouseWheel>", _scroll)
        self._events_frame.bind("<MouseWheel>", _scroll)

    # ──────────────────────────────────────────────────────────────────────
    # Traffic Scan orchestration (CSV-based)
    # ──────────────────────────────────────────────────────────────────────

    def _start_ml_scan(self, scan_type: str):
        is_deep  = scan_type == "Deep Scan"
        script   = DEEP_ML_SCRIPT if is_deep else ML_SCRIPT
        glob_pat = "deep_best_*.pkl" if is_deep else "rf_best_*.pkl"

        models = sorted(MODEL_DIR.glob(glob_pat)) if MODEL_DIR.exists() else []
        if not models:
            answer = messagebox.askyesno(
                "No trained model found",
                f"No trained {scan_type} model was found in the models/ folder.\n\n"
                "Would you like to select a LABELLED CSV to train a model first?\n"
                "(Training may take a minute.)",
            )
            if answer:
                self._run_training(scan_type=scan_type)
            return

        csv_path = filedialog.askopenfilename(
            title=f"Select network-scan CSV for {scan_type}",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialdir=str(PROJECT_ROOT),
        )
        if not csv_path:
            return

        self._set_scanning_state(True, f"{scan_type} — please wait…")
        threading.Thread(
            target=self._ml_scan_worker,
            args=(csv_path, scan_type, script),
            daemon=True,
        ).start()

    def _run_training(self, scan_type: str = "Quick Scan"):
        csv_path = filedialog.askopenfilename(
            title="Select LABELLED CSV for training (e.g. Train_data.csv)",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialdir=str(PROJECT_ROOT),
        )
        if not csv_path:
            return

        is_deep  = scan_type == "Deep Scan"
        script   = DEEP_ML_SCRIPT if is_deep else ML_SCRIPT

        self._set_scanning_state(True, "Training model — fitting configuration 1 of 3…",
                                  mode="determinate")
        self._progress_bar["maximum"] = 3
        self._progress_bar["value"]   = 0

        threading.Thread(
            target=self._training_worker,
            args=(csv_path, script),
            daemon=True,
        ).start()

    def _training_worker(self, csv_path: str, script: Path):
        config_num = 0
        started_at = time.perf_counter()

        try:
            proc = subprocess.Popen(
                [*_worker_cmd(script), "--train", "--data", csv_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(PROJECT_ROOT),
            )

            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue

                if "Fitting RF" in line:
                    config_num += 1
                    num   = config_num
                    label = f"Training model — fitting configuration {num} of 3…"
                    self.after(0, self._safe(lambda l=label, n=num: (
                        self._progress_label.configure(text=l),
                        self._progress_bar.configure(value=n - 1),
                    )))
                elif "Accuracy:" in line and "]" in line:
                    sub = line.split("]")[-1].strip()
                    self.after(0, self._safe(lambda s=sub: self._progress_sublabel.configure(text=s)))

            proc.wait()
            stderr_buf = proc.stderr.read()

            if proc.returncode != 0:
                script_name = Path(script).name
                self.after(0, lambda sn=script_name, e=stderr_buf: messagebox.showerror(
                    "Training failed", f"{sn} exited with an error:\n\n{e[-800:]}",
                ))
            else:
                elapsed = time.perf_counter() - started_at
                self.after(0, self._safe(lambda: self._progress_bar.configure(value=3)))
                self.after(0, self._safe(lambda e=elapsed: self._run_info_label.configure(
                    text=f"Training completed in {self._format_duration(e)}"
                )))
                self.after(400, lambda: messagebox.showinfo(
                    "Training complete",
                    f"Model trained successfully in {self._format_duration(elapsed)}!\n"
                    "You can now run a scan.",
                ))

        except Exception as exc:
            self.after(0, lambda: messagebox.showerror("Training error", str(exc)))
        finally:
            self.after(0, lambda: self._set_scanning_state(False, ""))

    def _ml_scan_worker(self, csv_path: str, scan_type: str, script: Path):
        started_at = time.perf_counter()
        try:
            result = subprocess.run(
                [*_worker_cmd(script), "--scan", "--data", csv_path],
                capture_output=True,
                text=True,
                cwd=str(PROJECT_ROOT),
            )

            if result.returncode != 0:
                self.after(0, lambda: self._handle_scan_error(result.stderr))
                return

            elapsed = time.perf_counter() - started_at
            self.after(0, lambda e=elapsed: self._on_scan_complete(e))

        except FileNotFoundError:
            self.after(0, lambda: messagebox.showerror(
                "Script not found",
                f"Could not find the classifier script at:\n{script}\n\n"
                "Make sure it lives in the project root.",
            ))
            self.after(0, lambda: self._set_scanning_state(False, ""))
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror("Scan error", str(exc)))
            self.after(0, lambda: self._set_scanning_state(False, ""))

    # ──────────────────────────────────────────────────────────────────────
    # Live Scan orchestration (Scapy capture → temp CSV → classifier)
    # ──────────────────────────────────────────────────────────────────────

    def _start_live_scan(self, scan_type: str):
        """Capture 30 s of live traffic and run the selected classifier."""
        is_deep  = scan_type == "Deep Scan"
        glob_pat = "deep_best_*.pkl" if is_deep else "rf_best_*.pkl"
        models   = sorted(MODEL_DIR.glob(glob_pat)) if MODEL_DIR.exists() else []

        if not models:
            messagebox.showerror(
                "No Trained Model",
                f"No trained {scan_type} model found.\n\n"
                "Train a model first using Traffic Scan.",
            )
            return

        try:
            import scapy.all  # noqa: F401 — just checking it's available
        except ImportError:
            messagebox.showerror(
                "Scapy Not Installed",
                "Live scanning requires the Scapy library.\n\n"
                "Install it with:\n    pip install scapy",
            )
            return

        script = DEEP_ML_SCRIPT if is_deep else ML_SCRIPT
        self._set_scanning_state(True, "Capturing live traffic —  0 / 30 s…")
        threading.Thread(
            target=self._live_scan_worker,
            args=(scan_type, script),
            daemon=True,
        ).start()

    def _live_scan_worker(self, scan_type: str, script: Path):
        """Background thread: capture → temp CSV → classifier → cleanup."""
        started_at = time.perf_counter()
        tmp_path: str | None = None

        try:
            from scapy.all import sniff  # type: ignore

            # Countdown ticker running in parallel with sniff()
            capture_done = threading.Event()

            def _tick():
                for elapsed in range(31):
                    if capture_done.is_set():
                        break
                    self.after(0, lambda s=elapsed: self._progress_label.configure(
                        text=f"Capturing live traffic — {s:2d} / 30 s…"
                    ))
                    time.sleep(1)

            threading.Thread(target=_tick, daemon=True).start()

            packets = sniff(timeout=30, store=True)
            capture_done.set()

            n_captured = len(packets)
            self.after(0, lambda n=n_captured: self._progress_label.configure(
                text=f"Captured {n} packets — running {scan_type}…"
            ))

            if n_captured == 0:
                self.after(0, lambda: messagebox.showwarning(
                    "No Traffic Captured",
                    "No packets were captured during the 30-second window.\n\n"
                    "Check that your network adapter is active.",
                ))
                return

            # Convert packets → temp CSV
            tmp_path = _packets_to_temp_csv(packets)
            if tmp_path is None:
                self.after(0, lambda: messagebox.showwarning(
                    "No Parseable Packets",
                    "No TCP/UDP/ICMP packets were found in the capture.",
                ))
                return

            # Run classifier on temp CSV
            result = subprocess.run(
                [*_worker_cmd(script), "--scan", "--data", tmp_path],
                capture_output=True,
                text=True,
                cwd=str(PROJECT_ROOT),
            )

            if result.returncode != 0:
                self.after(0, lambda: self._handle_scan_error(result.stderr))
                return

            elapsed = time.perf_counter() - started_at
            self.after(0, lambda e=elapsed: self._on_scan_complete(e))

        except PermissionError:
            self.after(0, lambda: messagebox.showerror(
                "Permission Denied",
                "Live scan requires administrator privileges.\n\n"
                "Right-click the application and choose 'Run as Administrator'.",
            ))
        except Exception as exc:
            _msg = str(exc)
            if "administrator" in _msg.lower() or "L3" in _msg or "Npcap" in _msg:
                self.after(0, lambda: messagebox.showerror(
                    "Administrator Required",
                    "Live packet capture requires one of:\n\n"
                    "  • Run this app as Administrator\n"
                    "    (right-click → Run as administrator)\n\n"
                    "  • Install Npcap (no admin needed after install)\n"
                    "    https://npcap.com/#download",
                ))
            else:
                self.after(0, lambda m=_msg: messagebox.showerror("Live Scan Error", m))
        finally:
            # Always delete the temp file
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
            self.after(0, lambda: self._set_scanning_state(False, ""))

    # ──────────────────────────────────────────────────────────────────────
    # GUI state helpers
    # ──────────────────────────────────────────────────────────────────────

    def _safe(self, fn):
        """Wrap a UI callback so it silently no-ops if the widget was destroyed."""
        def _wrapped(*args, **kwargs):
            try:
                fn(*args, **kwargs)
            except tk.TclError:
                pass
        return _wrapped

    def _set_scanning_state(self, scanning: bool, label: str,
                             mode: str = "indeterminate"):
        try:
            if scanning:
                self._progress_label.configure(text=label)
                self._progress_sublabel.configure(text="")
                self._progress_bar.configure(mode=mode)
                if mode == "indeterminate":
                    self._progress_bar.start(12)
                else:
                    self._progress_bar.stop()
                    self._progress_bar["value"] = 0
                self._progress_frame.pack(fill=tk.X, pady=(0, 8),
                                          before=self._events_canvas)
            else:
                self._progress_bar.stop()
                self._progress_frame.pack_forget()
                self._progress_sublabel.configure(text="")
        except tk.TclError:
            pass

    def _on_scan_complete(self, scan_duration_seconds: float | None = None):
        try:
            if scan_duration_seconds is not None:
                self._run_info_label.configure(
                    text=f"Scan completed in {self._format_duration(scan_duration_seconds)}"
                )
            self._set_scanning_state(False, "")
        except tk.TclError:
            pass
        self._refresh_results_panel()
        self._maybe_send_network_alert()

    def _maybe_send_network_alert(self):
        """Send an email alert if notifications are on and threats were detected."""
        try:
            email = get_logged_in_user()
            if not email or not notifications_enabled():
                return
            data         = load_network_data()
            threat_level = get_network_threat_level(data)
            if threat_level not in ("attack", "suspicious"):
                return
            summary = data.get("last_scan_summary", {})
            scan_type = data.get("last_scan_type", "Network Scan")
            pct       = float(summary.get("attack_percentage", 0) or 0)
            n         = int(summary.get("attacks_detected", 0) or 0)
            total     = summary.get("total_rows", "?")
            level_str = "ATTACK" if threat_level == "attack" else "SUSPICIOUS TRAFFIC"
            body = (
                f"Threat level : {level_str}\n"
                f"Scan type    : {scan_type}\n"
                f"Rows analysed: {total}\n"
                f"Threats found: {n}\n"
                f"Attack %     : {pct:.1f}%"
            )
            threading.Thread(
                target=send_attack_email, args=(email, body), daemon=True
            ).start()
        except Exception:
            pass

    def _handle_scan_error(self, stderr: str):
        self._set_scanning_state(False, "")
        messagebox.showerror(
            "Scan failed",
            f"The classifier returned an error:\n\n{stderr[-800:]}",
        )

    # ──────────────────────────────────────────────────────────────────────
    # Results panel refresh
    # ──────────────────────────────────────────────────────────────────────

    def _refresh_results_panel(self):
        data         = load_network_data()
        summary      = data.get("last_scan_summary", {})
        threat_level = get_network_threat_level(data)

        scan_duration = summary.get("scan_duration_seconds")
        if scan_duration is not None:
            self._run_info_label.configure(
                text=f"Last analysis time: {self._format_duration(scan_duration)}"
            )
        elif not self._progress_frame.winfo_ismapped():
            self._run_info_label.configure(text="")

        # Status badge
        if data.get("last_scan") is None:
            badge_text  = "No scan yet"
            badge_color = self.colors["text_gray"]
        elif threat_level == "attack":
            badge_text  = "⚠  THREATS DETECTED"
            badge_color = self.colors["danger"]
        elif threat_level == "suspicious":
            badge_text  = "⚠  SUSPICIOUS ACTIVITY"
            badge_color = "#ffb300"
        else:
            badge_text  = "✓  Clean"
            badge_color = self.colors["success"]

        self._status_badge.configure(text=badge_text, fg=badge_color)

        def _set(key: str, value: str, color: str | None = None):
            lbl = self._stat_labels.get(key)
            if lbl:
                lbl.configure(text=value)
                if color:
                    lbl.configure(fg=color)

        _set("scan_time",  format_timestamp(data.get("last_scan")))
        _set("scan_type",  data.get("last_scan_type") or "—")
        _set("total_rows", str(summary.get("total_rows", "—")))

        n_attacks = summary.get("attacks_detected", None)
        if n_attacks is None:
            _set("attacks", "—", self.colors["text_white"])
        elif n_attacks > 0:
            _set("attacks", str(n_attacks), self.colors["danger"])
        else:
            _set("attacks", "0", self.colors["success"])

        pct = summary.get("attack_percentage", None)
        _set("pct", f"{pct:.1f}%" if pct is not None else "—")
        _set("gpu", "Yes" if summary.get("gpu_used") else "No")

        # Rebuild scrollable events
        for widget in self._events_frame.winfo_children():
            widget.destroy()

        events = data.get("events", [])
        if not events:
            tk.Label(
                self._events_frame,
                text="No events recorded yet.",
                font=("Segoe UI", 10),
                bg=self.colors["bg_medium"],
                fg=self.colors["text_gray"],
            ).pack(anchor="w")
            return

        for evt in events:
            row = tk.Frame(self._events_frame, bg=self.colors["bg_medium"])
            row.pack(fill=tk.X, pady=2)

            title_text = evt.get("title", "")
            if "threat" in title_text.lower() or "attack" in title_text.lower():
                dot_color = self.colors["danger"]
            elif "no threats" in title_text.lower():
                dot_color = self.colors["success"]
            else:
                dot_color = self.colors["warning"]

            tk.Label(
                row, text="●", font=("Segoe UI", 8),
                bg=self.colors["bg_medium"], fg=dot_color,
            ).pack(side=tk.LEFT, padx=(0, 6))

            tk.Label(
                row,
                text=title_text,
                font=("Segoe UI", 10, "bold"),
                bg=self.colors["bg_medium"],
                fg=self.colors["text_white"],
            ).pack(side=tk.LEFT)

            detail = evt.get("detail", "")
            if detail:
                tk.Label(
                    row,
                    text=f"  —  {detail}",
                    font=("Segoe UI", 9),
                    bg=self.colors["bg_medium"],
                    fg=self.colors["text_gray"],
                ).pack(side=tk.LEFT)

            ts = evt.get("timestamp", "")
            if ts:
                tk.Label(
                    row,
                    text=format_timestamp(ts),
                    font=("Segoe UI", 9),
                    bg=self.colors["bg_medium"],
                    fg=self.colors["text_gray"],
                ).pack(side=tk.RIGHT)

            # Propagate mousewheel to events canvas
            row.bind("<MouseWheel>", lambda e: self._events_canvas.yview_scroll(
                int(-1 * (e.delta / 120)), "units"
            ))

    def _format_duration(self, seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.1f}s"
        minutes = int(seconds // 60)
        return f"{minutes}m {seconds - minutes * 60:04.1f}s"

    def destroy(self):
        if self._poll_job:
            self.after_cancel(self._poll_job)
        super().destroy()