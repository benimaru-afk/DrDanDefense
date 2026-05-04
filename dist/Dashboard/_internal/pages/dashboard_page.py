"""
Dashboard Summary Page
High-level security overview and detection statistics.
Reads from both network_data.txt and malware_data.txt.
Auto-refreshes every 10 seconds; also has a manual Refresh button.
"""

import tkinter as tk
from tkinter import ttk

from pages.security_data import (
    format_timestamp,
    get_network_threat_level,
    load_network_data,
    load_malware_data,
    next_scheduled_scan,
)

REFRESH_INTERVAL_MS = 10_000   # auto-refresh every 10 s


def _format_duration(seconds):
    if seconds is None:
        return "N/A"
    try:
        value = float(seconds)
    except (TypeError, ValueError):
        return "N/A"
    if value < 60:
        return f"{value:.1f}s"
    minutes = int(value // 60)
    return f"{minutes}m {value - minutes * 60:04.1f}s"


class DashboardPage(tk.Frame):
    def __init__(self, parent, colors):
        super().__init__(parent, bg=colors["bg_dark"])
        self.colors    = colors
        self._poll_job = None

        # Static chrome — header + subtitle + refresh button
        header = tk.Frame(self, bg=self.colors["bg_dark"], height=90)
        header.pack(fill=tk.X, padx=30, pady=(20, 10))
        header.pack_propagate(False)

        tk.Label(
            header,
            text="Dashboard",
            font=("Segoe UI", 28, "bold"),
            bg=self.colors["bg_dark"],
            fg=self.colors["text_white"],
        ).pack(side=tk.LEFT, anchor="w")

        refresh_btn = tk.Button(
            header,
            text="↻  Refresh",
            font=("Segoe UI", 10),
            bg=self.colors["bg_light"],
            fg=self.colors["text_white"],
            activebackground=self.colors["orange_primary"],
            activeforeground=self.colors["text_white"],
            relief=tk.FLAT,
            cursor="hand2",
            padx=12,
            pady=6,
            command=self._refresh,
        )
        refresh_btn.pack(side=tk.RIGHT, anchor="e", pady=20)
        refresh_btn.bind("<Enter>", lambda _: refresh_btn.configure(bg=self.colors["orange_primary"]))
        refresh_btn.bind("<Leave>", lambda _: refresh_btn.configure(bg=self.colors["bg_light"]))

        tk.Label(
            self,
            text="Security summary and detection statistics",
            font=("Segoe UI", 11),
            bg=self.colors["bg_dark"],
            fg=self.colors["text_gray"],
            anchor="w",
        ).pack(fill=tk.X, padx=30, pady=(0, 20))

        # Dynamic content area — rebuilt on every refresh
        self._content_frame = tk.Frame(self, bg=self.colors["bg_dark"])
        self._content_frame.pack(fill=tk.BOTH, expand=True)

        self._refresh()

    # ── Refresh orchestration ──────────────────────────────────────────────

    def _refresh(self):
        if self._poll_job is not None:
            try:
                self.after_cancel(self._poll_job)
            except Exception:
                pass
            self._poll_job = None

        for widget in self._content_frame.winfo_children():
            widget.destroy()

        self._build_content(self._content_frame)
        self._poll_job = self.after(REFRESH_INTERVAL_MS, self._refresh)

    # ── Content builder ────────────────────────────────────────────────────

    def _build_content(self, parent):
        # Load both data sources fresh from disk
        net_data     = load_network_data()
        malware_data = load_malware_data()

        # Most-recent scan timestamp across both sources
        net_ts  = net_data.get("last_scan")
        mal_ts  = malware_data.get("last_scan")
        if net_ts and mal_ts:
            last_scan_ts = net_ts if net_ts >= mal_ts else mal_ts
        else:
            last_scan_ts = net_ts or mal_ts
        last_scan_display = format_timestamp(last_scan_ts)

        malware_detected  = malware_data.get("malware_detected", False)
        quarantined_items = malware_data.get("quarantined_items", 0)

        # Malware last-scan summary
        mal_summary      = malware_data.get("last_scan_summary", {})
        mal_total        = int(mal_summary.get("total_files", 0) or 0)
        mal_infected     = int(mal_summary.get("infected_files", 0) or 0)
        mal_high_entropy = int(mal_summary.get("high_entropy", 0) or 0)

        # Network last-scan summary
        net_threat_level      = get_network_threat_level(net_data)
        signature_updated     = format_timestamp(net_data.get("threat_signatures_updated_at"))
        next_scan_display     = next_scheduled_scan(last_scan_ts)
        net_summary           = net_data.get("last_scan_summary", {})
        scan_duration_display = _format_duration(net_summary.get("scan_duration_seconds"))
        attack_pct            = float(net_summary.get("attack_percentage", 0) or 0)
        n_attacks             = int(net_summary.get("attacks_detected", 0) or 0)

        # ── Top row: stat card + two meter cards ───────────────────────────
        top_cards = tk.Frame(parent, bg=self.colors["bg_dark"])
        top_cards.pack(fill=tk.X, padx=30, pady=(0, 20))

        self._create_stat_card(top_cards, "Last Scan Performed", last_scan_display, "🕒", 0)

        if net_threat_level == "attack":
            net_subtext = f"{n_attacks} packet(s) flagged"
        elif net_threat_level == "suspicious":
            net_subtext = "Suspicious traffic"
        else:
            net_subtext = "No threats"

        self._create_meter_card(
            parent=top_cards, column=1,
            label="Malicious Packets", icon="🌐",
            amount_used=attack_pct, amount_total=100, unit="%",
            threat_level=net_threat_level, subtext=net_subtext,
        )

        # Malware meter — use real per-scan numbers when available
        if mal_total > 0:
            mal_meter_used  = float(mal_infected)
            mal_meter_total = float(mal_total)
            mal_unit        = " files"
            if mal_infected > 0:
                mal_subtext = f"{mal_infected}/{mal_total} infected"
                if mal_high_entropy > 0:
                    mal_subtext += f", {mal_high_entropy} high entropy"
            else:
                mal_subtext = f"All {mal_total} clean"
                if mal_high_entropy > 0:
                    mal_subtext += f", {mal_high_entropy} high entropy"
        else:
            mal_meter_used  = float(min(quarantined_items, 100))
            mal_meter_total = 100.0
            mal_unit        = " files"
            mal_subtext     = f"{quarantined_items} quarantined" if malware_detected else "No scan yet"

        self._create_meter_card(
            parent=top_cards, column=2,
            label="Malicious Files", icon="🦠",
            amount_used=mal_meter_used, amount_total=mal_meter_total, unit=mal_unit,
            threat_level=(
                "attack"     if mal_infected > 0 else
                "suspicious" if mal_high_entropy > 0 else
                "none"
            ),
            subtext=mal_subtext,
        )

        # ── Main detail row ────────────────────────────────────────────────
        details = tk.Frame(parent, bg=self.colors["bg_dark"])
        details.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 30))

        # Left — protection status
        status_panel = tk.Frame(
            details,
            bg=self.colors["bg_medium"],
            highlightbackground=self.colors["bg_light"],
            highlightthickness=1,
        )
        status_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        status_content = tk.Frame(status_panel, bg=self.colors["bg_medium"])
        status_content.pack(fill=tk.BOTH, expand=True, padx=25, pady=25)

        tk.Label(
            status_content,
            text="Protection Status",
            font=("Segoe UI", 15, "bold"),
            bg=self.colors["bg_medium"],
            fg=self.colors["text_white"],
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 15))

        self._create_status_row(
            status_content, "Real-time Monitoring",
            "Enabled" if net_data.get("real_time_monitoring") else "Disabled",
            self.colors["success"] if net_data.get("real_time_monitoring") else self.colors["warning"],
        )
        self._create_status_row(
            status_content, "Firewall Integration",
            "Active" if net_data.get("firewall_integration") else "Inactive",
            self.colors["success"] if net_data.get("firewall_integration") else self.colors["warning"],
        )
        self._create_status_row(
            status_content, "Threat Signatures Updated",
            signature_updated, self.colors["text_white"],
        )
        self._create_status_row(
            status_content, "Last Network Scan",
            format_timestamp(net_ts) if net_ts else "Never",
            self.colors["success"] if net_ts else self.colors["text_gray"],
        )
        self._create_status_row(
            status_content, "Last Malware Scan",
            format_timestamp(mal_ts) if mal_ts else "Never",
            self.colors["success"] if mal_ts else self.colors["text_gray"],
        )
        self._create_status_row(
            status_content, "Last Scan Duration",
            scan_duration_display, self.colors["text_white"],
        )
        self._create_status_row(
            status_content, "Quarantined Items",
            str(quarantined_items),
            self.colors["danger"] if quarantined_items > 0 else self.colors["text_white"],
        )
        self._create_status_row(
            status_content, "Next Scheduled Scan",
            next_scan_display, self.colors["text_white"],
        )

        # Right — scrollable merged events
        events_panel = tk.Frame(
            details,
            bg=self.colors["bg_medium"],
            highlightbackground=self.colors["bg_light"],
            highlightthickness=1,
        )
        events_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))

        events_content = tk.Frame(events_panel, bg=self.colors["bg_medium"])
        events_content.pack(fill=tk.BOTH, expand=True, padx=25, pady=25)

        tk.Label(
            events_content,
            text="Recent Security Events",
            font=("Segoe UI", 15, "bold"),
            bg=self.colors["bg_medium"],
            fg=self.colors["text_white"],
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 10))

        scroll_outer = tk.Frame(events_content, bg=self.colors["bg_medium"])
        scroll_outer.pack(fill=tk.BOTH, expand=True)

        events_canvas = tk.Canvas(
            scroll_outer, bg=self.colors["bg_medium"], highlightthickness=0,
        )
        events_scrollbar = ttk.Scrollbar(
            scroll_outer, orient="vertical", command=events_canvas.yview
        )
        inner_frame = tk.Frame(events_canvas, bg=self.colors["bg_medium"])

        inner_frame.bind(
            "<Configure>",
            lambda e: events_canvas.configure(scrollregion=events_canvas.bbox("all")),
        )
        win_id = events_canvas.create_window((0, 0), window=inner_frame, anchor="nw")
        events_canvas.configure(yscrollcommand=events_scrollbar.set)
        events_canvas.bind(
            "<Configure>",
            lambda e: events_canvas.itemconfig(win_id, width=e.width),
        )
        events_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        events_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        def _on_mousewheel(event):
            events_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        events_canvas.bind("<MouseWheel>", _on_mousewheel)
        inner_frame.bind("<MouseWheel>", _on_mousewheel)

        net_events = [dict(e, _source="network") for e in net_data.get("events", [])]
        mal_events = [dict(e, _source="malware") for e in malware_data.get("events", [])]
        all_events = sorted(
            net_events + mal_events,
            key=lambda e: e.get("timestamp") or "",
            reverse=True,
        )

        if not all_events:
            all_events = [{
                "title":  "No scans performed",
                "detail": "Run a Network or Malware scan to populate events",
                "timestamp": None, "_source": None,
            }]

        for event in all_events:
            row = self._create_event_row(
                inner_frame,
                event.get("title", "Event"),
                event.get("detail", ""),
                format_timestamp(event.get("timestamp")),
                source=event.get("_source"),
            )
            if row:
                row.bind("<MouseWheel>", _on_mousewheel)
                for child in row.winfo_children():
                    child.bind("<MouseWheel>", _on_mousewheel)

    # ── Widget builders ────────────────────────────────────────────────────

    def _create_stat_card(self, parent, label, value, icon, column):
        card = tk.Frame(
            parent,
            bg=self.colors["bg_medium"],
            highlightbackground=self.colors["bg_light"],
            highlightthickness=1,
        )
        card.grid(row=0, column=column, padx=10, sticky="nsew")
        parent.grid_columnconfigure(column, weight=1, uniform="stat")

        content = tk.Frame(card, bg=self.colors["bg_medium"])
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=18)

        tk.Label(content, text=icon, font=("Segoe UI Emoji", 18),
                 bg=self.colors["bg_medium"], fg=self.colors["orange_primary"],
                 anchor="w").pack(fill=tk.X)
        tk.Label(content, text=value, font=("Segoe UI", 16, "bold"),
                 bg=self.colors["bg_medium"], fg=self.colors["text_white"],
                 anchor="w").pack(fill=tk.X, pady=(8, 4))
        tk.Label(content, text=label, font=("Segoe UI", 10),
                 bg=self.colors["bg_medium"], fg=self.colors["text_gray"],
                 anchor="w").pack(fill=tk.X)

    def create_stat_card(self, parent, label, value, icon, column):
        self._create_stat_card(parent, label, value, icon, column)

    def _create_meter_card(self, parent, column, label, icon,
                           amount_used, amount_total, unit, threat_level, subtext):
        card = tk.Frame(
            parent,
            bg=self.colors["bg_medium"],
            highlightbackground=self.colors["bg_light"],
            highlightthickness=1,
        )
        card.grid(row=0, column=column, padx=10, sticky="nsew")
        parent.grid_columnconfigure(column, weight=1, uniform="stat")

        content = tk.Frame(card, bg=self.colors["bg_medium"])
        content.pack(fill=tk.BOTH, expand=True, padx=10, pady=12)

        top_row = tk.Frame(content, bg=self.colors["bg_medium"])
        top_row.pack(fill=tk.X, pady=(0, 4))

        tk.Label(top_row, text=icon, font=("Segoe UI Emoji", 14),
                 bg=self.colors["bg_medium"], fg=self.colors["orange_primary"],
                 ).pack(side=tk.LEFT, padx=(0, 6))
        tk.Label(top_row, text=label, font=("Segoe UI", 10),
                 bg=self.colors["bg_medium"], fg=self.colors["text_gray"],
                 anchor="w").pack(side=tk.LEFT)

        size      = 140
        pad       = 14
        bad_color = {"attack": "#f44336", "suspicious": "#ffb300"}.get(threat_level, "#4caf50")
        ok_color  = "#4caf50"

        canvas = tk.Canvas(content, width=size, height=size // 2 + 30,
                           bg=self.colors["bg_medium"], highlightthickness=0)
        canvas.pack(pady=(4, 0))

        x1, y1 = pad, pad
        x2, y2 = size - pad, size - pad
        pct         = max(0.0, min(1.0, amount_used / amount_total)) if amount_total else 0.0
        MIN_VISIBLE = 8.0
        bad_extent  = round(max(pct * 180, MIN_VISIBLE) if pct > 0 else 0.0, 2)
        clean_extent = round(180.0 - bad_extent, 2)

        if bad_extent > 0:
            canvas.create_arc(x1, y1, x2, y2, start=0, extent=bad_extent,
                              style=tk.ARC, outline=bad_color, width=14)
        if clean_extent > 0:
            canvas.create_arc(x1, y1, x2, y2, start=bad_extent, extent=clean_extent,
                              style=tk.ARC, outline=ok_color, width=14)

        cx, cy = size // 2, size // 2 + 4
        canvas.create_text(cx, cy - 6, text=f"{amount_used:.0f}{unit}",
                           fill=self.colors["text_white"], font=("Segoe UI", 13, "bold"))
        canvas.create_text(cx, cy + 12, text=subtext,
                           fill=self.colors["text_gray"], font=("Segoe UI", 9))

    def _create_status_row(self, parent, label, value, value_color):
        row = tk.Frame(parent, bg=self.colors["bg_medium"])
        row.pack(fill=tk.X, pady=8)
        tk.Label(row, text=label, font=("Segoe UI", 10),
                 bg=self.colors["bg_medium"], fg=self.colors["text_gray"],
                 anchor="w").pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(row, text=value, font=("Segoe UI", 10, "bold"),
                 bg=self.colors["bg_medium"], fg=value_color,
                 anchor="e").pack(side=tk.RIGHT)

    def create_status_row(self, parent, label, value, value_color):
        self._create_status_row(parent, label, value, value_color)

    def _create_event_row(self, parent, title, detail, when, source=None):
        row = tk.Frame(parent, bg=self.colors["bg_light"])
        row.pack(fill=tk.X, pady=(0, 6))

        content = tk.Frame(row, bg=self.colors["bg_light"])
        content.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        top = tk.Frame(content, bg=self.colors["bg_light"])
        top.pack(fill=tk.X)

        if source == "network":
            badge_text, badge_color = "🌐", self.colors.get("orange_secondary", "#ff8c42")
        elif source == "malware":
            badge_text, badge_color = "🦠", self.colors.get("danger", "#f44336")
        else:
            badge_text, badge_color = "", self.colors["text_gray"]

        if badge_text:
            tk.Label(top, text=badge_text, font=("Segoe UI Emoji", 10),
                     bg=self.colors["bg_light"], fg=badge_color,
                     ).pack(side=tk.LEFT, padx=(0, 5))

        tk.Label(top, text=title, font=("Segoe UI", 10, "bold"),
                 bg=self.colors["bg_light"], fg=self.colors["text_white"],
                 anchor="w").pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(top, text=when or "", font=("Segoe UI", 9),
                 bg=self.colors["bg_light"], fg=self.colors["text_gray"],
                 anchor="e").pack(side=tk.RIGHT)
        tk.Label(content, text=detail, font=("Segoe UI", 9),
                 bg=self.colors["bg_light"], fg=self.colors["text_gray"],
                 anchor="w", wraplength=320, justify="left",
                 ).pack(fill=tk.X, pady=(2, 0))

        return row

    def create_event_row(self, parent, title, detail, when, source=None):
        return self._create_event_row(parent, title, detail, when, source)

    def destroy(self):
        if self._poll_job is not None:
            try:
                self.after_cancel(self._poll_job)
            except Exception:
                pass
        super().destroy()