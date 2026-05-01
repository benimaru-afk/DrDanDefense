"""
Dashboard Summary Page
High-level security overview and detection statistics
"""

import tkinter as tk
from tkinter import ttk

from pages.security_data import format_timestamp, get_network_threat_level, load_security_data, next_scheduled_scan


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
        self.colors = colors
        self.data = load_security_data()

        last_scan_display      = format_timestamp(self.data.get("last_scan"))
        malware_detected       = self.data.get("malware_detected", False)
        net_threat_level       = get_network_threat_level(self.data)
        signature_updated      = format_timestamp(self.data.get("threat_signatures_updated_at"))
        next_scan_display      = next_scheduled_scan(self.data.get("last_scan"))
        quarantined_items      = self.data.get("quarantined_items", 0)
        scan_duration_display  = _format_duration(
            self.data.get("last_scan_summary", {}).get("scan_duration_seconds")
        )
        summary                = self.data.get("last_scan_summary", {})
        attack_pct             = float(summary.get("attack_percentage", 0) or 0)
        n_attacks              = int(summary.get("attacks_detected", 0) or 0)

        # ── Header ─────────────────────────────────────────────────────────
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

        tk.Label(
            self,
            text="Security summary and detection statistics",
            font=("Segoe UI", 11),
            bg=self.colors["bg_dark"],
            fg=self.colors["text_gray"],
            anchor="w",
        ).pack(fill=tk.X, padx=30, pady=(0, 20))

        # ── Top row: stat card + two meter cards ──────────────────────────
        top_cards = tk.Frame(self, bg=self.colors["bg_dark"])
        top_cards.pack(fill=tk.X, padx=30, pady=(0, 20))

        # Column 0 — Last Scan (plain stat card)
        self.create_stat_card(top_cards, "Last Scan Performed", last_scan_display, "🕒", 0)

        # Column 1 — Malicious Packets meter
        if net_threat_level == "attack":
            net_subtext = f"{n_attacks} packet(s) flagged"
        elif net_threat_level == "suspicious":
            net_subtext = "Suspicious traffic"
        else:
            net_subtext = "No threats"

        self._create_meter_card(
            parent=top_cards,
            column=1,
            label="Malicious Packets",
            icon="🌐",
            amount_used=attack_pct,
            amount_total=100,
            unit="%",
            threat_level=net_threat_level,
            subtext=net_subtext,
        )

        # Column 2 — Malicious Files meter
        self._create_meter_card(
            parent=top_cards,
            column=2,
            label="Malicious Files",
            icon="🦠",
            amount_used=float(min(quarantined_items, 100)),
            amount_total=100,
            unit=" files",
            threat_level="attack" if malware_detected else "none",
            subtext=f"{quarantined_items} quarantined" if malware_detected else "No threats",
        )

        # ── Main detail row ────────────────────────────────────────────────
        details = tk.Frame(self, bg=self.colors["bg_dark"])
        details.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 30))

        # Left panel — protection status
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

        self.create_status_row(
            status_content, "Real-time Monitoring",
            "Enabled" if self.data.get("real_time_monitoring") else "Disabled",
            self.colors["success"] if self.data.get("real_time_monitoring") else self.colors["warning"],
        )
        self.create_status_row(
            status_content, "Firewall Integration",
            "Active" if self.data.get("firewall_integration") else "Inactive",
            self.colors["success"] if self.data.get("firewall_integration") else self.colors["warning"],
        )
        self.create_status_row(status_content, "Threat Signatures Updated",
                               signature_updated, self.colors["text_white"])
        self.create_status_row(status_content, "Last Scan Duration",
                               scan_duration_display, self.colors["text_white"])
        self.create_status_row(status_content, "Quarantined Items",
                               str(quarantined_items), self.colors["text_white"])
        self.create_status_row(status_content, "Next Scheduled Scan",
                               next_scan_display, self.colors["text_white"])

        # Right panel — scrollable events
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

        # Scrollable canvas for events
        scroll_outer = tk.Frame(events_content, bg=self.colors["bg_medium"])
        scroll_outer.pack(fill=tk.BOTH, expand=True)

        events_canvas = tk.Canvas(
            scroll_outer,
            bg=self.colors["bg_medium"],
            highlightthickness=0,
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

        # Populate ALL events (not capped at 8)
        all_events = self.data.get("events", [])
        if not all_events:
            all_events = [{"title": "No scans performed",
                           "detail": "Run a Network or Malware scan to populate events",
                           "timestamp": None}]

        for event in all_events:
            row = self.create_event_row(
                inner_frame,
                event.get("title", "Event"),
                event.get("detail", ""),
                format_timestamp(event.get("timestamp")),
            )
            if row:
                row.bind("<MouseWheel>", _on_mousewheel)
                for child in row.winfo_children():
                    child.bind("<MouseWheel>", _on_mousewheel)

    # ──────────────────────────────────────────────────────────────────────
    # Widget builders
    # ──────────────────────────────────────────────────────────────────────

    def create_stat_card(self, parent, label, value, icon, column):
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

        tk.Label(
            content,
            text=icon,
            font=("Segoe UI Emoji", 18),
            bg=self.colors["bg_medium"],
            fg=self.colors["orange_primary"],
            anchor="w",
        ).pack(fill=tk.X)

        tk.Label(
            content,
            text=value,
            font=("Segoe UI", 16, "bold"),
            bg=self.colors["bg_medium"],
            fg=self.colors["text_white"],
            anchor="w",
        ).pack(fill=tk.X, pady=(8, 4))

        tk.Label(
            content,
            text=label,
            font=("Segoe UI", 10),
            bg=self.colors["bg_medium"],
            fg=self.colors["text_gray"],
            anchor="w",
        ).pack(fill=tk.X)

    def _create_meter_card(self, parent, column, label, icon,
                           amount_used, amount_total, unit,
                           threat_level, subtext):
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

        # Icon + label row
        top_row = tk.Frame(content, bg=self.colors["bg_medium"])
        top_row.pack(fill=tk.X, pady=(0, 4))

        tk.Label(
            top_row,
            text=icon,
            font=("Segoe UI Emoji", 14),
            bg=self.colors["bg_medium"],
            fg=self.colors["orange_primary"],
        ).pack(side=tk.LEFT, padx=(0, 6))

        tk.Label(
            top_row,
            text=label,
            font=("Segoe UI", 10),
            bg=self.colors["bg_medium"],
            fg=self.colors["text_gray"],
            anchor="w",
        ).pack(side=tk.LEFT)

        # Canvas semi-circle meter
        size      = 140
        pad       = 14
        bg_col    = self.colors["bg_medium"]
        bad_color = {"attack": "#f44336", "suspicious": "#ffb300"}.get(threat_level, "#4caf50")
        ok_color  = "#4caf50"

        canvas = tk.Canvas(
            content,
            width=size,
            height=size // 2 + 30,
            bg=bg_col,
            highlightthickness=0,
        )
        canvas.pack(pady=(4, 0))

        x1, y1 = pad, pad
        x2, y2 = size - pad, size - pad

        pct = max(0.0, min(1.0, amount_used / amount_total)) if amount_total else 0.0
        # Give small non-zero values a minimum visible arc of 8° so they're not invisible
        MIN_VISIBLE = 8.0
        bad_extent   = round(max(pct * 180, MIN_VISIBLE) if pct > 0 else 0.0, 2)
        clean_extent = round(180.0 - bad_extent, 2)

        # Bad portion grows from the right; clean (green) fills the remainder
        if bad_extent > 0:
            canvas.create_arc(x1, y1, x2, y2,
                              start=0, extent=bad_extent,
                              style=tk.ARC, outline=bad_color, width=14)
        if clean_extent > 0:
            canvas.create_arc(x1, y1, x2, y2,
                              start=bad_extent, extent=clean_extent,
                              style=tk.ARC, outline=ok_color, width=14)

        cx = size // 2
        cy = size // 2 + 4

        canvas.create_text(cx, cy - 6,
                           text=f"{amount_used:.0f}{unit}",
                           fill=self.colors["text_white"],
                           font=("Segoe UI", 13, "bold"))

        canvas.create_text(cx, cy + 12,
                           text=subtext,
                           fill=self.colors["text_gray"],
                           font=("Segoe UI", 9))

    def create_status_row(self, parent, label, value, value_color):
        row = tk.Frame(parent, bg=self.colors["bg_medium"])
        row.pack(fill=tk.X, pady=8)

        tk.Label(
            row,
            text=label,
            font=("Segoe UI", 10),
            bg=self.colors["bg_medium"],
            fg=self.colors["text_gray"],
            anchor="w",
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Label(
            row,
            text=value,
            font=("Segoe UI", 10, "bold"),
            bg=self.colors["bg_medium"],
            fg=value_color,
            anchor="e",
        ).pack(side=tk.RIGHT)

    def create_event_row(self, parent, title, detail, when):
        row = tk.Frame(parent, bg=self.colors["bg_light"])
        row.pack(fill=tk.X, pady=(0, 6))

        content = tk.Frame(row, bg=self.colors["bg_light"])
        content.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        top = tk.Frame(content, bg=self.colors["bg_light"])
        top.pack(fill=tk.X)

        tk.Label(
            top,
            text=title,
            font=("Segoe UI", 10, "bold"),
            bg=self.colors["bg_light"],
            fg=self.colors["text_white"],
            anchor="w",
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Label(
            top,
            text=when or "",
            font=("Segoe UI", 9),
            bg=self.colors["bg_light"],
            fg=self.colors["text_gray"],
            anchor="e",
        ).pack(side=tk.RIGHT)

        tk.Label(
            content,
            text=detail,
            font=("Segoe UI", 9),
            bg=self.colors["bg_light"],
            fg=self.colors["text_gray"],
            anchor="w",
            wraplength=320,
            justify="left",
        ).pack(fill=tk.X, pady=(2, 0))

        return row
