from __future__ import annotations

import tkinter.font as tkfont

import customtkinter as ctk


class UiTheme:
    BG = "#0B1220"
    PANEL = "#111827"
    PANEL_ALT = "#172033"
    BORDER = "#263247"
    TEXT = "#E5E7EB"
    MUTED = "#94A3B8"
    ACCENT = "#3B82F6"
    ACCENT_HOVER = "#2563EB"
    SUCCESS = "#22C55E"
    WARNING = "#F59E0B"
    DANGER = "#EF4444"
    CRITICAL = "#DC2626"


def configure_ctk() -> None:
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")


def select_font_family(root: ctk.CTk) -> str:
    families = set(tkfont.families(root))
    for candidate in ("Segoe UI Variable", "Segoe UI", "Inter", "Arial"):
        if candidate in families:
            return candidate
    return "TkDefaultFont"
