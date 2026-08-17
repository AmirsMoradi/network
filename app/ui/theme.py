from __future__ import annotations

import tkinter.font as tkfont

import customtkinter as ctk


class UiTheme:
    _DARK = {
        "BG": "#0B1220",
        "PANEL": "#111827",
        "PANEL_ALT": "#172033",
        "BORDER": "#263247",
        "TEXT": "#E5E7EB",
        "MUTED": "#94A3B8",
        "ACCENT": "#3B82F6",
        "ACCENT_HOVER": "#2563EB",
        "SUCCESS": "#22C55E",
        "WARNING": "#F59E0B",
        "DANGER": "#EF4444",
        "CRITICAL": "#DC2626",
    }
    _LIGHT = {
        "BG": "#F4F7FB",
        "PANEL": "#FFFFFF",
        "PANEL_ALT": "#EAF0F8",
        "BORDER": "#CFD8E6",
        "TEXT": "#152033",
        "MUTED": "#64748B",
        "ACCENT": "#2563EB",
        "ACCENT_HOVER": "#1D4ED8",
        "SUCCESS": "#15803D",
        "WARNING": "#B45309",
        "DANGER": "#DC2626",
        "CRITICAL": "#991B1B",
    }

    BG = _DARK["BG"]
    PANEL = _DARK["PANEL"]
    PANEL_ALT = _DARK["PANEL_ALT"]
    BORDER = _DARK["BORDER"]
    TEXT = _DARK["TEXT"]
    MUTED = _DARK["MUTED"]
    ACCENT = _DARK["ACCENT"]
    ACCENT_HOVER = _DARK["ACCENT_HOVER"]
    SUCCESS = _DARK["SUCCESS"]
    WARNING = _DARK["WARNING"]
    DANGER = _DARK["DANGER"]
    CRITICAL = _DARK["CRITICAL"]
    MODE = "dark"

    @classmethod
    def apply_mode(cls, mode: str) -> None:
        normalized = mode.lower().strip()
        palette = cls._LIGHT if normalized == "light" else cls._DARK
        cls.MODE = "light" if normalized == "light" else "dark"
        for name, value in palette.items():
            setattr(cls, name, value)


def configure_ctk(mode: str = "dark") -> None:
    UiTheme.apply_mode(mode)
    ctk.set_appearance_mode(UiTheme.MODE)
    ctk.set_default_color_theme("blue")


def select_font_family(root: ctk.CTk) -> str:
    families = set(tkfont.families(root))
    for candidate in ("Segoe UI Variable", "Segoe UI", "Inter", "Arial"):
        if candidate in families:
            return candidate
    return "TkDefaultFont"
