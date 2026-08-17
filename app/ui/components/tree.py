from __future__ import annotations

from tkinter import ttk

import customtkinter as ctk

from app.ui.theme import UiTheme


def create_tree(
    parent: ctk.CTkFrame,
    *,
    columns: tuple[str, ...],
    headings: tuple[str, ...],
    font_family: str,
) -> ttk.Treeview:
    style = ttk.Style(parent)
    style.theme_use("clam")
    style.configure(
        "SurNet.Treeview",
        background=UiTheme.PANEL,
        foreground=UiTheme.TEXT,
        fieldbackground=UiTheme.PANEL,
        borderwidth=0,
        rowheight=31,
        font=(font_family, 10),
    )
    style.configure(
        "SurNet.Treeview.Heading",
        background=UiTheme.PANEL_ALT,
        foreground=UiTheme.TEXT,
        relief="flat",
        font=(font_family, 10, "bold"),
    )
    style.map("SurNet.Treeview", background=[("selected", UiTheme.ACCENT)])

    tree = ttk.Treeview(
        parent,
        columns=columns,
        show="headings",
        style="SurNet.Treeview",
        selectmode="browse",
    )
    for column, heading in zip(columns, headings, strict=True):
        tree.heading(column, text=heading)
        tree.column(column, anchor="w", width=120, minwidth=70)
    return tree
