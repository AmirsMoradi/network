from __future__ import annotations

from collections.abc import Callable
from typing import Any

import customtkinter as ctk


class LifecycleFrame(ctk.CTkFrame):
    """CTkFrame whose scheduled callbacks become inert after the frame is destroyed.

    Runtime theme changes rebuild the application shell. Network-oriented pages use
    recurring ``after`` loops, so this guard prevents callbacks owned by the old
    widget tree from touching destroyed Tk widgets after a rebuild.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._lifecycle_alive = True
        super().__init__(*args, **kwargs)

    def after(
        self,
        ms: int,
        func: Callable[..., object] | None = None,
        *args: object,
    ) -> str | None:
        if func is None:
            return super().after(ms)

        def guarded() -> None:
            if self._lifecycle_alive:
                func(*args)

        return super().after(ms, guarded)

    def destroy(self) -> None:
        if not self._lifecycle_alive:
            return
        self._lifecycle_alive = False
        self.on_destroy()
        super().destroy()

    def on_destroy(self) -> None:
        """Optional hook for pages that own cancellation events."""
