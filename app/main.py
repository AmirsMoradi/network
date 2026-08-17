from __future__ import annotations

from app.core.logging import configure_logging
from app.database.session import Database
from app.ui.main_window import MainWindow
from app.ui.theme import configure_ctk


def main() -> None:
    configure_logging()
    configure_ctk()
    database = Database()
    database.initialize()
    app = MainWindow(database)
    app.mainloop()


if __name__ == "__main__":
    main()
