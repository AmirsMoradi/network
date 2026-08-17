from __future__ import annotations

from app.core.logging import configure_logging
from app.database.session import Database
from app.services.settings import SettingsService
from app.ui.main_window import MainWindow
from app.ui.theme import configure_ctk


def main() -> None:
    configure_logging()
    settings_service = SettingsService()
    settings = settings_service.load()
    configure_ctk(settings.theme)
    database = Database()
    database.initialize()
    app = MainWindow(database, settings_service=settings_service)
    app.mainloop()


if __name__ == "__main__":
    main()
