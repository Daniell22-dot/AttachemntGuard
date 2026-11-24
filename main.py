import sys
from pathlib import Path

_BOOTSTRAP_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
if str(_BOOTSTRAP_ROOT) not in sys.path:
    sys.path.insert(0, str(_BOOTSTRAP_ROOT))

from PyQt6.QtWidgets import QApplication

from core.paths import resource_dir
from ui.main_window import MainWindow

ROOT = resource_dir()


def main() -> None:
    app = QApplication(sys.argv)
    window = MainWindow(ROOT)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
