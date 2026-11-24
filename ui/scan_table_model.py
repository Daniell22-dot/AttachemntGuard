from typing import Any, Optional

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt6.QtGui import QColor


class ScanTableModel(QAbstractTableModel):
    COLUMNS = ['File', 'Verdict', 'Size', 'SHA-256', 'Detected type', 'Reasons', 'Time', 'Action']

    _BLOCK_BACKGROUND = QColor("#ffc7c7")
    _QUARANTINE_BACKGROUND = QColor("#ffe2b8")
    _WARNING_FOREGROUND = QColor("#8a1c00")

    def __init__(self, data=None, parent=None):
        super().__init__(parent)
        self._headers = self.COLUMNS
        self._rows: list[list[Any]] = []
        self._results: list[dict[str, Any]] = []
        for item in data or []:
            if isinstance(item, dict):
                self._append_result(item, emit=False)
            else:
                self._rows.append(list(item))
                self._results.append({})

    def rowCount(self, parent=None) -> int:
        if parent is not None and parent.isValid():
            return 0
        return len(self._rows)

    def columnCount(self, parent=None) -> int:
        if parent is not None and parent.isValid():
            return 0
        return len(self._headers)

    def headerData(self, section, orientation, role):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self._headers[section]
        return str(section + 1)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        if row >= len(self._rows) or col >= len(self._headers):
            return None

        verdict = str(self._results[row].get("verdict", self._rows[row][1])).upper()
        if role == Qt.ItemDataRole.DisplayRole:
            return str(self._rows[row][col])
        if role == Qt.ItemDataRole.BackgroundRole and col == 1:
            if verdict == "BLOCK":
                return self._BLOCK_BACKGROUND
            if verdict == "QUARANTINE":
                return self._QUARANTINE_BACKGROUND
        if role == Qt.ItemDataRole.ForegroundRole and col == 1:
            if verdict in {"BLOCK", "QUARANTINE"}:
                return self._WARNING_FOREGROUND
        return None

    def add_result(self, result: dict[str, Any]) -> None:
        self._append_result(result, emit=True)

    def report_path(self, row: int) -> Optional[str]:
        if 0 <= row < len(self._results):
            return self._results[row].get("report_path") or None
        return None

    def verdict_at(self, row: int) -> Optional[str]:
        if 0 <= row < len(self._results):
            return self._results[row].get("verdict")
        return None

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self._results.clear()
        self.endResetModel()

    def _append_result(self, result: dict[str, Any], *, emit: bool) -> None:
        reasons = result.get("reasons", [])
        row = [
            result.get("file", "unknown"),
            result.get("verdict", "ALLOW"),
            result.get("size_bytes", 0),
            result.get("sha256", ""),
            result.get("detected_mime_type", "unknown"),
            " | ".join(str(reason) for reason in reasons) if reasons else "",
            result.get("scanned_at", ""),
            "Quarantined" if result.get("quarantined") else "Retained",
        ]
        meta = {
            "verdict": result.get("verdict", "ALLOW"),
            "report_path": result.get("report_path", ""),
        }
        if emit:
            position = len(self._rows)
            self.beginInsertRows(QModelIndex(), position, position)
        self._rows.append(row)
        self._results.append(meta)
        if emit:
            self.endInsertRows()
