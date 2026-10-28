from PyQt6.QtCore import QAbstractTableModel, Qt


class ScanTableModel(QAbstractTableModel):
    COLUMNS = ['File', 'Verdict', 'Size', 'SHA-256', 'Detected type', 'Reasons', 'Time', 'Action']

    def __init__(self, data=None, parent=None):
        super().__init__(parent)
        self._data = data or []
        self._headers = self.COLUMNS

    def rowCount(self, parent=None):
        return len(self._data)

    def columnCount(self, parent=None):
        return len(self._headers)

    def headerData(self, section, orientation, role):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self._headers[section]
        return str(section)

    def data(self, index, role):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        if row < len(self._data) and col < len(self._data[row]):
            return str(self._data[row][col])
        return None