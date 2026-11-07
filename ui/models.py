"""Qt table models for the metadata tag list and binary signature table."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QFont

from ui import theme


class MetadataModel(QAbstractTableModel):
    """Every extracted tag as Tag / Value rows."""

    HEADERS = ["Metadata tag / field", "Extracted value"]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[tuple[str, str]] = []

    def set_meta(self, meta: dict[str, Any]) -> None:
        self.beginResetModel()
        clean = {k: v for k, v in meta.items() if not k.startswith("_")}
        self._rows = [(k, str(v)) for k, v in sorted(clean.items())]
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 2

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if role == Qt.DisplayRole:
            return self._rows[index.row()][index.column()]
        if role == Qt.FontRole and index.column() == 1:
            return QFont(theme.MONO_FONT, 11)
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.HEADERS[section]
        return None


class MetadataFilterProxy(QSortFilterProxyModel):
    """Case-insensitive substring filter over tag names and values."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._text = ""

    def set_filter(self, text: str) -> None:
        self._text = text.lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        if not self._text:
            return True
        model = self.sourceModel()
        tag = model.index(source_row, 0, source_parent).data() or ""
        value = model.index(source_row, 1, source_parent).data() or ""
        return self._text in tag.lower() or self._text in value.lower()


class SignaturesModel(QAbstractTableModel):
    """Binary signature matches: Offset / Category / Name / Confidence / Details."""

    HEADERS = ["Offset", "Category", "Name", "Confidence", "Details / signatures"]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[Any] = []

    def set_signatures(self, signatures: list[Any]) -> None:
        self.beginResetModel()
        self._rows = list(signatures)
        self.endResetModel()

    def clear(self) -> None:
        self.beginResetModel()
        self._rows = []
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 5

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        s = self._rows[index.row()]
        col = index.column()
        if role == Qt.DisplayRole:
            if col == 0:
                return f"0x{s.offset:06x}"
            if col == 1:
                return s.category
            if col == 2:
                return s.name
            if col == 3:
                return s.confidence
            return s.description
        if role == Qt.FontRole and col == 0:
            return QFont(theme.MONO_FONT, 11)
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.HEADERS[section]
        return None
