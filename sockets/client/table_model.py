from PyQt5.QtCore import QAbstractTableModel, Qt
from PyQt5 import QtGui
class TableModel(QAbstractTableModel):
    def __init__(self, data):
        super().__init__()
        self._data = data
        self._headers=list(data[0].keys())      
    def data(self, index, role):
        if role == Qt.DisplayRole:
            return self._data[index.row()][self._headers[index.column()]]

    def rowCount(self, index):
        return len(self._data)
    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal:
                
                return str(self._headers[section])

            if orientation == Qt.Vertical:
                return str(section)

    def columnCount(self, index):
        return len(self._headers)