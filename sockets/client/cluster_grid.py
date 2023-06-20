import sys
from PyQt5.QtWidgets import QHeaderView, QGroupBox, QDialog, QVBoxLayout, QGridLayout
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSlot,QSortFilterProxyModel
from PyQt5 import QtWidgets
import json 
from PyQt5.QtCore import QAbstractTableModel, Qt
from PyQt5 import QtGui

class ClusterModel(QAbstractTableModel):
    def __init__(self, data):
        super().__init__()
        self._data = data

    def rowCount(self,parent=None):
        return self._data.shape[0]
    def columnCount(self,parent=None):
        return self._data.shape[1]
    def data(self, index, role):
        if not index.isValid(): return None
        row=index.row()
        col=index.column()
        if role == Qt.DisplayRole:
            return str(self._data.iloc[row,col])
        if role==Qt.BackgroundRole:
            if row%2==0:return QtGui.QColor("#f0f0f0")
    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal:        
                return str(self._data.columns[section])
            if orientation == Qt.Vertical:
                return str(self._data.index[section])
    
class ClusterGrid(QDialog):

    def __init__(self,features):
        super().__init__()
        self.title = 'PyQt5 layout - pythonspot.com'
        self.left = 10
        self.top = 10
        self.width = 320
        self.height = 100
        
        self.n=len(features) # n clustere
        self.data=features #fiecare cu cate un dataframe de valori

        self.initUI()
        
    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)
        self.createGridLayout()
        
        windowLayout = QVBoxLayout()
        windowLayout.addWidget(self.horizontalGroupBox)
        self.setLayout(windowLayout)
        
        self.show()
    
    def createGridLayout(self):
        self.horizontalGroupBox = QGroupBox("Grid")
        layout = QGridLayout()
        rows=self.n 
        cols=1
        for row in range(rows):
            for col in range(cols):
                model = ClusterModel(self.data[row]) 
                proxy_model = QSortFilterProxyModel()
                proxy_model.setFilterKeyColumn(-1) 
                proxy_model.setSourceModel(model)
                proxy_model.sort(0, Qt.AscendingOrder)
                table=QtWidgets.QTableView()
                table.setModel(proxy_model)
                table.horizontalHeader().setStretchLastSection(True)
                table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeToContents)
                label=QtWidgets.QLabel(f'Cluster {row} observations: {len(self.data[row])}')
                layout.addWidget(label,2*row,col)
                layout.addWidget(table,2*row+1,col)
        self.horizontalGroupBox.setLayout(layout)

    