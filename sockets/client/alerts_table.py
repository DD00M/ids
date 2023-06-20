from PyQt5 import QtCore, QtGui, QtWidgets

from itertools import groupby
from operator import itemgetter

import client_utils

class Ui_AlertsTable(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()

        
        self.data2 = sorted(client_utils.alerts,key = itemgetter('Alert')) 
        stats={}
        for (key, value) in groupby(self.data2,key = itemgetter('Alert')):
            stats[key]=len(list(value))

        self.vLayout0 = QtWidgets.QHBoxLayout()
        self.vLayout1 = QtWidgets.QHBoxLayout()
        self.vLayout2=QtWidgets.QHBoxLayout()
        self.vLayout3=QtWidgets.QHBoxLayout()
        self.vLayout4=QtWidgets.QHBoxLayout()
        self.layout=QtWidgets.QVBoxLayout()

        self.create_menu_bar(self.vLayout0)
        self.layout.addStretch()
        self.layout.addLayout(self.vLayout0)

        
        self.layout.addStretch()
        label = QtWidgets.QLabel("Alerts", self)
        label.setFont(QtGui.QFont('Arial',40))
        label.setAlignment(QtCore.Qt.AlignCenter )
        self.layout.addWidget(label)
        self.layout.addStretch()

        self.layout.addLayout(self.vLayout1)
        self.layout.addStretch()
        
        red=255
        green=0
        blue=0
        for item in stats.items():
            self.add_label(f"rgb({red},{green},{blue})",str(item[1]))
            red-=50
            blue+=50
            green+=50

        self.layout.addStretch()
        self.layout.addLayout(self.vLayout2)

        for item in stats.items():
            self.add_label_text(item[0])

        self.layout.addStretch()
        self.layout.addLayout(self.vLayout4)
        self.add_filter_label("Filter")
        self.add_filter_label("Group By")

        self.layout.addStretch()
        self.layout.addLayout(self.vLayout3)

        self.add_table()

        self.layout.addStretch()
        self.setLayout(self.layout)
    
    def add_label(self,color,text):
        self.vLayout1.addStretch()
        label = QtWidgets.QLabel(text, self)
        label.setFont(QtGui.QFont('Arial',30))
        label.setAlignment(QtCore.Qt.AlignHCenter )
        label.setStyleSheet(f"background-color: {color};"
                                   "border-top-left-radius :20px;"
                                   "border-top-right-radius : 20px; "
                                   "border-bottom-left-radius : 20px; "
                                   "border-bottom-right-radius : 20px;")
        
        self.vLayout1.addWidget(label)
        self.vLayout1.addStretch()
    def add_label_text(self,text):
        self.vLayout2.addStretch()
        label = QtWidgets.QLabel(text, self)
        label.setFont(QtGui.QFont('Arial',10))
        label.setAlignment(QtCore.Qt.AlignHCenter )
        self.vLayout2.addWidget(label)
        self.vLayout2.addStretch()
    def add_filter_label(self,option):
        label1 = QtWidgets.QPushButton(option, self)
        label2 = QtWidgets.QLabel("None", self)
        label2.setStyleSheet(f"background-color: blue;"
                                   "border-top-left-radius :10px;"
                                   "border-top-right-radius : 10px; "
                                   "border-bottom-left-radius : 10px; "
                                   "border-bottom-right-radius : 10px;")
        self.vLayout4.addWidget(label1)
        self.vLayout4.addWidget(label2)
        
        self.vLayout4.addStretch()
    def create_menu_bar(self,parent):

        image = QtWidgets.QLabel()
        pixmap = QtGui.QPixmap('panda.png')
        pixmap = pixmap.scaled(30, 30, QtCore.Qt.KeepAspectRatio)
        image.setPixmap(pixmap)
        image.setAlignment(QtCore.Qt.AlignCenter)
        parent.addWidget(image)

        menubar = QtWidgets.QMenuBar()

        actionFile = menubar.addMenu("&Actions")

        actionFile.addAction(QtGui.QIcon("./icons/bug.png"),"&Scan file")
        actionFile.addAction(QtGui.QIcon("./icons/file-open.svg"), "&Detailed Alerts")
        actionFile.addAction(QtGui.QIcon("./icons/expand.svg"),"Open State Charts")
        actionFile.addSeparator()
       
       
        helpMenu=menubar.addMenu(QtGui.QIcon("./icons/help-content.svg"), "&Help")
        helpMenu.addAction("&Help Content")
        helpMenu.addAction("&About")
        parent.addWidget(menubar)
        
    def add_table(self):
        
        
        tableWidget=QtWidgets.QTableWidget(self)
        cols=len(client_utils.alerts[0].keys())
        rows=len(client_utils.alerts)

        tableWidget.setColumnCount(cols)
        tableWidget.setRowCount(rows)

        tableWidget.setAlternatingRowColors(True)
        tableWidget.setWindowTitle("Alerts Table")
        tableWidget.setHorizontalHeaderLabels(client_utils.alerts[0].keys()) 
        
        [tableWidget.horizontalHeader().setSectionResizeMode(i,QtWidgets.QHeaderView.ResizeToContents) for i in range(cols-1)]
        tableWidget.horizontalHeader().setSectionResizeMode(cols-1,QtWidgets.QHeaderView.Stretch)

       
        for row in range(rows):
            for i, (k, v) in enumerate(client_utils.alerts[row].items()):
                tableWidget.setItem(row,i,QtWidgets.QTableWidgetItem(v))

        self.vLayout3.addWidget(tableWidget)
        
