
from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_HelpPage(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QtWidgets.QVBoxLayout()
        self.layout2= QtWidgets.QHBoxLayout()
        label_princ = QtWidgets.QLabel("This is a help page", self)
        
        label_princ.setAlignment(QtCore.Qt.AlignHCenter)
        label_princ.setFont(QtGui.QFont('Times',40))
        self.layout.addLayout(self.layout2)
        self.layout.addStretch()
        self.create_menu_bar(self.layout2)

        self.layout.addWidget(label_princ)
        self.setLayout(self.layout)
    def create_menu_bar(self,parent):

        image = QtWidgets.QLabel()
        pixmap = QtGui.QPixmap('panda.png')
        pixmap = pixmap.scaled(25, 25, QtCore.Qt.KeepAspectRatio)
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