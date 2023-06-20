from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QComboBox, QCheckBox, QMessageBox
from PyQt5.QtCore import Qt,pyqtSignal

from client_utils import *
import subprocess

class BlockIPForm(QWidget):
    
    def __init__(self, Window_object=None):
        self.window_object = Window_object
        super().__init__()
        self.initUI()
    def initUI(self):
        self.setWindowTitle('Block IPs Form')
        layout = QHBoxLayout()
        self.ip_input=QLineEdit()
        label=QLabel("Enter Ip Here:")

        button=QPushButton("Submit")
        button.clicked.connect(self.block_ip)

        layout.addWidget(label)
        layout.addWidget(self.ip_input)
        layout.addWidget(button)
        
        self.setLayout(layout)
        
    def block_ip(self):
        response=get_response_from_ssl_socker('block',self.ip_input.text())
        self.close()
import sys
if __name__ == '__main__':
    app = QApplication(sys.argv)
    form = BlockIPForm()
    sys.exit(app.exec_())