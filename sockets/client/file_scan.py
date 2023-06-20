import hashlib
import zlib
from PyQt5 import QtCore, QtGui, QtWidgets
from file_browse import *
import urllib.request
import sys
import subprocess
import json

from time import sleep

headers={'Check':'','More':''}
api_key='ee7a8fa7ab98b3ae4e9677e5c3e936831db3bce50662f1adfd4350be354d035f'

class Ui_FileScan(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.vLayout1 = QtWidgets.QVBoxLayout()
        self.vLayout2=QtWidgets.QVBoxLayout()
        self.layout0 = QtWidgets.QHBoxLayout()
        self.layout = QtWidgets.QHBoxLayout()
        self.bigLayout=QtWidgets.QVBoxLayout()
        self.resize(500,380)
        self.create_menu_bar(self.layout0)
        self.layout0.addStretch()
        self.result_id=None
        self.bigLayout.addLayout(self.layout0)
        
        self.add_label("File Analysis",1.5,Qt.AlignCenter,20)

        self.add_label("Click to select a file or submit a hash",0.5,Qt.AlignVCenter,10)

        self.add_file_browser_layer1()
        self.add_submit_url_layer2()

        # subprocess.check_output(['tshark', '-r' ,'/home/cristiana/capfiles/capfile0' , '--export-objects' ,'http,./extracted'])        

        self.buttonClose = QtWidgets.QPushButton('Back')
        self.buttonClose.clicked.connect(self.close)
        
        
        self.vLayout1.addStretch()
        self.vLayout2.addStretch()
       

        self.bigLayout.addLayout(self.layout)
        

        self.setLayout(self.bigLayout)
        self.show()

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

    def add_label(self,title,width,alignment,fontsize):
        label_princ = QtWidgets.QLabel(title, self)
        label_princ.setStyleSheet("border: "+str(width)+"px solid black;")
        label_princ.setAlignment(alignment)
        label_princ.setFont(QtGui.QFont('Times',fontsize))
        self.bigLayout.addWidget(label_princ)
    def add_file_browser_layer1(self):
        self.fileBrowser=FileBrowser('Open File')
        self.vLayout1.addWidget(self.fileBrowser)
        self.buttonAnayze = QtWidgets.QPushButton('Analyze')
        self.buttonAnayze.clicked.connect(self.action_analize)
        self.buttonAnayze.setFixedSize(100,20)
        self.vLayout1.addWidget(self.buttonAnayze)
        self.layout.addLayout(self.vLayout1)
    def add_submit_url_layer2(self):
        self.url_label= QtWidgets.QLineEdit( self) 
        self.url_label.setPlaceholderText("Submit url or hash")    
        
        self.url_label.setAlignment(Qt.AlignLeft | Qt.AlignHCenter)
        self.url_label.setStyleSheet("border: 1px solid black; background-color: rgb(229, 228, 226);")
        # self.url_label.setFixedSize(400,200)

        self.progressBar = QtWidgets.QProgressBar(self)
        self.progressBar.setGeometry(25, 45, 210, 30)
        self.progressBar.hide()
        

        buttonSubmit= QtWidgets.QPushButton('Submit')
        buttonSubmit.clicked.connect(self.action_submit)
        self.status_label=QtWidgets.QLabel('') 

        self.vLayout2.addWidget(self.url_label)
        self.vLayout2.addWidget(buttonSubmit)
        self.vLayout2.addWidget(self.status_label)
        

        self.vLayout2.addWidget(self.progressBar)
        self.layout.addLayout(self.vLayout2)
  
    def action_submit(self):

        result = subprocess.run(['./vt-scan.sh','-k',api_key,'-a',self.result_id],stdout=subprocess.PIPE)
        attributes = json.loads(result.stdout.decode('utf-8'))
        
        while attributes['data']['attributes']['status'] == 'queued':
            result = subprocess.run(['./vt-scan.sh','-k',api_key,'-a',self.result_id],stdout=subprocess.PIPE)
            attributes = json.loads(result.stdout.decode('utf-8'))
            self.status_label.setText("Found!")
            QtWidgets.QApplication.processEvents()
            print('Still searching...')
            # sleep(1)
        
        attributes = attributes['data']['attributes']
        if attributes['status'] == 'completed':
            self.status_label.setText("Seatch completed!!")
            QtWidgets.QApplication.processEvents()
            print('Seatch completed!')
            if attributes['stats']['malicious'] > 0:
                self.status_label.setText('Seatch completed!!\n File appers o be malicious!')
            else:
                self.status_label.setText('Seatch completed!!\n File is safe!')
    def action_analize(self):
        try:
            file=self.fileBrowser.getPaths()[0]
        except:
            file='../panda.png'

        label_2 = QtWidgets.QLabel("Summary", self)       
        label_2.setStyleSheet("border: 1px solid black;")
        label_2.setAlignment(Qt.AlignLeft | Qt.AlignHCenter)
        self.vLayout1.addWidget(label_2)

        tableWidget=QtWidgets.QTableWidget()
        cols=2
        rows=8
        tableWidget.setColumnCount(cols)
        tableWidget.setRowCount(rows)

        tableWidget.setAlternatingRowColors(True)
        tableWidget.setWindowTitle("File analysis")
        tableWidget.setHorizontalHeaderLabels(headers.keys()) 
        [tableWidget.horizontalHeader().setSectionResizeMode(i,QtWidgets.QHeaderView.ResizeToContents) for i in range(cols-1)]
        tableWidget.horizontalHeader().setSectionResizeMode(cols-1,QtWidgets.QHeaderView.Stretch)
        self.vLayout1.addWidget(tableWidget)

        with open(file,'rb') as f:
            content=f.read()
        file_data={"Filename":file,"File type":"binary data","MD5":hashlib.md5(content).hexdigest(),"Sha256":hashlib.sha256(content).hexdigest(),"Sha512":hashlib.sha512(content).hexdigest(),"CRC32":hex(zlib.crc32(content) & 0xffffffff),"Yara":"None Matched","Score":"32"}
        for i, (k, v) in enumerate(file_data.items()):
            tableWidget.setItem(i,0,QtWidgets.QTableWidgetItem(k))
            tableWidget.setItem(i,1,QtWidgets.QTableWidgetItem(v))
        tableWidget.resizeColumnsToContents()
        tableWidget.resizeRowsToContents()
        self.buttonAnayze.hide()
        self.fileBrowser.hide()
        
        self.bigLayout.addWidget(self.buttonClose)
        self.bigLayout.addStretch()

        result = subprocess.run(['./vt-scan.sh','-k',api_key,'-f',file],stdout=subprocess.PIPE)
        result_id = json.loads(result.stdout.decode('utf-8'))
        self.result_id = result_id['data']['id']
import sys
if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    form = Ui_FileScan()
    sys.exit(app.exec_())