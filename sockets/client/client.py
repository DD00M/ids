
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *


from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

import json 
import sys
sys.dont_write_bytecode = True

from file_browse import *
from client_utils import *
from cluster_grid import * 
from client_thread import *


class ClientWindow(QDialog):
    def __init__(self,parent=None):
        QDialog.__init__(self)
        # self.setFixedHeight(1000)
        self.parent=parent
        self.ClusterGridWindow=None
        
        self.data=dict()
        self.algParameters=dict() #fine tuning pentru paramterii algoritmilor de ML

        self.cluster_features=None
        self.cluster_groups=None
        self.prev_action=""
        self.setWindowFlags(Qt.WindowStaysOnTopHint)
        self.setWindowTitle("Anomaly Detector")
        self.tunningWidget=QWidget()
        # Create and assign the main (vertical) layout.
        self.vlayout = QVBoxLayout()
        self.setLayout(self.vlayout)  

        self.vlayout1=QVBoxLayout()
        self.vlayout2=QVBoxLayout()
        self.vlayout.addLayout(self.vlayout1)
        self.vlayout.addLayout(self.vlayout2)
        self.hlayout1=QHBoxLayout()
        self.hlayout2=QHBoxLayout()  
        self.hlayout3=QHBoxLayout() 

        addRadioButtons(self.vlayout1,self.onClickedFile)
        self.addButtonOK(self.vlayout1,QtCore.Qt.AlignCenter)
        self.addTrainButton(self.hlayout1,QtCore.Qt.AlignCenter)
        self.addRetrainButton(self.hlayout1,QtCore.Qt.AlignLeft)
        self.vlayout2.addLayout(self.hlayout1)
        # self.addTunningParameters(self.vlayout2)
        self.addClompareButton(self.hlayout2,QtCore.Qt.AlignLeft)
        self.addSaveButton(self.hlayout2,QtCore.Qt.AlignCenter)
        self.addShowClusterDetailsButton(self.hlayout2,QtCore.Qt.AlignRight)
        #self.addGenerateReportButton(self.hlayout2,QtCore.Qt.AlignRight)
        self.addCloseButton(self.hlayout3,QtCore.Qt.AlignCenter)
        

        self.figure = Figure()
        self.canvas = FigureCanvas(self.figure)
        
        self.canvas.hide() 
        self.vlayout3=QVBoxLayout()
        self.vlayout3.addWidget(self.canvas)
        
        

        # self.vlayout.addLayout(self.hlayout1)
        self.vlayout.addLayout(self.hlayout2)
        self.vlayout.addLayout(self.hlayout3)
        self.vlayout.addLayout(self.vlayout3)
        

        self.client_thread = ClientThread()
        self.client_thread.received.connect(self.show_response_from_server)
        self.client_thread.start()

        self.show()
    def check_parameters_and_set_defult_values(self):
        if 'conn' not in self.data :self.data['conn'] = 'file'
        if 'alg' not in self.data :self.data['alg'] = 'IForest'
        if 'numClusters' not in self.data or self.data['numClusters'] == 0 :self.data['numClusters']=4
        if 'pcaComponents' not in self.data or self.data['pcaComponents'] == 0 :self.data['pcaComponents']=2
        if 'how' not in self.data :self.data['how']='no'
    def show_response_from_server(self, data):
        if data != 'Connected to server.':    
            if 'error' not in data:
                if self.data['action']=='ok':
                    data=json.loads(data)
                    statistics=json.loads(data['statistics'])
                    if statistics:
                        stats=""
                        for item in statistics: stats+=f"There are {str(item[0])} models saved with algorithm {item[1]} for connection type {item[2]}.\nChoose to train a model again or show statistics for the already trained model." 
                    else:
                        stats="No models saved yet for this type of algorithm and connection type\n"
                    create_message_box(stats,QMessageBox.Critical)
                    scores=[float(elem) for elem in data['scores'].split(" ")]
                    
                    pd.DataFrame({'Num Clusters':range(2,10), 'score':scores}).plot(x='Num Clusters', y='score')
                    plt.title("Initial Data Clusters")
                    plt.show()
                elif self.data['action']=='train' or self.data['action']=='retrain' :           
                    ftrs=http_features if self.data['conn']=='http' else file_features if self.data['conn']=='file' else conn_features
                    if self.prev_action!='train' and self.prev_action!='retrain' and self.prev_action!='compare': ftrs.append('score')
                    self.cluster_groups=json.loads(data)
                    self.cluster_features=plot_cluster_groups(self.vlayout3,self.figure,self.canvas,self.cluster_groups,ftrs)
                elif self.data['action']=='compare':
                    print('Plot comaprison between algorithms on same dataset')
                    ftrs=http_features if self.data['conn']=='http' else file_features if self.data['conn']=='file' else conn_features
                    data=json.loads(data)              
                    plot_for_compare(self.vlayout3,self.figure,self.canvas,data,ftrs,self.buttonActionSave)
                    #avem daele pentru fiecare dintre clustere, daca vrem sa salvam punem in data datele corespunztaore algoritmului dorit
                elif self.data['action']=='generate': print('Generated report')
                elif self.data['action']=='save': print(data)
                self.prev_action=self.data['action']
            else: 
                create_message_box(data,QMessageBox.Critical)
    

    def buttonActionOK(self): 
        self.data['action']='ok'
        self.check_parameters_and_set_defult_values()
        data=json.dumps(self.data)
        self.client_thread.send_message(data)

    def buttonActionCompare(self):
        self.buttonSave.hide()
        self.data['action']='compare'
        if self.tunningWidget: self.tunningWidget.hide()
        self.check_parameters_and_set_defult_values()
        data=json.dumps(self.data)
        self.client_thread.send_message(data)
    def buttonActionSave(self):
        self.data['action']='save'
        if self.prev_action=='compare' :
            self.data['alg']=self.sender().text().split(' ')[1]
            print(f"saving model for requested alg { self.data['alg']}")
        #else ramane ce e in self.data['alg']
        self.check_parameters_and_set_defult_values()
        data=json.dumps(self.data)
        self.client_thread.send_message(data)
    def buttonActionTrainMLAlgorithms(self):
        self.data['action']='train'
        self.data['how'],done=QInputDialog.getItem(self, 'Input Dialog', 'Load already existing model?', [ 'yes','no'])
        if 'conn' not  in self.data: self.data['conn'],done0=QInputDialog.getItem(self, 'Data type', 'Choose connection type:', [ 'http','conn','file'])
        if 'alg' not in self.data: self.data['alg'], done3= QInputDialog.getItem(self, 'Algorithm type', 'Choose unsupervised algorithm:', [ 'IForest','OneClassSVM'])
        
        #adaugam tunning parameters doar daca avem un model nou de antrenat
        if self.data['how'] == 'no' :
            self.addTunningParameters(self.vlayout2)
            #verificam daca a mai ramas vreun parametru de care e nevoie la antrenare necitit
            if 'numClusters' not in self.data: self.data['numClusters'], done1 =QInputDialog.getInt(self, 'Clusters', 'Enter number of clusters:')
            if 'pcaComponents' not in self.data:  self.data['pcaComponents'], done2 = QInputDialog.getInt(self, 'PCA', 'Enter your pca components:')                
        else:
            data=json.dumps(self.data)
            self.client_thread.send_message(data)

    def buttonActionSend(self):
        if self.algParameters:
            self.data['parameters']=self.algParameters
            self.contaminationSlider.setValue(0)
            self.featuresSlider.setValue(0)
            self.randomSlider.setValue(0)
        self.check_parameters_and_set_defult_values()
        data=json.dumps(self.data)
        self.client_thread.send_message(data)

    def buttonActionRetrain(self):
        if not self.tunningWidget.isVisible() : self.tunningWidget.show()
        #retrain se poate apela doar daca se apelase train inainte
        #momentan doar verificam pe how care e setat at cand se antreneaza modelul
        if  self.cluster_groups: # antrenasem deja ceva
            create_message_box(f"These are the old parameters: {self.data}",QMessageBox.Information)
            self.data['action']='retrain'
            #realegem parametrii numClusters si pcaComponents, algoritmul ramane la fel
            self.data['numClusters'], done1 =QInputDialog.getInt(self, 'Clusters', 'RE-enter number of clusters for retraining:')
            self.data['pcaComponents'], done2 = QInputDialog.getInt(self, 'PCA', 'RE-enter your pca components for retraining:')   
        
        else: create_message_box("You have to train a model first",QMessageBox.Critical)
            
    def buttonActionClusterGrid(self):
        if self.cluster_features :
            if self.ClusterGridWindow is None:
                self.ClusterGridWindow=ClusterGrid(self.cluster_features)
                self.ClusterGridWindow.show()      
            else:
                self.ClusterGridWindow.close()
                self.ClusterGridWindow=None
        else:
            create_message_box("You have to train a model first",QMessageBox.Critical) 
        
    def buttonActionGenrateReport(self):
        self.data['action']='generate'
        self.check_parameters_and_set_defult_values()
        data=json.dumps(self.data)
        self.client_thread.send_message(data)
    
    def addFileBrowserPanel(self):
        fileLayout = QHBoxLayout() 	
        self.fileFB = FileBrowser('Choose log file for training: ')     
        fileLayout.addWidget(self.fileFB)      
        fileLayout.addStretch()
        self.vlayout.addLayout(fileLayout)
    

    def onClickedFile(self):
        radioButton = self.sender()
        if radioButton.isChecked():  self.data['conn']=radioButton.file

    def addButtonOK(self, parentLayout,align):     
        self.button = QPushButton("Get Hints")
        self.button.clicked.connect(self.buttonActionOK)
        parentLayout.addWidget(self.button,alignment=align)
    def addShowClusterDetailsButton(self, parentLayout,align):
        self.buttonDetails = QPushButton("Get Cluster Details")
        self.buttonDetails.clicked.connect(self.buttonActionClusterGrid)
        parentLayout.addWidget(self.buttonDetails,alignment=align)
    def addGenerateReportButton(self,parentLayout,align):      
        self.buttonReport= QPushButton("Generate Report")
        self.buttonReport.clicked.connect(self.buttonActionGenrateReport)
        parentLayout.addWidget(self.buttonReport,alignment=align)
        
    def addRetrainButton(self, parentLayout,align):      
        self.buttonRetrain = QPushButton("Retrain")
        self.buttonRetrain.clicked.connect(self.buttonActionRetrain)
        parentLayout.addWidget(self.buttonRetrain,alignment=align )
      
    def addClompareButton(self,parentLayout,align):   
        self.btnClose = QPushButton("Compare")
        self.btnClose.clicked.connect(self.buttonActionCompare)
        parentLayout.addWidget(self.btnClose,alignment=align)
        
    def addSaveButton(self, parentLayout,align):      
        self.buttonSave = QPushButton("Save")
        self.buttonSave.clicked.connect(self.buttonActionSave)
        parentLayout.addWidget(self.buttonSave,alignment=align)
        
    def addTrainButton(self, parentLayout,align):      
        self.buttonTrain = QPushButton("Train")
        self.buttonTrain.clicked.connect(self.buttonActionTrainMLAlgorithms)
        parentLayout.addWidget(self.buttonTrain,alignment=align)
    def addTunningParameters(self,parentLayout):
        
        paramsGrid = QGridLayout()
        if self.data['alg'] == 'IForest':
            self.labelContamination = create_label_for_slider()
            self.labelFeatures=create_label_for_slider()
            self.labelRandom = create_label_for_slider()
            
            paramsGrid.addWidget(self.contaminationGroup(), 0, 0)
            paramsGrid.addWidget(self.labelContamination,0,1)
            paramsGrid.addWidget(self.featuresGroup(), 1, 0)
            paramsGrid.addWidget(self.labelFeatures,1,1)
            paramsGrid.addWidget(self.randomGroup(), 2, 0)
            paramsGrid.addWidget(self.labelRandom,2,1)
        else:
            self.labelNu=create_label_for_slider()
            self.labelgamma=create_label_for_slider()

            paramsGrid.addWidget(self.nuGroup(),0,0)
            paramsGrid.addWidget(self.labelNu,0,1)
            paramsGrid.addWidget(self.gammaGroup(),1,0)
            paramsGrid.addWidget(self.labelNu,1,1)
        self.tunningWidget.setLayout(paramsGrid)
        # parentLayout.addLayout(self.paramsGrid)
        parentLayout.addWidget(self.tunningWidget)
        send=QPushButton("Send")
        send.clicked.connect(self.buttonActionSend)
        parentLayout.addWidget(send)
    def nuGroup(self):
        groupBox = QGroupBox("Nu Values")
        button = QPushButton("&Choose Value")
        button.setMaximumHeight(20)

        self.nuSlider=create_slider()

        self.nuSlider.valueChanged.connect(self.changeValueNu)
        button.clicked.connect(lambda: self.get_nu_value(self.nuSlider))

        vbox = QVBoxLayout()
        vbox.addWidget(self.nuSlider)
        vbox.addWidget(button)
        vbox.addStretch(1)

        groupBox.setLayout(vbox)
        return groupBox
    def gammaGroup(self):
        groupBox = QGroupBox("Gamma Values")
        button = QPushButton("&Choose Value")
        button.setMaximumHeight(20)

        self.gammaSlider=create_slider()

        self.gammaSlider.valueChanged.connect(self.changeValueGamma)
        button.clicked.connect(lambda: self.get_gamma_value(self.gammaSlider))

        vbox = QVBoxLayout()
        vbox.addWidget(self.gammaSlider)
        vbox.addWidget(button)
        vbox.addStretch(1)

        groupBox.setLayout(vbox)
        return groupBox
    def contaminationGroup(self):
        groupBox = QGroupBox("Contamination Values")
        button = QPushButton("&Choose Value")
        button.setMaximumHeight(20)

        self.contaminationSlider=create_slider()

        self.contaminationSlider.valueChanged.connect(self.changeValueContamination)
        button.clicked.connect(lambda: self.get_contamination_value(self.contaminationSlider))

        vbox = QVBoxLayout()
        vbox.addWidget(self.contaminationSlider)
        vbox.addWidget(button)
        vbox.addStretch(1)

        groupBox.setLayout(vbox)
        return groupBox
    def featuresGroup(self):
        groupBox = QGroupBox("Max Features Values")
        button = QPushButton("&Choose Value")
        button.setMaximumHeight(20)

        self.featuresSlider=create_slider()

        self.featuresSlider.valueChanged.connect(self.changeValueFeatures)
        button.clicked.connect(lambda: self.get_features_value(self.featuresSlider))

        vbox = QVBoxLayout()
        vbox.addWidget(self.featuresSlider)
        vbox.addWidget(button)
        vbox.addStretch(1)

        groupBox.setLayout(vbox)
        return groupBox
    def randomGroup(self):
        groupBox = QGroupBox("Random State Values")
        button = QPushButton("&Choose Value")
        button.setMaximumHeight(20)

        self.randomSlider=create_slider()

        self.randomSlider.valueChanged.connect(self.changeValueRandom)
        button.clicked.connect(lambda: self.get_random_value(self.randomSlider))

        vbox = QVBoxLayout()
        vbox.addWidget(self.randomSlider)
        vbox.addWidget(button)
        vbox.addStretch(1)

        groupBox.setLayout(vbox)
        return groupBox    
    def changeValueContamination(self,value):self.labelContamination.setText(str(value))
    def changeValueFeatures(self,value):
        self.labelFeatures.setText(str(value))
    def changeValueRandom(self,value):
        self.labelRandom.setText(str(value))
    def changeValueNu(self,value):
        self.labelNu.setText(str(value))
    def changeValueGamma(self,value):
        self.labelgamma.setText(str(value))
    
    def get_contamination_value(self,slider):
        if slider.value() == 0 :
            value = "auto"
        value = slider.value()/200 # the contamination should be in the range (0, 0.5]
        self.algParameters['contamination'] = str(value)
    def get_random_value(self,slider):
        if slider.value() == 0 :
           value = None
        value = slider.value() #Pass an int for reproducible results across multiple function calls
        self.algParameters['random_state'] = str(value)
    def get_features_value(self,slider):
        if slider.value() == 0 :
            value = 7
        value = slider.value()//10 #int, then draw max_features features
        self.algParameters['max_features'] = str(value)
    def get_nu_value(self,slider):
        if slider.value() == 0 :
            value = 0.5
        value = str(float(slider.value()/100)) #Should be in the interval (0, 1]. By default 0.5 
        self.algParameters['max_features'] = str(value)
    def get_gamma_value(self,slider):
        if slider.value() == 0 :
            value = 'auto'
        value = str(float(slider.value()/100))
        self.algParameters['max_features'] = str(value)
    def addCloseButton(self, parentLayout,align):      
        self.buttonTrain = QPushButton("Close")
        self.buttonTrain.clicked.connect(self.close)
        parentLayout.addWidget(self.buttonTrain,alignment=align)
        
    def close(self):
        QCoreApplication.exit(0)
        plt.close('all')
    

if __name__ == "__main__":
    app = QApplication(sys.argv)

    client_window = ClientWindow()
    client_window.show()

    sys.exit(app.exec_())
