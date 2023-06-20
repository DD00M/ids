# file_browser_ui.py
  
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from sklearn.metrics import silhouette_score
import sys
import pandas as pd

from pyod.models.lof import LOF
from pyod.models.ocsvm import OCSVM
from pyod.models.iforest import IForest

from sklearn.svm import OneClassSVM
import json 
import argparse
from sklearn.cluster import KMeans

from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
from zat.dataframe_to_matrix import DataFrameToMatrix

import numpy as np

import jinja2
import pdfkit
from datetime import datetime
import os 

from connect import *
from log_file_operations import *
from file_browse import *
from utils import *

import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)
warnings.warn = warn


algs =[ 'IForest','OneClassSVM']

clfs= dict()
clfs[algs[0]]=IForest(contamination=0.25)
clfs[algs[1]]=OneClassSVM(gamma='auto')


to_matrix = DataFrameToMatrix()


class UI_MLWindow(QDialog):
    def __init__(self, parent=None):
        QDialog.__init__(self)

        self.parent=parent
        self.res_file='res.json'
        self.to_print=pd.DataFrame()
        self.models=dict()
        self.bro_df=pd.DataFrame()
        self.alg=None
        self.features=[]

    
        self.setWindowFlags(Qt.WindowStaysOnTopHint)
        self.setWindowTitle("Anomaly Detetcor")

        # Create and assign the main (vertical) layout.
        self.vlayout = QVBoxLayout()
        self.setLayout(self.vlayout)  

        self.hlayout1=QHBoxLayout()
        self.hlayout2=QHBoxLayout()  
        self.hlayout3=QHBoxLayout() 

        self.add_statistics()
        self.fileBrowserPanel(self.vlayout)

        
        # self.vlayout.addStretch()
        # self.alertsTablePanel(self.vlayout)

        self.addButtonPanel(self.hlayout1,QtCore.Qt.AlignLeft)
        self.addTrainButton(self.hlayout1,QtCore.Qt.AlignCenter)
        self.addClompareButton(self.hlayout1,QtCore.Qt.AlignRight )
        self.addRetrainButton(self.hlayout2,QtCore.Qt.AlignLeft)
        self.addSaveButton(self.hlayout2,QtCore.Qt.AlignCenter)
        self.addGenerateReportButton(self.hlayout2,QtCore.Qt.AlignRight)
        self.addCloseButton(self.hlayout3,QtCore.Qt.AlignCenter)

        self.vlayout.addLayout(self.hlayout1)
        self.vlayout.addLayout(self.hlayout2)
        self.vlayout.addLayout(self.hlayout3)
    
        self.show()
    def save_data_model(self,file):
        pickle.dump(self.model,open('./model.sav','wb'))
        with open('./model.sav','rb') as f:
            bytes_model=f.read()
        insert_model((b64encode(bytes_model).decode('utf-8')),self.alg,self.conn_type,self.pcaComponents,self.numClusters,str(int(self.iteration)+1))
        insert_data(file,self.conn_type,str(int(self.iteration)+1))
        msgBox=QtWidgets.QMessageBox()
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setText("Successfully saved mode to database")
        msgBox.setStandardButtons(QMessageBox.Ok)
        msgBox.exec() 
       
    
    def read_data_model(self):
        print('Readig already trained data model')
        result =  get_model(self.conn_type,self.alg)
        with open('./model.sav','wb') as f:
            f.write(b64decode(result[1]))
        self.model=pickle.load(open('./model.sav','rb'))
        self.pcaComponents=result[4]
        self.numClusters=result[5]
        self.iteration=result[6]

        self.models[self.alg]=self.model



    def buttonOK(self):    
        
        # self.alertsTable.show()
        # self.toolbar.show()

        self.alg, done3= QInputDialog.getItem(self, 'Input Dialog', 'The algorithm u choose:', algs)
        #fisier nou == model nou
        if len(self.fileFB.getPaths()) != 0:
            file=self.fileFB.getPaths()[-1]
            
            self.conn_type=file.split('/')[-1].split('.')[0]    
            if 'conn' in file:
                self.bro_df,self.features=create_df_conn(file)      
            elif 'ftp' in file:
                self.bro_df,self.features=create_df_ftp(file)
            elif 'http' in file:
                self.bro_df,self.features=create_df_http(file)  
            
            bro_df_aux=self.bro_df.copy()
            
            bro_matrix=to_matrix.fit_transform(bro_df_aux[self.features],normalize=True)   
            self.detect_optimal_number_of_clusters(bro_matrix,"Initial Data Clusters")
            self.numClusters, done1 =QInputDialog.getInt(self, 'Clusters', 'Enter number of clusters:')
            self.pcaComponents, done2 = QInputDialog.getInt(self, 'PCA', 'Enter your pca components:')                
            self.model=None #se completeaza in train
            self.iteration=get_last_iteration_number(self.conn_type,self.alg)
        else:
            #se reincarca ultimul model train-uit si se arata statisticile 
            self.conn_type,done4=QInputDialog.getItem(self, 'Input Dialog', 'The type of log file u choose:', ['http','conn','ftp'])
            self.read_data_model()
            #ca sa ne cream bro_df-ul trebuie sa aducem logurile aferente din BD
            self.bro_df,self.features=get_data(self.conn_type,self.iteration)
            self.features=self.features[:-1]
            
            if self.model:
                fig, axs = plt.subplots(1,1)
                print("Showing statistics for already trained model")
                clf=self.model
                df=self.bro_df.copy()
                ftrs=self.features.copy()
                
                bro_matrix=to_matrix.fit_transform(df[ftrs],normalize=True)        

                ftrs.append('score')
                df['score']=clf.decision_function(bro_matrix)
                odd_df=df[ftrs][clf.predict(bro_matrix) !=0]
                odd_matrix = to_matrix.fit_transform(odd_df)
                kmeans = KMeans(n_clusters=self.numClusters).fit_predict(odd_matrix)  
                pca= PCA(n_components=self.pcaComponents).fit_transform(odd_matrix)
                odd_df['x'] = pca[:, 0] 
                odd_df['y'] = pca[:, 1] 
                odd_df['cluster'] = kmeans
                odd_df['jx'] = jitter(odd_df['x'])
                odd_df['jy'] = jitter(odd_df['y'])
                cluster_groups = odd_df.groupby('cluster')
                for key, group in cluster_groups:  
                    group.plot(ax=axs, kind='scatter', x='jx', y='jy', alpha=0.5, s=250,label='Cluster: {:d}'.format(key), color=colors[key])
                    print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
                    if 'score' in ftrs:
                        top=group[ftrs].sort_values(by='score', ascending=False).head()
                        self.to_print=self.to_print.append(top)
                plt.title(self.alg)
                plt.show()
                



    def buttonActionTrainMLAlgorithms(self):
        self.train()
       
        self.to_print.to_json(self.res_file,index=False,orient='table')

        columns=len(self.to_print.columns)
        rows=len(self.to_print.index)
        
        #TODO sa punem datele in tabele astfel incat sa ni se arate feature-urile clusterlor
        #plot alerts based on cluster beautifully
        # self.table=QTableWidget()
        # self.table.setRowCount(rows)
        # self.table.setColumnCount(columns)
        # for row_index in range(rows):
        #     for col_index in range(columns):
        #         self.table.setItem(row_index,col_index,QTableWidgetItem(str(self.to_print.iloc[row_index,col_index])))
                    
        # self.table.setHorizontalHeaderLabels(self.to_print.columns)
        
        # self.table.horizontalHeader().setStretchLastSection(True)  
        # self.table.horizontalHeader().setSectionResizeMode( QHeaderView.Stretch)  
        # self.vlayout.addWidget(self.table)
       
    
    def buttonActionSave(self):
        self.save_data_model(self.fileFB.getPaths()[-1])
        

    def alertsTablePanel(self,parentLayout):
        vlayout=QVBoxLayout()
        self.alertsTable=QTableWidget(self)
        header = self.alertsTable.horizontalHeader()       
        log_file='/var/log/suricata/fast.log'
        with open(log_file,'r') as f:
            lines=f.readlines()
            self.alertsTable.setRowCount(len(lines))
            col_count=max([len(line.split('[**]')) for line in lines])
            self.alertsTable.setColumnCount(col_count)
            for i in range(col_count):
                header.setSectionResizeMode(i, QHeaderView.ResizeToContents)
            row_count=0
            for line in lines:
                line=line.split('[**]')
                for i in range(len(line)):
                    self.alertsTable.setItem(row_count,i,QTableWidgetItem(line[i]))
                [src_ip,dest_ip]=get_ips(line[len(line)-1])
                
                row_count+=1
       
        
        vlayout.addWidget(self.alertsTable)
        vlayout.addStretch()
        parentLayout.addLayout(vlayout)

                         
    def fileBrowserPanel(self, parentLayout):
        fileLayout = QHBoxLayout() 	
        self.fileFB = FileBrowser('Choose log file for training: ')     
        fileLayout.addWidget(self.fileFB)      
        fileLayout.addStretch()
        parentLayout.addLayout(fileLayout)
    def add_statistics(self):
        label = QLabel(self)   
        label.setText("Detect anomalies based on log file")
        label.setAlignment(QtCore.Qt.AlignCenter )
        label.setFont(QtGui.QFont('Arial',15))
        self.vlayout.addWidget(label)

        alg_by_conn,conn_by_alg=get_statistics()
        # stats1=""
        # [stats1+=f"There are {str(item[0])} models saved for connection type {item[1]} with algorithm {item[2]}.\n" for item in alg_by_conn]
        if conn_by_alg:
            stats=""
            for item in conn_by_alg:
                stats+=f"There are {str(item[0])} models saved with algorithm {item[1]} for connection type {item[2]}.\n" 
        else:
            stats="No models saved yet for this type of algorithm and connection type\n"

        label = QLabel(self)   
        label.setText(stats)
        label.setAlignment(QtCore.Qt.AlignCenter )
        label.setFont(QtGui.QFont('Arial',10))
        self.vlayout.addWidget(label)

    def addButtonPanel(self, parentLayout,align):     
        self.button = QPushButton("OK")
        self.button.clicked.connect(self.buttonOK)
        parentLayout.addWidget(self.button,alignment=align)
       
    
    def addGenerateReportButton(self,parentLayout,align):      
        self.buttonReport= QPushButton("Generate Report")
        self.buttonReport.clicked.connect(self.buttonGenrateReport)
        parentLayout.addWidget(self.buttonReport,alignment=align)
        
    def addRetrainButton(self, parentLayout,align):      
        self.buttonRetrain = QPushButton("Retrain")
        self.buttonRetrain.clicked.connect(self.buttonActionRetrain)
        parentLayout.addWidget(self.buttonRetrain,alignment=align )
      
    def addClompareButton(self,parentLayout,align):   
        self.btnClose = QPushButton("Compare")
        self.btnClose.clicked.connect(self.compare)
        parentLayout.addWidget(self.btnClose,alignment=align)
        
    def addSaveButton(self, parentLayout,align):      
        self.buttonSave = QPushButton("Save")
        self.buttonSave.clicked.connect(self.buttonActionSave)
        parentLayout.addWidget(self.buttonSave,alignment=align)
        
    def addTrainButton(self, parentLayout,align):      
        self.buttonTrain = QPushButton("Train")
        self.buttonTrain.clicked.connect(self.buttonActionTrainMLAlgorithms)
        parentLayout.addWidget(self.buttonTrain,alignment=align)
    def addCloseButton(self, parentLayout,align):      
        self.buttonTrain = QPushButton("Close")
        self.buttonTrain.clicked.connect(self.close)
        parentLayout.addWidget(self.buttonTrain,alignment=align)
        
    def close(self):
        QCoreApplication.exit(0)
        plt.close('all')

    def detect_optimal_number_of_clusters(self,feature_matrix,title):
        #silhouette scoring este o măsură a cât de asemănător este un obiect cu propriul său cluster în comparație cu alte clustere (separare). Silueta variază de la -1 la 1, unde o valoare mare indică faptul că obiectul este bine potrivit cu acesta. propriul cluster și prost potrivit cu clusterele învecinate. Dacă majoritatea obiectelor au o valoare mare, atunci configurația de clustering este adecvată. Dacă multe puncte au o valoare scăzută sau negativă, atunci configurația clustering poate avea prea multe sau prea puține clustere.
        #testam valoarea scorului pana cand ne este indeicat numarul optim de clustere din grafic, apoi introducem in interfata parametrii pe care ii dam algoritmului
        scores = []
        clusters = range(2,10)
        feature_matrix_aux=feature_matrix.copy()
        for K in clusters:
            clusterer = KMeans(n_clusters=K)
            cluster_labels = clusterer.fit_predict(feature_matrix_aux)
            score = silhouette_score(feature_matrix_aux, cluster_labels)
            scores.append(score)
        
        pd.DataFrame({'Num Clusters':clusters, 'score':scores}).plot(x='Num Clusters', y='score')
        plt.title(title)
        plt.show()
        
    def train(self):
        fig, axs = plt.subplots(1,1)
        plt.rcParams.update(params)

        df=self.bro_df.copy()
        ftrs=self.features.copy()
        
        
        bro_matrix=to_matrix.fit_transform(df[ftrs],normalize=True)        
       
        ftrs.append('score')
        

        if self.model is None: # nu am citit
            clf=clfs[self.alg]
            clf.fit(bro_matrix)
            self.models[self.alg]=clf
            print('Training model for the first time for: '+self.alg)
        else:
            clf=self.model
            print('Using already trained model '+self.alg)
        #va returna un scor limitat între 0 - 1, unde valorile mai apropiate de 1 sunt considerate Anomale, iar valorile care sunt <0,5 sunt considerate „normale”.
      
        df['score']=clf.decision_function(bro_matrix)
        odd_df=df[ftrs][clf.predict(bro_matrix) !=0]
        try:
            odd_matrix = to_matrix.fit_transform(odd_df)
            #demonstarm faptul ca numarul de clustere pentru punctele detectate ca fiind outliere este la fel ca cel pentru setul initial de date
            # self.detect_optimal_number_of_clusters(odd_matrix,algorithm)
            # plt.pause(2)
            # plt.close()
            #detectam punctele outlier si le grupam in clustere
            kmeans = KMeans(n_clusters=self.numClusters).fit_predict(odd_matrix)  
            pca= PCA(n_components=self.pcaComponents).fit_transform(odd_matrix)
            
            odd_df['x'] = pca[:, 0] 
            odd_df['y'] = pca[:, 1] 
            odd_df['cluster'] = kmeans
            #jitter este folosit pentru a putea proiecta in 2D PCA in oricate dimensiuni
            odd_df['jx'] = jitter(odd_df['x'])
            odd_df['jy'] = jitter(odd_df['y'])
            cluster_groups = odd_df.groupby('cluster')
            
            for key, group in cluster_groups:  
                group.plot(ax=axs, kind='scatter', x='jx', y='jy', alpha=0.5, s=250,label='Cluster: {:d}'.format(key), color=colors[key])
                
                print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
                if 'score' in ftrs:
                    top=group[ftrs].sort_values(by='score', ascending=False).head()
                    print(top)
                    self.to_print=self.to_print.append(top)
                           
        except Exception as e:
            print(e)
        
        self.model=clf
        plt.title(self.alg)
        plt.show()


    #comparam 2 algoritmi diferiti pe acelasi set de date
    #cazul 1 - avem modelele pentru ambii algoritmi deja deja antrenati
    # cazul 2 - avem doar un model antrenat, iar pe celalt trebuie sa il antrenam
    def compare(self,conn_type):
    
        plt.rcParams.update(params)
        fig, axs = plt.subplots(1,2)

        bro_df=self.bro_df.copy()
        features=self.features.copy()
        
        bro_matrix=to_matrix.fit_transform(bro_df[features],normalize=True)        
        features.append('score')
    
        for i, algorithm in enumerate(clfs.keys()):
            bro_matrix_aux=bro_matrix.copy()
            result=get_model(conn_type,algorithm)
            if result:#ne folosim de ceea ce aveam antrenat in bd, nu reantrenam
                clf=result[0]
                pcaComponents=result[4]
                numClusters=result[5]
            elif self.model:
                clf=self.model
                pcaComponents=self.pcaComponents
                numClusters=self.numClusters
            else:
                clf=clfs[algorithm]
            #si verificam daca nu cumva la rularea asta tocmai antrenasem ceva aka self.model e statat
            clf.fit(bro_matrix_aux)
            bro_df['score']=clf.decision_function(bro_matrix_aux)
            odd_df=bro_df[features][clf.predict(bro_matrix_aux) !=0]
        
            try:
                odd_matrix = to_matrix.fit_transform(odd_df)
                
                kmeans = KMeans(n_clusters=numClusters).fit_predict(odd_matrix)  
                pca= PCA(n_components=pcaComponents).fit_transform(odd_matrix)
                
                odd_df['x'] = pca[:, 0] 
                odd_df['y'] = pca[:, 1] 
                odd_df['cluster'] = kmeans
                odd_df['jx'] = jitter(odd_df['x'])
                odd_df['jy'] = jitter(odd_df['y'])
                cluster_groups = odd_df.groupby('cluster')
                
                for key, group in cluster_groups:  
                    group.plot(ax=axs[i], kind='scatter', x='jx', y='jy', alpha=0.5, s=250,label='Cluster: {:d}'.format(key), color=colors[key])
                    axs[i].set_title(str(clf).split('(')[0])
                    print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
                    if 'score' in features:
                        top=group[features].sort_values(by='score', ascending=False).head()
                        print(top)
                        self.to_print=self.to_print.append(top)
                            
            except Exception as e:
                print(e)
                 
        plt.show()
        
    
    def buttonActionRetrain(self):
        print("We do retrain same data file")
        
        QMessageBox.about(self,"Warning","Choose connection type you want to train again!")
        self.conn_type=QInputDialog.getItem(self, 'Input Dialog', 'The type of log file u choose:', ['http','conn','ftp'])[0]
        
        #reimprospatam fisierul de log-uri
        #get_zeek_logs()
        print(self.conn_type)
        if self.conn_type=='http':
            self.bro_df,self.features=create_df_http('./logs/http.log')
        elif self.conn_type=='ftp':
            self.bro_df,self.features=create_df_ftp('./logs/ftp.log')
        else:
            self.bro_df,self.features=create_df_conn('./logs/conn.log')
        self.retrain()
        

    def retrain(self):
        bro_df=self.bro_df
        features=self.features
        bro_matrix=to_matrix.fit_transform(bro_df[features],normalize=True)    
        if not self.alg:
            self.alg, done3= QInputDialog.getItem(self, 'Input Dialog', 'The algorithm u choose:', algs)
        clf=clfs[self.alg]
        clf.fit(bro_matrix)
        
        self.models[self.alg]=clf
        
        #asta nu e necesar decat pentru a arata cum arata noile rezultate
        self.numClusters =QInputDialog.getInt(self, 'Clusters', 'Enter number of clusters:')[0]
        self.pcaComponents = QInputDialog.getInt(self, 'PCA', 'Enter different number of pca components to retrain:')[0]
                       
        features.append('score')
        bro_df['score']=clf.decision_function(bro_matrix)
        odd_df=bro_df[features][clf.predict(bro_matrix) !=0]
        odd_matrix = to_matrix.fit_transform(odd_df)
        kmeans = KMeans(n_clusters=self.numClusters).fit_predict(odd_matrix)  
        pca= PCA(n_components=self.pcaComponents).fit_transform(odd_matrix)
        odd_df['x'] = pca[:, 0] 
        odd_df['y'] = pca[:, 1] 
        odd_df['cluster'] = kmeans
        odd_df['jx'] = jitter(odd_df['x'])
        odd_df['jy'] = jitter(odd_df['y'])
        cluster_groups = odd_df.groupby('cluster')
        fig, ax = plt.subplots()
        for key, group in cluster_groups:  
            group.plot(ax=ax, kind='scatter', x='jx', y='jy', alpha=0.5, s=250,label='Cluster: {:d}'.format(key), color=colors[key])
            print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
            if 'score' in features:
                top=group[features].sort_values(by='score', ascending=False).head()
                print(top)
                self.to_print=self.to_print.append(top)
        
        plt.show()
    def buttonGenrateReport(self):
        client_name = "Anomaly Detection Report"
       
        today_date = datetime.today().strftime("%d %b, %Y")
        month = datetime.today().strftime("%B")

        counter=len([entry for entry in os.listdir('.') if (os.path.isfile(os.path.join('.', entry)) and ('result' in entry ) )])
        counter+=1
        context = {'client_name': client_name, 'today_date': today_date, 'month': month,'static_counter':counter}

        f=open(self.res_file)
        data=json.load(f)
        data=data['data']
       
        if self.conn_type=='conn':
            for i in range(len(data)):
                context["proto"+str(i)]=data[i]['proto']
                context["service"+str(i)]=data[i]['service']
                context["resp"+str(i)]=data[i]['id.resp_p']
                context["duration"+str(i)]=data[i]['duration']
                html_template = 'index_conn.html'
            
        elif self.conn_type=='ftp':
            for i in range(len(data)):
                context["command"+str(i)]=data[i]['command']
                context["reply_code"+str(i)]=data[i]['reply_code']
                context["user"+str(i)]=data[i]['user']
                context["password"+str(i)]=data[i]['password']
                context["file_size"+str(i)]=data[i]['file_size']
                context["arg"+str(i)]=data[i]['arg']
                html_template = 'index_ftp.html'
        elif self.conn_type=='http':
            for i in range(len(data)):
                context["id.resp_p"+str(i)]=data[i]['id.resp_p']
                context["method"+str(i)]=data[i]['v']
                context["resp_mime_types"+str(i)]=data[i]['resp_mime_types']
                context["request_body_len"+str(i)]=data[i]['request_body_len']
                html_template = 'index_http.html'
      
        template_loader = jinja2.FileSystemLoader('./sources/')
        template_env = jinja2.Environment(loader=template_loader)

        template = template_env.get_template(html_template)
        output_text = template.render(context)

        config = pdfkit.configuration(wkhtmltopdf='/usr/bin/wkhtmltopdf')

        output_pdf = 'result'+str(counter)+'.pdf'
        pdfkit.from_string(output_text, output_pdf, configuration=config, css='./sources/index.css')

        

       
if __name__ == '__main__':
    #get_zeek_logs()
    app = QApplication(sys.argv)
    demo = UI_MLWindow() 
    demo.show()
    sys.exit(app.exec_())
    