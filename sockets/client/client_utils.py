import matplotlib.pyplot as plt
import glob,os
import pandas as pd
import json
import ssl
import socket
from PyQt5 import QtWidgets

import paramiko
import os



colors = {0:'green', 1:'blue', 2:'red',3:'yellow', 4:'purple', 5:'brown',6:'pink',7:'olive',8:'cyan',9:'gray'}
params = {'axes.labelsize': 2,'axes.titlesize':5,  'legend.fontsize': 5, 'xtick.labelsize': 2, 'ytick.labelsize': 2}


file_features=['mime_type','duration','total_bytes','seen_bytes','orig_h']
conn_features=['service','duration', 'proto', 'resp_p','conn_state','orig_pkts','orig_h']
http_features = ['method','resp_p', 'resp_mime_types', 'orig_mime_types','orig_h','request_body_len','response_body_len']


def str_to_dict(string):
    string = string.strip('{}')
    pairs = string.split('; ')
    return {key: value for key, value in (pair.split(':') for pair in pairs if ':' in pair) }

    
def get_response_from_ssl_socker(action,additional_data=None):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('0.0.0.0',5001))
    ssl_client_socket=ssl.wrap_socket(client_socket, cert_reqs=ssl.CERT_REQUIRED, ca_certs='../server.crt', ssl_version=ssl.PROTOCOL_TLS)
    
    data=dict()
    data['action']=action
    data['additional']=additional_data
    ssl_client_socket.send(json.dumps(data).encode())
    response=ssl_client_socket.recv(1024).decode()
    final=response
    while len(response) == 1024:
        response=ssl_client_socket.recv(1024).decode()
        final+=response

    ssl_client_socket.close()
    client_socket.close()
    return final



def addSaveButton(layout,action,align,algorithm):
    buttonSave = QPushButton(f"Save {algorithm}")
    buttonSave.clicked.connect(action)
    layout.addWidget(buttonSave,alignment=align)
    
def plot_for_compare(layout,figure,canvas,data,ftrs,action):
    for i,algorithm in enumerate(data):
        cluster_groups=json.loads(data[algorithm])
        axs=figure.add_subplot(int(f'21{i+1}'))

        show_clusters=dict()
        cluster_groups = {key[::-1]: value for key, value in cluster_groups.items()}
        for key in cluster_groups:
            group=pd.read_json(cluster_groups[key])
            key=int(key)
            group.plot(ax=axs, kind='scatter', x='jx', y='jy', alpha=0.5, s=250,label='Cluster: {:d}'.format(key), color=colors[key])  
            print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
            if 'score' in ftrs:
                    top=group[ftrs].sort_values(by='score', ascending=True)#.head() 
                    print(top.head())
                    # for_cluster=dict()
                    # for column in top.columns:
                    #     if top[column].nunique() == 1 and all(top[column] != '-') and column != 'score':
                    #         for_cluster[column]=str(top[column][0])
                            
            # show_clusters[key]=for_cluster
        addSaveButton(layout,action,Qt.AlignCenter,algorithm)
    
    
    canvas.show()
    canvas.setSizePolicy(QtWidgets.QSizePolicy.Expanding,QtWidgets.QSizePolicy.Fixed)

    canvas.draw() 
  
def plot_cluster_groups(layout,figure,canvas,cluster_groups,ftrs):

    axs=figure.add_subplot(111)

    show_clusters=list()
    cluster_groups = {key[::-1]: value for key, value in cluster_groups.items()}
    for key in cluster_groups:
        group=pd.read_json(cluster_groups[key])
        key=int(key)
        group.plot(ax=axs, kind='scatter', x='jx', y='jy', alpha=0.5, s=250,label='Cluster: {:d}'.format(key), color=colors[key])  
        print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
        if 'score' in ftrs:
            top=group[ftrs].sort_values(by='score', ascending=True)#.head() 
            print(top.head())
            show_clusters.append(top)
    canvas.show()
    canvas.setSizePolicy(QtWidgets.QSizePolicy.Expanding,QtWidgets.QSizePolicy.Fixed)
    canvas.resize(400,400)
    canvas.draw() 
    return show_clusters

from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

def create_slider():
    contaminationSlider = QSlider(Qt.Horizontal)
    contaminationSlider.setFocusPolicy(Qt.StrongFocus)
    contaminationSlider.setTickPosition(QSlider.TicksBothSides)
    contaminationSlider.setMaximumHeight(50)
    contaminationSlider.setTickInterval(5)
    contaminationSlider.setSingleStep(1)
    return contaminationSlider

def create_label_for_slider():
    label= QLabel("0")
    label.setAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignBottom)
    label.setMaximumHeight(70)
    return label

def create_message_box(message,warning):
    msgBox=QtWidgets.QMessageBox()
    msgBox.setIcon(warning)
    msgBox.setText(message)
    msgBox.setStandardButtons(QMessageBox.Ok)
    msgBox.exec()
    
def addRadioButtons(parentLayout,callback):
        gridlayout = QGridLayout()

        connRadio = QRadioButton("conn")
        connRadio.file = "conn"
        connRadio.toggled.connect(callback)
        gridlayout.addWidget(connRadio, 0, 0)

        httpRadio = QRadioButton("http")
        httpRadio.file = "http"
        httpRadio.toggled.connect(callback)
        gridlayout.addWidget(httpRadio, 0, 1)

        fileRadio  = QRadioButton("file")
        fileRadio.file = "file"
        fileRadio.toggled.connect(callback)
        gridlayout.addWidget(fileRadio, 0, 2)
        parentLayout.addLayout(gridlayout)


def init():
    global rules,alerts
    rules=[]
    alerts=[]
