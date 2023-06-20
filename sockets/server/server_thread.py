import sys
sys.dont_write_bytecode = True

import socket
import threading
import ssl
import json 

from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM


sys.path.insert(1, '/home/cristiana/pyqt/two_windows/')

from server_utils import *
from connect import *

import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)
warnings.warn = warn



algs =[ 'IForest','OneClassSVM']
clfs= dict()
clfs[algs[0]]=IsolationForest(contamination=0.25)
clfs[algs[1]]=OneClassSVM(gamma='auto')



class ServerThread(threading.Thread):
    def __init__(self, client_socket, client_address):
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.client_address = client_address

        self.iteration=0
        self.model=None
        self.response_compare=None
        self.models=dict()
        self.parameters=None
        self.clusterningAlg='kmeans1'

    def run(self):
        print(f"Connected to {self.client_address}")
         # Wrap the socket with SSL/TLS
        ssl_client_socket = ssl.wrap_socket(self.client_socket, server_side=True, certfile='../server.crt', keyfile='../ca_key.prv', ssl_version=ssl.PROTOCOL_TLS)

        while True:
            data = ssl_client_socket.recv(2048).decode()
            if not data:
                break
            print(f"Received message from {self.client_address}: {data}")
            
            data=json.loads(data)
            action=data['action']
            #actions from UI client
            if action =='init':
                #liste de dictionare
                try:
                    rules=parse_rule_file()
                    alerts=parse_alert_file()
                    print(rules,alerts)
                    response=dict()
                    response['rules']=json.dumps(rules)
                    response['alerts']=json.dumps(alerts)
                    response=json.dumps(response)
                except:
                    response='error in getting rules and alerts from remote machine'
                ssl_client_socket.sendall(response.encode())
            elif action == 'block' :
                ip=data['additional']
                res,err=get_remote_stdout_sudo(f'sudo iptables -A INPUT -s {ip} -j DROP')
                if not err: response='blocked'
                else: response='error in blocking ip with iptables firewall'
                ssl_client_socket.sendall(response.encode())
            elif action == 'add' :
                new_rule=data['additional']
                res,err=response,err=get_remote_stdout_sudo(f"sudo echo '{new_rule}' >> /etc/snort/rules/local.rules; sudo service snort restart")
                if not err: response='added'
                else: response='error in adding local snort rules'
                ssl_client_socket.sendall(response.encode())
            #actions from ML client
            else:
                try:
                    self.conn_type=data['conn']
                    self.bro_df,self.features=create_df_conn(conn_log_file)  if 'conn' == self.conn_type else create_df_file(file_log_file) if 'file' == self.conn_type else create_df_http(http_log_file) 
                except: 
                    response="error parsing log data"
                    ssl_client_socket.sendall(response.encode())
                    break
                if action=='ok':
                    bro_df_aux=self.bro_df.copy()
                    try:
                        bro_matrix=to_matrix.fit_transform(bro_df_aux[self.features],normalize=True)   
                        scores=detect_optimal_number_of_clusters(bro_matrix)
                        response=dict()
                        alg_by_conn,conn_by_alg=get_statistics()
                        response['statistics']=json.dumps(conn_by_alg)
                        response['scores']=" ".join(map(lambda x : str(x),scores))
                        response=json.dumps(response)
                    except:
                        response='error in getting statistics'
                elif action=='train':
                    self.alg=data['alg']
                    if 'parameters' in data:
                        self.parameters=data['parameters']
                    if data['how']=='yes':
                        #load model from database
                        print('using already trained model')
                        try:
                            self.read_data_model()
                            if self.model:
                                #aducem datele din bd
                                try:
                                    self.bro_df,self.features=get_data(self.conn_type,self.iteration)
                                    try:
                                        response=self.already_train()
                                        self.models[self.alg]=self.model
                                    except: response="error Can't use already trained model!"
                                except: response='error reading data from db!'
                            else:response="error performing this action. Train sth first!"
                        except: response='error reading data from db!'  
                    else:
                        print("Training model for connection type based on log file")
                        self.pcaComponents=data['pcaComponents']
                        self.numClusters=data['numClusters']
                        try:
                            response=self.train()
                        except: response='error training model!'
                elif action=='retrain':
                    if 'parameters' in data:
                        self.parameters=data['parameters']
                    #upate parameters anc call train
                    self.pcaComponents=data['pcaComponents']
                    self.numClusters=data['numClusters']
                    print('Retraining model for: '+self.alg)
                    # try:  
                    response=self.retrain()
                    # except: response='error RE-training model!'
                elif action == 'save':
                    if self.response_compare:
                        self.alg=data['alg']
                        self.model=self.models[data['alg']]
                        self.response_compare=None
                    # try: #TODO punem try except-urile aici sau in functiile de save si read ca sa inconjuram functiile ce lucreaza cu bd ??
                    response=self.save()
                    # except: response='error saving model to db!'
                elif action=='compare':
                    if data['how'] == 'no':
                        self.pcaComponents=data['pcaComponents']
                        self.numClusters=data['numClusters']
                    #else ramane ce aveam
                    try:
                        self.response_compare=self.compare()
                        response=json.dumps(self.response_compare)
                    except: response='error creating comparison statistics!'
            
                ssl_client_socket.sendall(response.encode())
            
                
        self.client_socket.close()
        print(f"Connection closed with {self.client_address}")


    def already_train(self):
        df=self.bro_df.copy()
        ftrs=self.features.copy()
        bro_matrix=to_matrix.fit_transform(df[ftrs],normalize=True)        
        ftrs.append('score')
        clf=self.model
        return get_cluster_groups(df,ftrs,clf,bro_matrix,self.numClusters,self.pcaComponents,self.clusterningAlg)
        
    def train(self):
    
        df=self.bro_df.copy()
        ftrs=self.features.copy()
        bro_matrix=to_matrix.fit_transform(df[ftrs],normalize=True)               
        ftrs.append('score')
        clf=clfs[self.alg]
        if self.parameters:
            for param in self.parameters.keys():
                if param=='max_features': clf.set_params(max_features=int(self.parameters[param]))
                if param=='random_state': clf.set_params(random_state=int(self.parameters[param]))
                if param=='contamination' and self.parameters[param]  != 'auto': clf.set_params(contamination=float(self.parameters[param]))
        clf.fit(bro_matrix)
        self.model=clf
        self.models[self.alg]=self.model
        return get_cluster_groups(df,ftrs,clf,bro_matrix,self.numClusters,self.pcaComponents,self.clusterningAlg)
    
    def retrain(self):
        get_zeek_logs()
        self.bro_df,self.features=create_df_conn(conn_log_file)  if 'conn' == self.conn_type else create_df_file(file_log_file) if 'file' == self.conn_type else create_df_http(http_log_file) 
        result = self.train()
        # pickle.dump(self.model,open('./model.sav','wb'))
        # with open('./model.sav','rb') as f: bytes_model=f.read()
        # update_model((b64encode(bytes_model).decode('utf-8')),self.pcaComponents,self.numClusters,self.alg,self.conn_type,self.iteration)
        # update_data(self.conn_type,self.iteration)
        return result
        
    def compare(self):
        bro_df=self.bro_df.copy()
        features=self.features.copy()
        
        bro_matrix=to_matrix.fit_transform(bro_df[features],normalize=True)        
        features.append('score')
        
        result=dict()
        for algorithm in clfs.keys():
            bro_matrix_aux=bro_matrix.copy()
            model_result=get_model(self.conn_type,algorithm)
            if model_result:#ne folosim de ceea ce aveam antrenat in bd, nu reantrenam
                try:
                    with open('./model.sav','wb') as f:
                        f.write(b64decode(model_result[1]))
                        clf=pickle.load(open('./model.sav','rb'))
                    pcaComponents=model_result[4]
                    numClusters=model_result[5]
                    cluser_greoup_fo_alg=get_cluster_groups(bro_df,features,clf,bro_matrix_aux,numClusters,pcaComponents,self.clusterningAlg)
        
                except:
                    if self.model and self.alg == algorithm:
                        clf=self.model
                    else: #altfel, antrenam acum #TODO ADAUGA OPTUNE SA POATA SALVA
                        clf=clfs[algorithm]
                        clf.fit(bro_matrix_aux)
                    pcaComponents=self.pcaComponents
                    numClusters=self.numClusters 
                    cluser_greoup_fo_alg=get_cluster_groups(bro_df,features,clf,bro_matrix_aux,numClusters,pcaComponents,self.clusterningAlg)
            else: # antrenam modelul cu parametrii de la celalt model antrenat deja
                clf=clfs[algorithm]
                clf.fit(bro_matrix_aux)
                pcaComponents=self.pcaComponents
                numClusters=self.numClusters 
                cluser_greoup_fo_alg=get_cluster_groups(bro_df,features,clf,bro_matrix_aux,numClusters,pcaComponents,self.clusterningAlg)
                #Tin minte si modelul nou antrenat in caz ca se doreste salvarea acestuia in BD de catre user
                self.models[algorithm]=clf
    
            result[algorithm]=cluser_greoup_fo_alg
        
        return result    
 
    def save(self):

        pickle.dump(self.model,open('./model.sav','wb'))
        with open('./model.sav','rb') as f:
            bytes_model=f.read()
        insert_model((b64encode(bytes_model).decode('utf-8')),self.alg,self.conn_type,self.pcaComponents,self.numClusters,str(int(self.iteration)+1))
        insert_data(self.conn_type,str(int(self.iteration)+1))
        return 'Successfully saved to db!'

    def read_data_model(self):
        print('Readig already trained data model')
        result =  get_model(self.conn_type,self.alg)
        with open('./model.sav','wb') as f:
            f.write(b64decode(result[1]))
        self.model=pickle.load(open('./model.sav','rb'))
        self.pcaComponents=result[4]
        self.numClusters=result[5]
        self.iteration=result[6]
        print(f"here: {self.pcaComponents} {self.numClusters} {self.iteration}")



def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server started on {host}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()
        thread = ServerThread(client_socket, client_address)
        thread.start()

if __name__ == "__main__":
    host = '0.0.0.0'
    port = 5001
    start_server(host, port)