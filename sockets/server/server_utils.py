import numpy as np
import subprocess
import re
import glob
import os 
import pandas as pd

http_log_file='/home/cristiana/pyqt/two_windows/logs/http.log'
conn_log_file='/home/cristiana/pyqt/two_windows/logs/conn.log'
file_log_file='/home/cristiana/pyqt/two_windows/logs/files.log'

file_features=['mime_type','duration','total_bytes','seen_bytes','orig_h']
conn_features=['service','duration', 'proto', 'resp_p','conn_state','orig_pkts','orig_h']
http_features = ['method','resp_p', 'resp_mime_types', 'orig_mime_types','orig_h','request_body_len','response_body_len']
import csv 
import json 

def csv_to_json(path):
    output=subprocess.call('/home/cristiana/pyqt/two_windows/logs/parse_before.sh',shell=True)
    onlyfiles = [os.path.join(path, f) for f in os.listdir(path) if os.path.isfile(os.path.join(path, f)) and f.endswith('.log')]
    for file in onlyfiles:
        try:
            jsonArray = []
            with open(file, encoding='utf-8') as csvf: 
                csvReader = csv.DictReader(csvf,delimiter='\t') 
                for row in csvReader: 
                    jsonArray.append(row)
            with open(file, 'w', encoding='utf-8') as jsonf: 
                jsonString = json.dumps(jsonArray, indent=4)
                jsonf.write(jsonString)
        except:
            pass
# Extract IPv4 from a string
def get_ips(string):
    ipv4_extract_pattern = "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    return re.findall(ipv4_extract_pattern, string)


def jitter(arr):
    stdev = .02*(max(arr)-min(arr))
    return arr + np.random.randn(len(arr)) * stdev

def warn(*args, **kwargs):
    pass

def clean_df(df):
    df=df.dropna()
    df=df.applymap(str)
    return df
def create_df_file(file):
    with open(file,'r') as f:
        bro_df=pd.DataFrame( json.load(f))
    bro_df=clean_df(bro_df)
    bro_df.rename(columns = {'id.orig_h':'orig_h'}, inplace = True)
    return bro_df,file_features
def create_df_conn(file):
    with open(file,'r') as f:
        bro_df=pd.DataFrame( json.load(f))
    bro_df=clean_df(bro_df)
    bro_df.rename(columns = {'id.resp_p':'resp_p','id.orig_h':'orig_h'}, inplace = True)
    return bro_df,conn_features
def create_df_http(file):
    with open(file,'r') as f:
        bro_df=pd.DataFrame( json.load(f))
    bro_df=clean_df(bro_df)
    bro_df.rename(columns = {'id.resp_p':'resp_p','id.orig_h':'orig_h'}, inplace = True)
    return bro_df,http_features



#serverul aduna toate log-urile 
#din capturile aferente de trafic, general fiserele de log, pe care zeek le pune default in folderul curent asa ca le mutam in folderul de logs
#la nevoie, functia poate fi reapelata
def get_zeek_logs():
    try:
        output=subprocess.check_output(['zeek','-C','-r','/home/cristiana/capfiles/capfile1'])
    except subprocess.CalledProcessError as e:
        print(e.output)
    output=subprocess.call('mv /home/cristiana/pyqt/two_windows/sockets/server/*.log /home/cristiana/pyqt/two_windows/logs/',shell=True)
    csv_to_json('/home/cristiana/pyqt/two_windows/logs/')




from sklearn.metrics import silhouette_score
from sklearn.cluster import KMeans

#se apeleaza cu bro_matrix
def detect_optimal_number_of_clusters(feature_matrix):
    #silhouette scoring este o măsură a cât de asemănător este un obiect cu propriul său cluster în comparație cu alte clustere (separare). Silueta variază de la -1 la 1, unde o valoare mare indică faptul că obiectul este bine potrivit cu acesta. propriul cluster și prost potrivit cu clusterele învecinate. Dacă majoritatea obiectelor au o valoare mare, atunci configurația de clustering este adecvată. Dacă multe puncte au o valoare scăzută sau negativă, atunci configurația clustering poate avea prea multe sau prea puține clustere.
    #testam valoarea scorului pana cand ne este indeicat numarul optim de clustere din grafic, apoi introducem in interfata parametrii pe care ii dam algoritmului
    scores = []
    clusters = range(2,10)
    feature_matrix_aux=feature_matrix.copy()
    for K in clusters:
        clusterer = KMeans(n_clusters=K)
        try:
            cluster_labels = clusterer.fit_predict(feature_matrix_aux)
            score = silhouette_score(feature_matrix_aux, cluster_labels)
            scores.append(score)
        except Exception as e:
            print("Stopping here ",e)
            break
    return scores


from zat.dataframe_to_matrix import DataFrameToMatrix
to_matrix = DataFrameToMatrix()
from sklearn.decomposition import PCA
from sklearn.cluster import AgglomerativeClustering

def get_cluster_groups(df,ftrs,clf,bro_matrix,numClusters,pcaComponents,clustering_alg):
    df['score']=clf.decision_function(bro_matrix)
    
    odd_df=df[ftrs][clf.predict(bro_matrix) == -1] #y=-1 abnormal y=1 normal
    
    odd_matrix = to_matrix.fit_transform(odd_df)
    #demonstarm faptul ca numarul de clustere pentru punctele detectate ca fiind outliere este la fel ca cel pentru setul initial de date
    # self.detect_optimal_number_of_clusters(odd_matrix,algorithm)
    #detectam punctele outlier si le grupam in clustere
    if clustering_alg=='kmeans':
        clustering = KMeans(n_clusters=numClusters).fit_predict(odd_matrix)  
    else: 
        clustering = AgglomerativeClustering(n_clusters=numClusters).fit_predict(odd_matrix)
    pca= PCA(n_components=pcaComponents).fit_transform(odd_matrix)
    

    clustering_normal = KMeans(n_clusters=numClusters).fit_predict(bro_matrix)  
    pca_normal=PCA(n_components=pcaComponents).fit_transform(bro_matrix)
    df['x']=pca_normal[:,0]
    df['y'] = pca_normal[:, 1] 
    df['cluster'] = clustering_normal
    df['jx'] = jitter(df['x'])
    df['jy'] = jitter(df['y'])
    normal_groups=df.groupby('cluster')
    
    odd_df['x'] = pca[:, 0] 
    odd_df['y'] = pca[:, 1] 
    odd_df['cluster'] = clustering
    #jitter este folosit pentru a putea proiecta in 2D PCA in oricate dimensiuni
    odd_df['jx'] = jitter(odd_df['x'])
    odd_df['jy'] = jitter(odd_df['y'])
    #avem n_clusters liste de dictiona
    
    cluster_groups = odd_df.groupby('cluster')
    result=dict()
    for key, group in cluster_groups:
        res=group.to_json(orient='records')#string representation    
        result[str(key)]=res
    
    result=json.dumps(result)
    return result


import ssl
import socket
import paramiko

def str_to_dict(string):
    string = string.strip('{}')
    pairs = string.split('; ')
    return {key: value for key, value in (pair.split(':') for pair in pairs if ':' in pair) }


def get_remote_stdout(cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.144.133', username='cristiana', password=os.environ.get('servicepassword'))

    stdin_raw, stdout_raw, stderr_raw = client.exec_command(cmd)
    stdout_raw.channel.recv_exit_status() 
    print(stdout_raw,stderr_raw)
    stdout = []
    for line in stdout_raw: stdout.append(line.strip())
    stderr=[]
    for line in stderr_raw: stderr.append(line.strip())
    client.close()
    del client, stdin_raw, stdout_raw, stderr_raw
    return stdout,stderr

def get_remote_stdout_sudo(cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('192.168.144.133', username='cristiana', password=os.environ.get('servicepassword'))
   
    stdin_raw, stdout_raw, stderr_raw = client.exec_command(cmd,get_pty = True)
    
    stdin_raw.write(os.environ.get('servicepassword')+ '\n')
    stdin_raw.flush()
    stdout_raw.channel.recv_exit_status() 

    stdout = []
    for line in stdout_raw: stdout.append(line.strip())
    stderr=[]
    for line in stderr_raw: stderr.append(line.strip())
    client.close()
    del client, stdin_raw, stdout_raw, stderr_raw
    return stdout,stderr

def parse_rule_file():
    rule_file='/etc/snort/rules/local.rules'
    data=[]

    rules,err=get_remote_stdout(f'cat {rule_file}')
    
    for i,rule in enumerate(rules):
        action=rule.split(' ')[0]
        if "#" not in action:
           
            proto=rule.split(' ')[1]
            source_net= rule.split(' ')[2]
            source_port=rule.split(' ')[3]
            dest_net=rule.split(' ')[5]
            dest_port=rule.split(' ')[6]
            message='{'+"action:"+action+"; proto:"+proto+"; source_net:"+source_net+"; source_port:"+source_port+"; dest_net:"+dest_net+"; dest_port:"+dest_port+"; " +rule.split('(')[1].split(')')[0][:-1]+'}'
            message=message.replace('msg','Rule')
            
            try:
                data.append(str_to_dict(message))
            except: pass

    return data
    
def parse_alert_file():
    data=[]
    keys=["@timestamp","Alert","protocol","source","destination"]
  
    alerts,err=get_remote_stdout("cat /var/log/snort/alert")
    
    for alert in alerts:
        try:
            alert_dict={}
            alert_dict[keys[0]]=alert.split('[**] ')[0].strip()
            alert_dict[keys[1]]=alert.split('[**]')[1].split(']')[1].strip()
            alert_dict[keys[2]]=alert.split('{')[1].split('}')[0]
            alert_dict[keys[3]]=alert.split(' ')[-3]
            alert_dict[keys[4]]=alert.split(' ')[-1]
            data.append(alert_dict)
        except:
            print(alert)
    
    return data

def init():
    get_zeek_logs()

init()