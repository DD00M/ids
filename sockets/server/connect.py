from clickhouse_driver import Client
# import csv
import json
from server_utils import *

#TODO full automation: get mode, run over log files, get anomaly clusters, get reports
client =  Client('192.168.144.133',
                user='cristiana',
                password=os.environ.get('dbpassword'),
                database='logs')

def format_file(file,features,iteration):
    with open(file,'r') as f:
        data=json.load(f)
    
    for d in data: 
        for key in list(d.keys()):
            if key not in features:
                if key != 'id.resp_p' and key != 'id.orig_h':
                    del d[key]
                else:
                    if key == 'id.resp_p':d['resp_p']=str(d.pop(key))
                    else: d['orig_h']=str(d.pop(key))
            else:
                d[key]=str(d[key])

        d['iteration']=str(iteration)
    return data
def insert_data(conn_type,iteration):
    if conn_type=='http':
        data=format_file(http_log_file,http_features,iteration)
    elif conn_type=='conn':
        data=format_file(conn_log_file,conn_type,iteration)
    elif conn_type=='file':
        data=format_file(file_log_file,file_features,iteration)
    client.execute(f"INSERT INTO {conn_type} FORMAT JSONEachRow", (d for d in data))

def update_data(conn_type,iteration):
    client.execute(f"ALTER TABLE {conn_type} DELETE WHERE iteration='{iteration}'")
    #inseram noile log-uri pentru aceeasi iteratie
    insert_data(conn_type,iteration)

   


def create_table(conn_type,features):
    exists=f'exists {conn_type}'
    result=client.execute(exists)[0][0]
    if result == 0:
        if conn_type=='model':
            query="""
                CREATE TABLE model (
                id UUID,
                content String,
                algorithm String,
                conn_type String,
                pca UInt32,
                clusters UInt32,
                iteration String
                ) ENGINE = MergeTree() 
                PRIMARY KEY id 
                ORDER BY id;
                """
        else:
            query=f"CREATE TABLE {conn_type} ("
            for feature in features:
                query=query+feature +" String, "
            query=query+f"iteration String) ENGINE MergeTree ORDER BY {features[0]}"
        
        client.execute(query)

create_table('conn',conn_features)
create_table('http',http_features)
create_table('file',file_features)
create_table('model',features=None)


def get_data(conn_type,iteration):
    #execute('SET output_format_json_named_tuples_as_objects = 1') #nu face nimic, returneaza tot ca tuple
    data=client.execute_iter(f"select * from {conn_type} where iteration = '{iteration}'",with_column_types=True)
    columns = [column[0] for column in next(data)]
    #result=[json.dumps(dict(zip(columns, [value for value in row]))) for row in data]
    df = pd.DataFrame.from_records(data, columns=columns)
    df=clean_df(df)
    df.drop('iteration',axis=1,inplace=True)
    return df,columns[:-1]
    
 
import pickle
from base64 import b64encode,b64decode
def insert_model(ml_model,alg,conn_type,pca,clusters,iteration):
    client.execute(f"insert into model values(generateUUIDv4(),'{ml_model}','{alg}','{conn_type}',{pca},{clusters},{iteration} );")
#update model cand reantrenam
def update_model(new_model,new_pca,new_clusters,algorithm,conn_type,iteration):
    client.execute(f"ALTER TABLE model UPDATE content='{new_model}', pca={new_pca}, clusters={new_clusters} WHERE algorithm='{algorithm}' AND conn_type='{conn_type}' AND iteration={iteration}")
def get_model(conn_type,alg):
    query=f"select * from model where conn_type='{conn_type}' and algorithm='{alg}'"
    result=client.execute(query)
    #vrem ultima iteratie
    return result[len(result)-1] if len(result) else None

def get_statistics():
    return client.execute("select count(algorithm),conn_type,algorithm from model group by conn_type,algorithm"),client.execute("select count(conn_type),algorithm,conn_type from model group by algorithm,conn_type")

def get_last_iteration_number(connt_type,alg):
    result=client.execute(f"select top 1 iteration from model where algorithm='{alg}' and conn_type='{connt_type}' order by iteration desc")
    return result[0][0] if result else '0'
    


