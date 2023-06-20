
import json
import os
import time
import subprocess

from paramiko import SSHClient
from scp import SCPClient

def readHosts():
    hosts = dict()
    with open("known_hosts",'r') as f:
        lines=f.readlines()
        for line in lines:
            line=line.split()
            hosts[line[0]]=[line[1],line[2]]
    return hosts

def deleteFile(filename,sshconn):
    sftp = sshconn.open_sftp()
    sftp.remove(filename)
    print("Successfully deleted: ",filename)
    sftp.close()

def searchFile(local_filename,sshconn):
    scp = SCPClient(ssh.get_transport())
    stdin, stdout, stderr = sshconn.exec_command('find /home/ -type f') #am putea pune /home/Downloads
    with open(local_filename,'rb') as f:
        content=f.read()
    for line in stdout:
        line=line.strip('\n')
        scp.get(line)
        remote_filename = './' + line.split('/')[-1]
        #deschidem si citim din ce am luat local cu get
        with open(remote_filename,'rb') as f:
            if f.read() == content:         
                os.remove(remote_filename)
                return remote_filename 
        #stergem orice am downloadat
        os.remove(remote_filename)
        break
    return None


api_key='ee7a8fa7ab98b3ae4e9677e5c3e936831db3bce50662f1adfd4350be354d035f'

def findMalware(sshconn,hosts):
    for d in os.listdir('/nsm/import/bro/'):
        bro_file='/nsm/import/bro/' + d + '/files.log'
        
        with open(bro_file,'r') as f:
            lines=f.readlines()
            for line in lines:
                data=json.loads(line)
                if data.get('extracted') is not None:
                    source_ip=data['tx_hosts'][0]
                    dest_ip=data['rx_hosts'][0]
                    #dest_ip='10.10.181.105'
                    extracted_file=data['extracted']
        if extracted_file and os.path.exists(extracted_file):
            
            #daca destinatia este o victima din reteaua nastra            
            [username,password] = hosts[dest_ip]
            sshconn.connect(hostname=dest_ip,username=username,password=password)


            result = subprocess.run(['./vt-scan.sh','-k',api_key,'-f',extracted_file],stdout=subprocess.PIPE)
            result_id = json.loads(result.stdout.decode('utf-8'))
            result_id = result_id['data']['id']
            print(result_id)
            result = subprocess.run(['./vt-scan.sh','-k',api_key,'-a',result_id],stdout=subprocess.PIPE)
            attributes = json.loads(result.stdout.decode('utf-8'))
            while attributes['data']['attributes']['status'] == 'queued':
                result = subprocess.run(['./vt-scan.sh','-k',api_key,'-a',result_id],stdout=subprocess.PIPE)
                attributes = json.loads(result.stdout.decode('utf-8'))
                print("Still searching...")
                time.sleep(1)
            
            attributes = attributes['data']['attributes']
            if attributes['status'] == 'completed':
                print("Found!")
                if attributes['stats']['malicious'] > 0:
                    #cautam fisierul pe hostul din reteaua noastra si stergem fisierul
                    remote_filename = searchFile(extracted_file,sshconn) 
                    if remote_filename != None:
                        print("Deleteing file from remote host: " + remote_filename)
                        deleteFile(remote_filename,sshconn)
                    #TODO write suricata rule to rejectsrc
                    print(source_ip,dest_ip)




ssh = SSHClient()
ssh.load_system_host_keys()
#hosts=readHosts()

#ssh.connect(hostname=ip,username=name,password=password)
#findMalware(ssh,hosts)

#subprocess.Popen(["suricata", "-c" ,"/etc/nsm/onion-vm-ens192/suricata.yaml", "-i","ens192"])

subprocess.run("for i in `seq 1 1000`; do mysql -uroot -pwrong -h 10.10.181.104 -P3306 ; done", shell=True, check=True)
ssh.close()

#sudo suricata -c /etc/nsm/onion-vm-ens192/suricata.yaml -i ens192
