
import re 
import subprocess
from time import sleep
# Extract IPv4 from a string
def get_ips(string):
    ipv4_extract_pattern = "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    return re.findall(ipv4_extract_pattern, string)

log_file='/var/log/suricata/fast.log'
def parse_fast():
    with open(log_file,'r') as f:
        lines=f.readlines()
        for line in lines:
            line=line.split('[**]')
            timestamp=line[0]
            sid_rev_message=line[1]
            proto_ips_ports=line[2]

            [src_ip,dest_ip]=get_ips(proto_ips_ports)
            print(src_ip,dest_ip)

#/var/lib/suricata/rules/custom.rules
#sudo suricata -T -c /etc/suricata/suricata.yaml -v
#dupa ce am detectat activitate malitioasa, vrem sa blocam ip-ul
def write_custom_rules(ip):

    with open('/var/lib/suricata/rules/custom.rules','r') as f:
        start_sid=len(f.readlines())
    action='drop '
    protocol='tcp '
    nets=ip+' any -> $HOME_NET any (' #blocam orice vine de la ip
    message='msg:"preventing intrusions by blocking ip"; '
    flow='flow:established,to_server; '
    content=['content:"USER "; ','content:"|3a 29|"; ']
    sid='sid:2013188' + str(start_sid)+'; '
    rev='rev:1;)\n'

    rule= action+protocol+nets+message+flow
    for c in content:
        rule+=c
    rule=rule+sid+rev
    with open('/var/lib/suricata/rules/custom.rules','a') as f:
        f.write(rule)

    pid=subprocess.check_output(['pidof','suricata']).decode('utf-8').strip()
    ret=  subprocess.run(['suricata' ,'-T', '-c' ,'/etc/suricata/suricata.yaml', '-v']).returncode
    if ret == 0:
        ret = subprocess.run(['kill', '-usr2' ,pid]).returncode
        if ret ==0 :
            print("successfully added rule")




import json
import os
import time
import subprocess

from paramiko import SSHClient
from scp import SCPClient


api_key='ee7a8fa7ab98b3ae4e9677e5c3e936831db3bce50662f1adfd4350be354d035f'

ssh = SSHClient()
ssh.load_system_host_keys()

def search_file_on_lan_host(file,username):
    scp = SCPClient(ssh.get_transport())
    stdin, stdout, stderr = ssh.exec_command('find /home/'+username+ '/Downloads -type f') 
    
    with open(file,'rb') as f:
        content=f.read()
    
    for line in stdout.readlines():
        line=line.strip('\n')
        res=scp.get(line)
        
        remote_filename = './' + line.split('/')[-1]
        print(remote_filename)
        #deschidem si citim din ce am luat local cu get
        with open(remote_filename,'rb') as f:
            if f.read() == content:         
                os.remove(remote_filename)
                return remote_filename 
        #stergem orice am downloadat
        #os.remove(remote_filename)
    return None

def find_malware(file,dest_host,dest_username,dest_pass):
    if os.path.exists(file):

        result = subprocess.run(['./vt-scan.sh','-k',api_key,'-f',file],stdout=subprocess.PIPE)
        result_id = json.loads(result.stdout.decode('utf-8'))
        result_id = result_id['data']['id']
       
        result = subprocess.run(['./vt-scan.sh','-k',api_key,'-a',result_id],stdout=subprocess.PIPE)
        attributes = json.loads(result.stdout.decode('utf-8'))
        while attributes['data']['attributes']['status'] == 'queued':
            result = subprocess.run(['./vt-scan.sh','-k',api_key,'-a',result_id],stdout=subprocess.PIPE)
            attributes = json.loads(result.stdout.decode('utf-8'))
            print("Still searching...")
            time.sleep(1)
        
        attributes = attributes['data']['attributes']
        if attributes['status'] == 'completed':
            
            #if attributes['stats']['malicious'] > 0:
            if True:    
                ssh.connect(hostname=dest_host,username=dest_username,password=dest_pass)
                #cautam fisierul pe hostul din reteaua noastra si stergem fisierul
                remote_filename = search_file_on_lan_host(file,dest_username) 
                if remote_filename != None:
                   print("Deleteing file from remote host: " + remote_filename)
                   #deleteFile(remote_filename,sshconn)
                
        
#write_custom_rules('192.168.144.135')

find_malware('/home/cristiana/Downloads/scwxc.exe','192.168.144.133','cristiana','adorsunca')
ssh.close()