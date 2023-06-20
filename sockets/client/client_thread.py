import socket
import ssl
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
def get_all_data(socket):
    data=socket.recv(1024).decode()
    final=data
    while len(data)==1024:
        data=socket.recv(1024).decode()
        final+=data
    return final
class ClientThread(QThread):
    received = pyqtSignal(str)

    def __init__(self, parent=None):
        super(ClientThread, self).__init__(parent)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = '0.0.0.0'
        self.port = 5001
        self.client_socket.connect((self.host, self.port))
        self.received.emit('Connected to server.')
        self.ssl_client_socket = ssl.wrap_socket(self.client_socket, cert_reqs=ssl.CERT_REQUIRED, ca_certs='../server.crt', ssl_version=ssl.PROTOCOL_TLS)
        

    def run(self):
        while True:
            final=get_all_data(self.ssl_client_socket)
            self.received.emit(final)
        self.client_socket.close()
    def send_message(self, message):
        self.ssl_client_socket.send(message.encode())
