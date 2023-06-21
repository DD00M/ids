import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QComboBox, QCheckBox, QMessageBox
from PyQt5.QtCore import Qt,pyqtSignal


import client_utils
from block_ips import *

class SnortRuleForm(QWidget):
    window_closed = pyqtSignal()
    def __init__(self, Window_object=None):
        self.window_object = Window_object
        super().__init__()
        self.initUI()
    def closeEvent(self, event):
        self.window_closed.emit()
        event.accept()
    def initUI(self):
        self.setWindowTitle('Snort Rule Form')
        self.IPWindow=None
        self.create_top_form()


    def create_top_form(self):
        rule_id_label = QLabel('SID:')
        self.rule_id_input = QLineEdit()
        self.msgBox = QMessageBox()

        protocol_label = QLabel('Protocol:')
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItem('TCP')
        self.protocol_combo.addItem('UDP')
        self.protocol_combo.addItem('ICMP')

        source_ip_label = QLabel('Source IP:')
        self.source_ip_input = QLineEdit()
        self.source_ip_input.setPlaceholderText('192.168.144.133/any')
        source_port_label = QLabel('Source Port:')  
        self.source_port_input = QLineEdit()
        self.source_port_input.setPlaceholderText('80/any')

        dest_ip_label = QLabel('Destination IP:')
        self.dest_ip_input = QLineEdit()
        self.dest_ip_input.setPlaceholderText('192.168.144.133/any')
        dest_port_label = QLabel('Destination Port:')
        self.dest_port_input = QLineEdit()
        self.dest_port_input.setPlaceholderText('80/any')

        action_label = QLabel('Action:')
        self.action_input = QLineEdit()
        self.action_input.setPlaceholderText('alert/pass/log')

        message_text_label = QLabel("Message text:")
        self.message_text_input = QLineEdit()

        class_type_label = QLabel("Class-Type:")
        self.class_type_input = QComboBox()
        self.flow_input = QComboBox()
        self.class_type_input.addItem('None')
        self.class_type_input.addItem('web-application-attack')
        self.class_type_input.addItem('web-application-activity')
        self.class_type_input.addItem('network-scan')
        self.class_type_input.addItem('denial-of-service')
        self.class_type_input.addItem('misc-activity')
        self.class_type_input.addItem('file-format')

        flow_label = QLabel("Flow:")
        self.flow_input = QComboBox()
        self.flow_input.addItem('None')
        self.flow_input.addItem('stateless')
        self.flow_input.addItem('from_server')
        self.flow_input.addItem('to_server')
        self.flow_input.addItem('from_server,established')
        self.flow_input.addItem('to_server,established')

        gid_label = QLabel("rev:")
        self.gid_input = QLineEdit()

        submit_button = QPushButton('Submit')
        submit_button.clicked.connect(self.submit)

        layout = QVBoxLayout()

        form_layout = QHBoxLayout()
        form_layout.addWidget(rule_id_label)
        form_layout.addWidget(self.rule_id_input)
        form_layout.addWidget(protocol_label)
        form_layout.addWidget(self.protocol_combo)
        form_layout.addWidget(source_ip_label)
        form_layout.addWidget(self.source_ip_input)
        form_layout.addWidget(source_port_label)
        form_layout.addWidget(self.source_port_input)
        form_layout.addWidget(dest_ip_label)
        form_layout.addWidget(self.dest_ip_input)
        form_layout.addWidget(dest_port_label)
        form_layout.addWidget(self.dest_port_input)
        form_layout.addWidget(action_label)
        form_layout.addWidget(self.action_input)

        layout.addLayout(form_layout)

    
        second_row_layout = QHBoxLayout()
        second_row_layout.addWidget(message_text_label)
        second_row_layout.addWidget(self.message_text_input)
        second_row_layout.addWidget(class_type_label)
        second_row_layout.addWidget(self.class_type_input)
        second_row_layout.addWidget(flow_label)
        second_row_layout.addWidget(self.flow_input)
        second_row_layout.addWidget(gid_label)
        second_row_layout.addWidget(self.gid_input)

        layout.addLayout(second_row_layout)

        content_layout = QHBoxLayout()
        content_label = QLabel("Content: ")
        self.content_input=QLineEdit()
        content_layout.addWidget(content_label)
        content_layout.addWidget(self.content_input)
        layout.addLayout(content_layout)


        detection_layout = QHBoxLayout()
        filter = QLabel("Detection Filter")
        self.filter_combo = QComboBox()
        self.filter_combo.addItem('None')
        self.filter_combo.addItem('track by_dst')
        self.filter_combo.addItem('track by_src')
        

        count_label=QLabel("Count")
        self.count_input=QLineEdit()
        seconds_label = QLabel("Seconds")
        self.seconds_input = QLineEdit()

        detection_layout.addWidget(filter,alignment=Qt.AlignmentFlag.AlignAbsolute)
        detection_layout.addWidget(self.filter_combo)
        detection_layout.addWidget(count_label)
        detection_layout.addWidget(self.count_input)
        detection_layout.addWidget(seconds_label)
        detection_layout.addWidget(self.seconds_input)

        TCP_flags_layout = QHBoxLayout()

        TCP_flags_label = QLabel("TCP Flags")
        TCP_flags_layout.addWidget(TCP_flags_label)

        self.checkbox_ack = QCheckBox("ACK")
        self.checkbox_ack.stateChanged.connect(lambda:self.btnstate(self.checkbox_ack))
        TCP_flags_layout.addWidget(self.checkbox_ack, alignment=Qt.AlignmentFlag.AlignLeft)


        self.checkbox_syn = QCheckBox("SYN")
        self.checkbox_syn.stateChanged.connect(lambda:self.btnstate(self.checkbox_syn))
        TCP_flags_layout.addWidget(self.checkbox_syn, alignment=Qt.AlignmentFlag.AlignLeft)

        self.checkbox_psh = QCheckBox("PSH")
        self.checkbox_psh.stateChanged.connect(lambda:self.btnstate(self.checkbox_psh))
        TCP_flags_layout.addWidget(self.checkbox_psh)


        self.checkbox_rst = QCheckBox("RST")
        self.checkbox_rst.stateChanged.connect(lambda:self.btnstate(self.checkbox_rst))
        TCP_flags_layout.addWidget(self.checkbox_rst)

        self.checkbox_fin = QCheckBox("FIN")
        self.checkbox_fin.stateChanged.connect(lambda:self.btnstate(self.checkbox_fin))
        TCP_flags_layout.addWidget(self.checkbox_fin)


        layout.addLayout(detection_layout)
        layout.addLayout(TCP_flags_layout)
        #layout.addLayout(HTTP_status_code) 
        last_line=QHBoxLayout()
        last_line.addWidget(submit_button)
        add_ip=QPushButton('Block IP')
        add_ip.clicked.connect(self.block_ip)
        last_line.addWidget(submit_button)
        last_line.addWidget(add_ip)
        
        layout.addLayout(last_line)
    
        self.setLayout(layout)
        self.show()

    def block_ip(self):
        if self.IPWindow is None:
            self.IPWindow=BlockIPForm(self)
            self.IPWindow.show()
                 
        else:
            self.IPWindow.close()
            self.IPWindow=None
    def btnstate(self, b):
        return b.isChecked()

    def submit(self):
        

        action = self.action_input.text()
        protocol = self.protocol_combo.currentText()
        source_ip = self.source_ip_input.text()
        source_port = self.source_port_input.text()
        dest_ip = self.dest_ip_input.text()
        dest_port = self.dest_port_input.text()
        message=self.message_text_input.text()
        rule_id = self.rule_id_input.text()
        rev=self.gid_input.text()
        
        for rule in client_utils.rules:
            if rule['sid']==rule_id:            
                self.msgBox.setIcon(QMessageBox.Warning)
                self.msgBox.setText("Rule with seed already exists")
                self.msgBox.setStandardButtons(QMessageBox.Ok)
                self.msgBox.exec() 
                break
        
        new_rule=f'{action} {protocol.lower()} {source_ip} {source_port} -> {dest_ip} {dest_port} (msg:"{message}"; '
        if self.content_input.text():
            new_rule+= f'content:"{self.content_input.text()}"; ' 
        if str(self.filter_combo.currentText()) != "None":
            new_rule+=f'detection_filter:{str(self.filter_combo.currentText())}, count {self.count_input.text()}, seconds {self.seconds_input.text()}; '
        if str(self.flow_input.currentText()) != "None":
            new_rule+=f'flow:{str(self.flow_input.currentText())}; '
        if str(self.class_type_input.currentText()) != "None":
            new_rule+=f'classtype:{str(self.flow_input.currentText())}; '
        #https://paginas.fe.up.pt/~mgi98020/pgr/writing_snort_rules.htm#flags
        flags=''
        if self.checkbox_ack.isChecked(): flags+='A'
        if self.checkbox_fin.isChecked(): flags+='F'
        if self.checkbox_syn.isChecked(): flags+='S'
        if self.checkbox_rst.isChecked(): flags+='R'
        if self.checkbox_psh.isChecked(): flags+='P'
        if flags: new_rule+=f'flags:{flags}; '

        if rev: new_rule+= f'rev:{rev}; ' 
        new_rule+=f'sid: {rule_id};)'  
        
        print(get_response_from_ssl_socker('add',new_rule))

        data_rule='{'+"action:"+action+"; proto:"+protocol+"; source_net:"+source_ip+"; source_port:"+source_port+"; dest_net:"+dest_ip+"; dest_port:"+dest_port+"; " +new_rule.split('(')[1].split(')')[0][:-1]+'}'
        data_rule=data_rule.replace('msg','Rule')
        client_utils.rules.append(str_to_dict(data_rule))
        self.close()
        

        