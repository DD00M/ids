import jinja2
import pdfkit
from datetime import datetime
import pandas as pd
import json



client_name = "Anomaly Detection Report"
static_counter=0


today_date = datetime.today().strftime("%d %b, %Y")
month = datetime.today().strftime("%B")

context = {'client_name': client_name, 'today_date': today_date, 'month': month,'static_counter':static_counter}


f=open('../res.json')
data=json.load(f)
data=data['data']

for i in range(len(data)):
    context["proto"+str(i)]=data[i]['proto']
    context["service"+str(i)]=data[i]['service']
    context["resp"+str(i)]=data[i]['id.resp_h']
    context["duration"+str(i)]=data[i]['duration']

template_loader = jinja2.FileSystemLoader('./')
template_env = jinja2.Environment(loader=template_loader)

html_template = 'index.html'
template = template_env.get_template(html_template)
output_text = template.render(context)

config = pdfkit.configuration(wkhtmltopdf='/usr/bin/wkhtmltopdf')
output_pdf = 'result.pdf'
pdfkit.from_string(output_text, output_pdf, configuration=config, css='index.css')