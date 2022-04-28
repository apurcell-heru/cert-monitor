#!/usr/bin/env python3
from kubernetes import client, config
from prometheus_client import start_http_server, Gauge
from cryptography import x509
import base64
import time
import datetime
import string

global is_vars_set 
is_vars_set = 0

def get_cert_data():
    global is_vars_set
    config.load_kube_config()
    v1 = client.CoreV1Api()
    ret = v1.list_secret_for_all_namespaces(watch=False)
    for i in ret.items:
        secret_name = i.metadata.name
        namespace = i.metadata.namespace
        secret = v1.read_namespaced_secret(secret_name, namespace).data
        if secret.get("tls.crt") is not None:
            cert_glob = base64.b64decode(secret.get("tls.crt"))
            cert = x509.load_pem_x509_certificate(cert_glob)
            cert_date = cert.not_valid_after
            name = cert.subject
            convert_cert_to_epoch = datetime.datetime(cert_date.year, cert_date.month, cert_date.day, cert_date.hour, cert_date.minute, cert_date.second).timestamp()
            now = time.time()
            days_remaining = (convert_cert_to_epoch - now) / 86400
            days_remaining = round(days_remaining, 2)
            #is_vars_set == 0 means we need to create variables for all the kpis. 1 means its done!
            if is_vars_set == 0:
                fetch_var = create_kpi(name)
                if fetch_var == "heru_monitor_certificate_days_remaining_echo_unc":
                    continue
                globals()[fetch_var] = Gauge(fetch_var, "Days left before cert expires")
            else:
                fetch_var = create_kpi(name)
                if fetch_var == "heru_monitor_certificate_days_remaining_echo_unc":
                    continue
                globals()[fetch_var].set(days_remaining)
                
    is_vars_set = 1       


def create_kpi(name):
# We need to reformat the names into a way that prometheus likes
# no dots or dashes only underscores
# we lob off the .heru.net as its not needed

    cn = str(name)
    cn = cn.split('=')
    cn = cn[1].split(')')
    appname = cn[0]
    appname = appname.replace('.', '_')
    appname = appname.replace('-', '_')
    appname = appname.replace('_heru_net', '')
    kpi_string = "heru_monitor_certificate_days_remaining_" + appname
    return(kpi_string)

def main():
    start_http_server(9100)
    while True:
        get_cert_data()
        time.sleep(10)
        
if __name__ == '__main__': 
    main()