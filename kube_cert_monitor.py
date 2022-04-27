#!/usr/bin/env python3
from kubernetes import client, config
from prometheus_client import start_http_server, Gauge
from cryptography import x509
import base64
import time
import datetime

global gage 
def get_cert_data():
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
            publish_metrics(name, namespace, days_remaining)


def publish_metrics(name, namespace, days_remaining):
    cn = str(name)
    cn = cn.split('=')
    cn = cn[1].split(')')
    appname = cn[0]
    days_remaining = round(days_remaining, 2)
    kpi_string = "heru_monitor_certificate_days_reminaining" + "{" + appname + "}"
    gage = Gauge(kpi_string, 'Days left before cert expires')
    gage.set(days_remaining)


def main():
    start_http_server(9100)
    while True:
        get_cert_data()
        time.sleep(30)

        
if __name__ == '__main__': 
    main()