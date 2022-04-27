#!/usr/bin/env python3
from kubernetes import client, config
from cryptography import x509
import base64
import time
import datetime

def main():
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
            print("cert ", name, "in namespace", namespace, "has: ", "%.2f" % days_remaining, "days left")
        
        

        
        
if __name__ == '__main__': 
    main()