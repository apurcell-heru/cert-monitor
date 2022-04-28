FROM python:latest
RUN mkdir /app
WORKDIR /app
COPY . /app/
RUN pip install -r requirements.txt
ENTRYPOINT [ "python" ]
CMD [ "kube_cert_monitor.py" ]