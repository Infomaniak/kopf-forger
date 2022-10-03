FROM python:3.10.5-alpine

WORKDIR /usr/src/app

RUN pip install pipenv

COPY Pipfile* ./

RUN pipenv requirements > requirements.txt

RUN pip install -r requirements.txt

ADD handlers.py .

CMD kopf run --verbose --liveness=http://0.0.0.0:8080/healthz --all-namespaces /usr/src/app/handlers.py
