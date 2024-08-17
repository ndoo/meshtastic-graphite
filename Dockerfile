FROM python:3

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY meshtastic-graphite.py globals.py .

ENTRYPOINT [ "python", "./meshtastic-graphite.py" ]
