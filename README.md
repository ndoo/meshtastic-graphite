# Meshtastic Graphite Exporter

## Usage

```
$ ./meshtastic-graphite.py --help
usage: meshtastic-graphite [-h] [-H MQTT_HOST] [-P MQTT_PORT] [-u MQTT_USER] [-p MQTT_PASSWORD] [-t MQTT_ROOT_TOPIC] [-c MESHTASTIC_CHANNEL] [-k MESHTASTIC_KEY] -g GRAPHITE_SERVER [-G GRAPHITE_PREFIX] [-d] [-v]

Connects Meshtastic radios via MQTT and publishes data to Graphite

options:
  -h, --help            show this help message and exit
  -H MQTT_HOST, --mqtt-host MQTT_HOST
                        The MQTT broker host name or IP (default: mqtt.meshtastic.org)
  -P MQTT_PORT, --mqtt-port MQTT_PORT
                        The MQTT broker port (default: 1883)
  -u MQTT_USER, --mqtt-user MQTT_USER
                        The MQTT broker user name (default: meshdev)
  -p MQTT_PASSWORD, --mqtt-password MQTT_PASSWORD
                        The MQTT broker password (default: large4cats)
  -t MQTT_ROOT_TOPIC, --mqtt-root-topic MQTT_ROOT_TOPIC
                        The MQTT root topic (default: msh/SG_923/2/e/)
  -c MESHTASTIC_CHANNEL, --meshtastic-channel MESHTASTIC_CHANNEL
                        The Meshtastic channel (default: LongFast)
  -k MESHTASTIC_KEY, --meshtastic-key MESHTASTIC_KEY
                        The Meshtastic channel encryption key (default: AQ==)
  -g GRAPHITE_SERVER, --graphite-server GRAPHITE_SERVER
                        The Graphite server (default: None)
  -G GRAPHITE_PREFIX, --graphite-prefix GRAPHITE_PREFIX
                        Prefix for Graphite metrics (default: meshtastic)
  -d, --debug           Set log level debug (default: 30)
  -v, --verbose         Set log level info (default: None)
```

For example:
`./meshtastic-graphite.py -g 192.168.1.123 -v`

## Implemented Metrics

* Position
* Telemetry
