#!/usr/bin/python3

import argparse
import base64
import logging
import signal
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from google.protobuf.message import Message
import graphyte
from meshtastic import mesh_pb2, mqtt_pb2, portnums_pb2, telemetry_pb2
import paho.mqtt.client as mqttClient

from globals import Globals

def onMQTTMessage(mqttc, obj, msg):
    """Callback invoke when we receive a message via MQTT"""
    logging.debug(f"MQTT: Received message on topic {msg.topic} at QoS {msg.qos}")
    serviceEnvelope = mqtt_pb2.ServiceEnvelope()
    isEncrypted = False
    try:
        serviceEnvelope.ParseFromString(msg.payload)
        messagePacket = serviceEnvelope.packet
    except Exception as e:
        logging.warning(f"protobuf: Failed to parse: {str(e)}")
        return

    if messagePacket.HasField("encrypted") and not messagePacket.HasField("decoded"):
        decryptMessagePacket(messagePacket)
        isEncrypted = True

    fromNode = getattr(messagePacket, "from")
    fromNode = f"{fromNode:x}"
    logging.info(f"protobuf: {fromNode}: Received packet")

    portnum = messagePacket.decoded.portnum

    if portnum == portnums_pb2.POSITION_APP:
        onMeshtasticPosition(fromNode, messagePacket.decoded)

    elif portnum == portnums_pb2.TELEMETRY_APP:
        onMeshtasticTelemetry(fromNode, messagePacket.decoded)

def onMQTTConnect(client, userdata, flags, reason_code, properties):
    """Callback invoke when we connect to MQTT broker"""
    _globals = Globals.getInstance()
    if reason_code != 0:
        logging.error(f"MQTT: unexpected connection error {reason_code}")

    mqtt = _globals.getMqtt()
    topic = _globals.getMqttRootTopic()
    mqtt.subscribe(topic)
    logging.info(f"MQTT: Subscribed to {topic}")

    args = _globals.getArgs()
    graphyte.init(args.graphite_server, prefix=args.graphite_prefix)
    logging.info(f"graphyte: Connected to Graphite server {args.graphite_server} with prefix {args.graphite_prefix}")

def onMQTTDisconnect(client, userdata, reason_code, properties):
    """Callback invoke when we disconnect from MQTT broker"""
    if reason_code != 0:
        logging.error(f"MQTT: unexpected disconnection error {reason_code}")

def decryptMessagePacket(messagePacket):
    try:
        _globals = Globals.getInstance()
        args = _globals.getArgs()

        # Convert key to bytes
        key = base64.b64decode(args.meshtastic_key.encode('ascii') + b'==')

        noncePacketId = getattr(messagePacket, "id").to_bytes(8, "little")
        nonceFromNode = getattr(messagePacket, "from").to_bytes(8, "little")

        # Put both parts into a single byte array.
        nonce = noncePacketId + nonceFromNode

        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(getattr(messagePacket, "encrypted")) + decryptor.finalize()

        data = mesh_pb2.Data()
        data.ParseFromString(decrypted_bytes)
        messagePacket.decoded.CopyFrom(data)

        logging.debug(f"protobuf: Decoded encrypted packet {messagePacket.id}")
        logging.debug(f"{messagePacket.decoded}")
    except Exception as e:
        logging.warning(f"protobuf: Decryption failed for packet {messagePacket.id}: {str(e)}")
        return

    #sendGraphiteMetric(f"{getattr(messagePacket, "id")}.rssi", getattr(messagePacket, "rx_rssi", None))

def onMeshtasticPosition(fromNode, messagePacket):
    logging.info(f"Meshtastic: {fromNode}: Received position") 
    pos = mesh_pb2.Position()
    pos.ParseFromString(messagePacket.payload)
    logging.debug(f"{pos}")

    logging.info(f"graphyte: {fromNode}: Sending position")
    for posLabel, posValue in pos.ListFields():
        if posValue != None:
            sendGraphiteMetric(fromNode, f"position.{posLabel.name}", posValue)

def onMeshtasticTelemetry(fromNode, messagePacket):
    logging.info(f"Meshtastic: {fromNode}: Received telemetry")

    telemetry = telemetry_pb2.Telemetry()
    telemetry.ParseFromString(messagePacket.payload)

    for telemetryMessageLabel, telemetryMessage in telemetry.ListFields():
        if not isinstance(telemetryMessage, Message):
            continue

        logging.info(f"graphyte: {fromNode}: Sending {telemetryMessageLabel.name}")
        for telemetryLabel, telemetryValue in telemetryMessage.ListFields():
            if telemetryValue != None:
                sendGraphiteMetric(fromNode, f"{telemetryMessageLabel.name}.{telemetryLabel.name}", telemetryValue)

def sendGraphiteMetric(fromNode, metric, value):
    metric = f"{fromNode}.{metric}"
    logging.debug(f"graphyte: Sending {metric} with value {value}")
    graphyte.send(metric, float(value))

def initArgParser():
    """Initialize the command line argument parsing."""
    _globals = Globals.getInstance()
    parser = _globals.getParser()
    args = _globals.getArgs()

    parser.add_argument(
        "-H", "--mqtt-host",
        help="The MQTT broker host name or IP",
        default="mqtt.meshtastic.org",
        required=False,
    )

    parser.add_argument(
        "-P", "--mqtt-port",
        help="The MQTT broker port",
        default=1883,
        required=False
    )

    parser.add_argument(
        "-u", "--mqtt-user",
        help="The MQTT broker user name",
        default="meshdev",
        required=False
    )

    parser.add_argument(
        "-p", "--mqtt-password",
        help="The MQTT broker password",
        default="large4cats",
        required=False
    )

    parser.add_argument(
        "-t", "--mqtt-root-topic",
        help="The MQTT root topic",
        default="msh/SG_923/2/e/",
        required=False,
    )

    parser.add_argument(
        "-c", "--meshtastic-channel",
        help="The Meshtastic channel",
        default="LongFast",
        required=False,
    )

    parser.add_argument(
        "-k", "--meshtastic-key",
        help="The Meshtastic channel encryption key",
        default="AQ==",
        required=False,
    )

    parser.add_argument(
        "-g", "--graphite-server",
        help="The Graphite server",
        required=True,
    )

    parser.add_argument(
        "-G", "--graphite-prefix",
        help="Prefix for Graphite metrics",
        default="meshtastic",
        required=False,
    )

    parser.add_argument(
        '-d', '--debug',
        help="Set log level debug",
        action="store_const", dest="loglevel", const=logging.DEBUG,
        default=logging.WARNING,
    )

    parser.add_argument(
        '-v', '--verbose',
        help="Set log level info",
        action="store_const", dest="loglevel", const=logging.INFO,
    )

    parser.set_defaults(deprecated=None)
    # parser.add_argument("--version", action="version", version=f"{__version__}")

    args = parser.parse_args()
    _globals.setArgs(args)
    _globals.setParser(parser)

def initMQTT():
    """Initialize the MQTT client and connect to broker"""
    _globals = Globals.getInstance()
    args = _globals.getArgs()
    mqtt = _globals.getMqtt()
    try:
        mqtt = mqttClient.Client(mqttClient.CallbackAPIVersion.VERSION2)
        _globals.setMqtt(mqtt)
        _globals.setMqttRootTopic(args.mqtt_root_topic + args.meshtastic_channel + "/#")
        mqtt.on_message = onMQTTMessage
        mqtt.on_connect = onMQTTConnect
        mqtt.on_disconnect = onMQTTDisconnect
        mqtt.username_pw_set(args.mqtt_user, args.mqtt_password)
        mqtt.connect(args.mqtt_host, int(args.mqtt_port))

    except Exception as e:
        logging.error(f"MQTT client error: {e}")
        sys.exit(1)

def main():
    """Main program function"""

    _globals = Globals.getInstance()
    parser = argparse.ArgumentParser(
        prog="meshtastic-graphite",
        description="Connects Meshtastic radios via MQTT and publishes data to Graphite",
        epilog="License: MIT License, Copyright (c) 2024 Andrew Yong",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    _globals.setParser(parser)
    initArgParser()

    args = _globals.getArgs()

    logging.basicConfig(level=args.loglevel)

    if args.meshtastic_key == "AQ==":
        logging.info("Meshtastic: Key is default, expanding to AES128")
        args.meshtastic_key = "1PG7OiApB1nwvP+rz05pAQ=="

    initMQTT()

    mqtt = _globals.getMqtt()

    def signal_handler(signal, frame):
        mqtt.disconnect()
        mqtt.loop_stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGABRT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    mqtt.loop_forever()

if __name__ == "__main__":
    main()
