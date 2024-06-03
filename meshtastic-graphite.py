import argparse
import base64
import logging
import signal
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import google.protobuf
from meshtastic import mesh_pb2, mqtt_pb2, portnums_pb2, telemetry_pb2
import paho.mqtt.client as mqttClient

from globals import Globals

def onMQTTMessage(mqttc, obj, msg):
    """Callback invoke when we receive a message via MQTT"""
    logging.info(f"MQTT: Received message on topic {msg.topic} at QoS {msg.qos}")
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

    portnum = messagePacket.decoded.portnum

    if portnum == portnums_pb2.POSITION_APP:
        onMeshtasticPosition(messagePacket.decoded)

    elif portnum == portnums_pb2.TELEMETRY_APP:
        onMeshtasticTelemetry(messagePacket.decoded)

    elif portnum == portnums_pb2.TEXT_MESSAGE_APP:
        onMeshtasticTextMessage(messagePacket.decoded)

def onMQTTConnect(client, userdata, flags, rc, properties):
    """Callback invoke when we connect to MQTT broker"""
    _globals = Globals.getInstance()
    if rc != 0:
        logging.error(f"MQTT: unexpected connection error {rc}")

    mqtt = _globals.getMqtt()
    topic = _globals.getMqttRootTopic()
    mqtt.subscribe(topic)
    logging.info(f"MQTT: Subscribed to {topic}")

def onMQTTDisconnect(client, userdata, rc):
    """Callback invoke when we disconnect from MQTT broker"""
    if rc != 0:
        logging.error(f"MQTT: unexpected disconnection error {rc}")
        _globals = Globals.getInstance()
        if _globals.getLoop() is not None:
            _globals.getLoop().stop()

def decryptMessagePacket(messagePacket):
    try:
        _globals = Globals.getInstance()
        args = _globals.getArgs()

        # Convert key to bytes
        key = base64.b64decode(args.meshtastic_key.encode('ascii'))
    
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
        logging.info(f"protobuf: Decoded encrypted packet {messagePacket.id}")
    except Exception as e:
        logging.info(f"protobuf: Decryption failed for packet {messagePacket.id}: {str(e)}")
        return

    logging.info(f"protobuf: Received packet from {getattr(messagePacket, "from")}")
    logging.debug(f"{messagePacket.decoded}")

def onMeshtasticPosition(messagePacket):
    logging.info(f"Meshtastic: Received position") 
    pos = mesh_pb2.Position()
    pos.ParseFromString(messagePacket.payload)
    logging.debug(f"{pos}") 

def onMeshtasticTelemetry(messagePacket):
    logging.info(f"Meshtastic: Received telemetry")
    rssi = getattr(messagePacket, "rx_rssi", None)

    env = telemetry_pb2.Telemetry()
    env.ParseFromString(messagePacket.payload)

    # Device Metrics
    device_metrics_dict = {
        'Battery Level': env.device_metrics.battery_level,
        'Voltage': round(env.device_metrics.voltage, 2),
        'Channel Utilization': round(env.device_metrics.channel_utilization, 1),
        'Air Utilization': round(env.device_metrics.air_util_tx, 1)
    }
    if rssi:
        device_metrics_dict["RSSI"] = rssi

    # Environment Metrics
    environment_metrics_dict = {
        'Temp': round(env.environment_metrics.temperature, 2),
        'Humidity': round(env.environment_metrics.relative_humidity, 0),
        'Pressure': round(env.environment_metrics.barometric_pressure, 2),
        'Gas Resistance': round(env.environment_metrics.gas_resistance, 2)
    }

    if rssi:
        environment_metrics_dict["RSSI"] = rssi

    # Power Metrics
    # TODO
    # Air Quality Metrics
    # TODO

    device_metrics_string = "Device metrics: "
    environment_metrics_string = "Environment metrics: "

    # Only use metrics that are non-zero
    has_device_metrics = True
    has_environment_metrics = True
    has_device_metrics = all(value != 0 for value in device_metrics_dict.values())
    has_environment_metrics = all(value != 0 for value in environment_metrics_dict.values())

    # Loop through the dictionary and append non-empty values to the string
    for label, value in device_metrics_dict.items():
        if value is not None:
            device_metrics_string += f"{label}: {value}, "

    for label, value in environment_metrics_dict.items():
        if value is not None:
            environment_metrics_string += f"{label}: {value}, "

    # Remove the trailing comma and space
    device_metrics_string = device_metrics_string.rstrip(", ")
    environment_metrics_string = environment_metrics_string.rstrip(", ")

    # Print or use the final string
    if has_device_metrics:
        logging.debug(device_metrics_string)
    if has_environment_metrics:
        logging.debug(environment_metrics_string)

def onMeshtasticTextMessage(messagePacket):
    logging.info(f"Meshtastic: Received text message")
    msg = messagePacket.payload.decode("utf-8")
    logging.debug(f"{msg}")

def initArgParser():
    """Initialize the command line argument parsing."""
    _globals = Globals.getInstance()
    parser = _globals.getParser()
    args = _globals.getArgs()

    parser.add_argument(
        "-H", "--mqtt-host",
        help="The MQTT broker host name or IP.",
        default="mqtt.meshtastic.org",
        required=False,
    )

    parser.add_argument(
        "-P", "--mqtt-port",
        help="The MQTT broker port.",
        default=1883,
        required=False
    )

    parser.add_argument(
        "-u", "--mqtt-user",
        help="The MQTT broker user name.",
        default="meshdev",
        required=False
    )

    parser.add_argument(
        "-p", "--mqtt-password",
        help="The MQTT broker password.",
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
        help="The Meshtastic channel",
        default="AQ==",
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
