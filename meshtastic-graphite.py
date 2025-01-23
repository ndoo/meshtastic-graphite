#!/usr/bin/python3

import argparse
import base64
import logging
import signal
import sys
import time

from google.protobuf.message import Message
import graphyte
import meshtastic
from meshtastic import mesh_pb2, portnums_pb2, serial_interface, telemetry_pb2
from pubsub import pub

from globals import Globals

def onReceive(packet, interface):

    fromNode = packet["fromId"]

    logging.info(f"meshtastic: {fromNode}: Received packet")

    if "decoded" not in packet:
        logging.info(f"meshtastic: {fromNode}: Empty packet")
        return

    portnum = packet["decoded"]["portnum"]

    if portnum == "POSITION_APP":
        onMeshtasticPosition(fromNode, packet["decoded"])

    elif portnum == "TELEMETRY_APP":
        onMeshtasticTelemetry(fromNode, packet["decoded"])

def onConnection(interface, topic=pub.AUTO_TOPIC):
    logging.info(f"meshtastic: Connected")
    _globals = Globals.getInstance()
    args = _globals.getArgs()
    graphyte.init(args.graphite_server, prefix=args.graphite_prefix)
    logging.info(f"graphyte: Connected to Graphite server {args.graphite_server} with prefix {args.graphite_prefix}")

def onMeshtasticPosition(fromNode, messagePacket):
    logging.info(f"Meshtastic: {fromNode}: Received position") 
    pos = mesh_pb2.Position()
    pos.ParseFromString(messagePacket["payload"])
    logging.debug(f"{pos}")

    logging.info(f"graphyte: {fromNode}: Sending position")
    for posLabel, posValue in pos.ListFields():
        if posValue != None:
            sendGraphiteMetric(fromNode, f"position.{posLabel.name}", posValue)

def onMeshtasticTelemetry(fromNode, messagePacket):
    logging.info(f"Meshtastic: {fromNode}: Received telemetry")

    telemetry = telemetry_pb2.Telemetry()
    telemetry.ParseFromString(messagePacket["payload"])

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
        "-s", "--serial",
        help="The serial port",
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

    pub.subscribe(onReceive, "meshtastic.receive")
    pub.subscribe(onConnection, "meshtastic.connection.established")

    interface =  meshtastic.serial_interface.SerialInterface(args.serial)

    def signal_handler(signal, frame):
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGABRT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while True:
        time.sleep(1000)
    interface.close()

if __name__ == "__main__":
    main()
