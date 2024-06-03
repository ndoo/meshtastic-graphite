class Globals:
    """Globals class is a Singleton."""

    __instance = None

    @staticmethod
    def getInstance():
        """Get an instance of the Globals class."""
        if Globals.__instance is None:
            Globals()
        return Globals.__instance

    def __init__(self):
        """Constructor for the Globals CLass"""
        if Globals.__instance is not None:
            raise Exception("This class is a singleton")
        else:
            Globals.__instance = self
        self.args = None
        self.mqtt = None
        self.mqttRootTopic = None
        self.parser = None

    # setters
    def setArgs(self, args):
        """Set the args"""
        self.args = args

    def setParser(self, parser):
        """Set the parser"""
        self.parser = parser

    def setMqtt(self, mqtt):
        """Set the MQTT client"""
        self.mqtt = mqtt

    def setMqttRootTopic(self, topic):
        """Set the MQTT root topic"""
        self.mqttRootTopic = topic

    # getters
    def getArgs(self):
        """Get args"""
        return self.args

    def getParser(self):
        """Get parser"""
        return self.parser

    def getMqtt(self):
        """Get the MQTT client"""
        return self.mqtt

    def getMqttRootTopic(self):
        """Get the MQTT root topic"""
        return self.mqttRootTopic
