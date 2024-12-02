import paho.mqtt.client as mqtt
from queue import Queue
import paho.mqtt.client as paho
import ssl

class MqttClient:
    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code " + str(rc))
        if rc== 0:
            print("Connection successful")
        else:
            print("Connection failed")

    def on_message(self, client, userdata, msg):
        print(f"Received message: {msg.payload.decode()}")
        self.messages.put(msg.payload.decode())

    def subscribe(self, topic):
        self.client.subscribe(topic)
        print(f"Subscribed to topic: {topic}")

    def __init__(self, broker, port, username, password):
        self.client = mqtt.Client()
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

        self.client.tls_set(tls_version=paho.ssl.PROTOCOL_TLS)
        self.client.username_pw_set(username, password)
        self.client.connect(broker, port, 60)
        self.client.loop_start()
        self.messages = Queue()

    def get_message(self):
        if not self.messages.empty():
            return self.messages.get()
        return None

    def get_messages(self):
        while not self.messages.empty():
            yield self.messages.get()
