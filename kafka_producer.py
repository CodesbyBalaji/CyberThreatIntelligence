import json
import time
import random
from datetime import datetime
from kafka import KafkaProducer
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_mock_event():
    event_types = ["Suspicious Login", "DDoS Detected", "Malware C2 Beacon", "Data Exfiltration Attempt"]
    sources = ["SIEM", "NIDS", "EDR", "Firewall"]
    ips = ["192.168.1.100", "185.15.2.1", "10.0.0.45", "172.16.0.22", "8.8.8.8"]
    
    event_type = random.choice(event_types)
    source = random.choice(sources)
    ip = random.choice(ips)
    
    if event_type == "Suspicious Login":
        content = f"Multiple failed login attempts detected from IP {ip} followed by a successful login."
    elif event_type == "DDoS Detected":
        content = f"High volume SYN flood traffic detected from origin {ip} targeting the main application gateway."
    elif event_type == "Malware C2 Beacon":
        content = f"Endpoint at {ip} observed beaconing to known malicious domain malicorp.xyz over port 443."
    else:
        content = f"Unusual outbound data transfer (50GB) detected from {ip} to an unknown external server."
        
    return {
        "title": f"Live Alert - {event_type}",
        "content": content,
        "source": source,
        "event_type": event_type,
        "timestamp": datetime.now().isoformat()
    }

def start_producer(bootstrap_servers='localhost:9092', topic='threat-intel-stream'):
    try:
        producer = KafkaProducer(
            bootstrap_servers=[bootstrap_servers],
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )
        logger.info(f"Connected to Kafka at {bootstrap_servers}")
        
        while True:
            event = generate_mock_event()
            producer.send(topic, value=event)
            logger.info(f"Sent event to {topic}: {event['title']}")
            time.sleep(random.uniform(5, 10)) # Send an event every 5 to 10 seconds
            
    except Exception as e:
        logger.error(f"Failed to connect to Kafka: {e}")

if __name__ == "__main__":
    start_producer()
