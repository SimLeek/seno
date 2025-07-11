import time
import threading
import json
import socket
import logging
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration (load minimal info from config.json)
with open("config.json", "r") as f:
    CONFIG = json.load(f)
LOCAL_ID = CONFIG["local_id"]

@dataclass
class CounterUpdate:
    type: str
    counter_id: str
    value: float
    machine_id: str

# Counter state
counters = {
    "counter1": 0.0,  # Increments at 1/sec
    "counter2": 0.0,  # Increments at 0.5/sec
    "counter3": 0.0   # Increments at 0.2/sec
}

def broadcast_update(counter_id: str, value: float):
    """Broadcast counter update to all machines."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    update = CounterUpdate(
        type="counter_update",
        counter_id=counter_id,
        value=value,
        machine_id=LOCAL_ID
    )
    for machine in CONFIG["machines"].values():
        if machine["id"] != LOCAL_ID:
            try:
                sock.sendto(json.dumps(asdict(update)).encode(), (machine["ip"], 5001))
            except Exception as e:
                logger.error(f"Failed to send update to {machine['id']}: {e}")
    sock.close()

def receive_updates():
    """Receive counter updates from other machines."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 5001))
    while True:
        data, _ = sock.recvfrom(4096)
        try:
            update = json.loads(data.decode())
            if update["type"] == "counter_update":
                counter_id = update["counter_id"]
                value = update["value"]
                if counter_id in counters:
                    counters[counter_id] = max(counters[counter_id], value)
                    logger.info(f"Updated {counter_id} to {counters[counter_id]} from {update['machine_id']}")
        except Exception as e:
            logger.error(f"Error processing update: {e}")

def main():
    """Main loop to increment counters and broadcast updates."""
    threading.Thread(target=receive_updates, daemon=True).start()
    start_time = time.time()
    while True:
        elapsed = time.time() - start_time
        # Increment counters
        counters["counter1"] = elapsed  # 1/sec
        counters["counter2"] = elapsed * 0.5  # 0.5/sec
        counters["counter3"] = elapsed * 0.2  # 0.2/sec
        # Broadcast updates
        for counter_id, value in counters.items():
            broadcast_update(counter_id, value)
        logger.debug(f"Local counters: {counters}")
        time.sleep(0.2)  # 5 updates per second

if __name__ == "__main__":
    main()