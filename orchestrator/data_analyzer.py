import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

logger.info("Data analyzer running, processing data...")
start_time = time.time()
while time.time() - start_time < 10:  # Run for 10 seconds then exit
    time.sleep(1)
logger.info("Data analyzer completed naturally")