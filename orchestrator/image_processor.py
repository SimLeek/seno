import time
import sys
import logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

logger.info("Image processor running, capturing camera feed...")
start_time = time.time()
while time.time() - start_time < 15:  # Run for 15 seconds then crash
    time.sleep(1)
logger.error("Image processor crashed!")
sys.exit(1)
