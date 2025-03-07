#!/usr/bin/env python3
"""
Standalone script to run scheduled compliance reports even when the web app is not running.
This can be configured as a system service or cron job to ensure scheduled reports run reliably.
"""

import os
import sys
import json
import logging
import time
import signal

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import from the scheduling module
from scheduling import scheduler, load_existing_schedules

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scheduler.log'),
        logging.StreamHandler()
    ]
)

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logging.info("Received signal to shut down")
    scheduler.shutdown()
    sys.exit(0)

if __name__ == "__main__":
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logging.info("Starting Meraki Compliance Report scheduler")
    
    # Load and schedule all saved reports
    load_existing_schedules()
    
    if not scheduler.running:
        scheduler.start()
    
    # Print all scheduled jobs
    jobs = scheduler.get_jobs()
    if jobs:
        logging.info(f"Loaded {len(jobs)} scheduled reports:")
        for job in jobs:
            next_run = job.next_run_time.strftime("%Y-%m-%d %H:%M:%S") if job.next_run_time else "Not scheduled"
            logging.info(f"- ID: {job.id}, Next run: {next_run}")
    else:
        logging.info("No scheduled reports found")
    
    logging.info("Scheduler is running. Press Ctrl+C to exit.")
    
    # Keep the script running
    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        logging.info("Shutting down scheduler")
        scheduler.shutdown()
        logging.info("Scheduler shut down")