from celery import Celery
from pymongo import MongoClient
from utils.scanner_task_runner import run_scan_once
from celery.schedules import crontab
import os

app = Celery("scanner_tasks", broker="redis://localhost:6379/0")
app.conf.timezone = "Asia/Kolkata"

# MongoDB connection
mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(mongo_uri)
db = client["subdomain_scanner"]
collection = db["scan_results_subfinder"]


@app.task(name="periodic_subdomain_scan")
def periodic_subdomain_scan():
    domain = "iitm.ac.in"
    return run_scan_once(domain, collection)


app.conf.beat_schedule = {
    "run-auto-scan-daily-at-3-30pm": {
        "task": "periodic_subdomain_scan",
        "schedule": crontab(minute=40, hour=15),
    }
}
