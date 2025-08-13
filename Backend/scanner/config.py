import os

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "vuln_assessment"
COLLECTION_NAME = "subdomain_scans"
