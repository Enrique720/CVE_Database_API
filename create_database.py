import json
import os
import requests
import time
from pymongo import MongoClient
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta

CVES = {}

def get_API(results_per_page, start_index):
    api = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={results_per_page}&startIndex={start_index}"
    return api

def get_cve_data(api):
    try:
        response = requests.get(api)
        data = response.json()
        return data
    except Exception as e:
        print(f"Error fetching data from API: {e}")
        return None

def parse_and_store_cve_data(results_per_page, db):
    start_index = 0
    total_results = 1  # Initialize to enter the loop

    while start_index < total_results:
        api = get_API(results_per_page, start_index)
        data = get_cve_data(api)

        if data:
            total_results = data.get("totalResults", 0)

            cve_items = data.get("vulnerabilities", [])

            for item in cve_items:
                cve_id = item.get("cve", {}).get("id")
                if cve_id:
                    CVES[cve_id] = item
                    db.cves.update_one({"cve.cve.id": cve_id}, {"$set": item}, upsert=True)

            start_index += results_per_page
        else:
            break

        # Sleep to avoid overwhelming the API and getting us blocked.
        time.sleep(5)

def update_database_periodically(db, initial_delay_minutes=0, interval_minutes=120):
    scheduler = BackgroundScheduler()
    
    # Schedule the initial run
    initial_run_time = datetime.now() + timedelta(minutes=initial_delay_minutes)
    scheduler.add_job(parse_and_store_cve_data, 'date', run_date=initial_run_time, args=[2000, db])
    
    # Schedule subsequent runs
    scheduler.add_job(parse_and_store_cve_data, 'interval', minutes=interval_minutes, args=[2000, db])
    
    scheduler.start()

if __name__ == "__main__":
    client = MongoClient("mongodb://localhost:27017/")
    db = client.cve_database

    # Schedule the initial run immediately and subsequent runs every 2 hours
    update_database_periodically(db, initial_delay_minutes=0, interval_minutes=120)

    # Keep the script running to allow the scheduler to run
    try:
        while True:
            time.sleep(2)
    except (KeyboardInterrupt, SystemExit):
        pass



