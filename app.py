from flask import Flask, jsonify, render_template, request, redirect, url_for
from pymongo import MongoClient
from apscheduler.schedulers.background import BackgroundScheduler
import time
import requests
import re
import datetime

app = Flask(__name__)

client = MongoClient("mongodb://localhost:27017/")
db = client.cve_database

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
            print(total_results)
            cve_items = data.get("vulnerabilities", [])

            for item in cve_items:
                cve_id = item.get("cve", {}).get("id")
                if cve_id:
                    CVES[cve_id] = item
                    db.cves.update_one({"cve.id": cve_id}, {"$set": item}, upsert=True)

            start_index += results_per_page
        else:
            break

        # Sleep to avoid overwhelming the API and getting us blocked.
        time.sleep(5)

def update_database_periodically(db, initial_delay_minutes=0, interval_minutes=120):
    scheduler = BackgroundScheduler()
    
    initial_run_time = datetime.datetime.now() + datetime.timedelta(minutes=initial_delay_minutes)
    scheduler.add_job(parse_and_store_cve_data, 'date', run_date=initial_run_time, args=[2000, db])
    
    scheduler.add_job(parse_and_store_cve_data, 'interval', minutes=interval_minutes, args=[2000, db])
    
    scheduler.start()

def convert_objectid_to_str(cve):
    cve['_id'] = str(cve['_id'])
    return cve

@app.route('/api/cves', methods=['GET'])
def get_cves():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    sort_by = request.args.get('sort_by', 'cve.published')
    sort_order = request.args.get('sort_order', 'asc')
    skips = per_page * (page - 1)
    total_cves = db.cves.count_documents({})

    sort_order = 1 if sort_order == 'asc' else -1
    cves = db.cves.find().sort(sort_by, sort_order).skip(skips).limit(per_page)
    
    cve_list = []
    for cve in cves:
        cve_list.append(convert_objectid_to_str(cve))
    
    return jsonify({
        "total": total_cves,
        "cves": cve_list
    })

@app.route('/cves/<cve_id>', methods=['GET'])
def get_cve(cve_id):
    cve = db.cves.find_one({'cve.id': str(cve_id)})
    if cve:
        cve = convert_objectid_to_str(cve)
        return render_template('cve.html', cve=cve)
    else:
        return "CVE not found", 404

@app.route('/api/cves/<cve_id>', methods=['GET'])
def get_cve_api(cve_id):
    cve = db.cves.find_one({'cve.id': str(cve_id)})
    if cve:
        return jsonify(cve)
    else:
        return jsonify({"error": "CVE not found"}), 404

# Filter CVEs by year
@app.route('/api/cves/year/<cve_year>', methods=['GET'])
def get_cve_by_year(cve_year):
    
    if not re.fullmatch(r"\d{4}", cve_year):
        return jsonify({"error": "Invalid year format. Use YYYY format only."}), 400

    cves = db.cves.find({
        "cve.published": {"$regex": f"^{cve_year}-"}
    })

    cves = db.cves.find({"cve.published": {"$regex": f"{cve_year}-"}})

    cve_list = []
    for cve in cves:
        cve_list.append(convert_objectid_to_str(cve))
        
    if not cve_list:
        return jsonify({"message": "No CVEs found"}), 200
    
    return jsonify(cve_list) 

# Filter by baseScore
@app.route('/api/cves/score/<base_score>', methods=['GET'])
def get_cve_by_base_score(base_score):
    cves = db.cves.find({
        "cve.metrics.cvssMetricV2.0.cvssData.baseScore": {"$gte": float(base_score)}
    })
    cve_list = []
    for cve in cves:
        cve_list.append(convert_objectid_to_str(cve))
        
    if not cve_list:
        return jsonify({"message": "No CVEs found"}), 200
    return jsonify(cve_list)

# Filter by modified in N days
@app.route('/api/cves/modified/<days>', methods=['GET'])
def get_cve_by_modified(days):
    days = int(days)
    date_threshold = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).isoformat(timespec="milliseconds") + "Z"

    cves = db.cves.find({"cve.lastModified": {"$gte": date_threshold}})
    cve_list = []
    for cve in cves:
        cve_list.append(convert_objectid_to_str(cve))
        
    if not cve_list:
        return jsonify({"message": "No CVEs found"}), 200   
    return jsonify(cve_list)

@app.route('/')
def home():
    return redirect(url_for('index'))  # Redirects to /cves/list


@app.route('/cves/list')
def index():
    return render_template('index.html')

if __name__ == "__main__":
    update_database_periodically(db, initial_delay_minutes=0, interval_minutes=120)
    app.run(debug=False)
