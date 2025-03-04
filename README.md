# NVD Assessment

This project is a web application that fetches and displays CVE (Common Vulnerabilities and Exposures) data from the NVD (National Vulnerability Database) API. The application uses Flask for the backend and MongoDB for data storage. The data is periodically updated to ensure the latest CVE information is available.

## Setup Instructions

### Prerequisites

- Python 3.x
- MongoDB
- pip (Python package installer)

### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/Enrique720/NVD_Assesment.git
    cd NVD_Assesment
    ```

2. Create a virtual environment and activate it:

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. Install the required packages:

    ```bash
    pip install -r requirements.txt
    ```

4. Start MongoDB:

    ```bash
    sudo systemctl start mongod
    ```

5. Run the Flask application:

    ```bash
    python app.py
    ```

The application will be available at `http://localhost:5000`.

## API Endpoint Documentation

### Get All CVEs

- **URL:** `/api/cves`
- **Method:** `GET`
- **Query Parameters:**
  - `page` (optional): Page number (default: 1)
  - `per_page` (optional): Number of results per page (default: 10)
  - `sort_by` (optional): Field to sort by (default: `cve.published`)
  - `sort_order` (optional): Sort order (`asc` or `desc`, default: `asc`)
- **Response:**
  - `total`: Total number of CVEs
  - `cves`: List of CVEs

### Get CVE by ID

- **URL:** `/api/cves/<cve_id>`
- **Method:** `GET`
- **Response:**
  - CVE details

### Get CVEs by Year

- **URL:** `/api/cves/year/<cve_year>`
- **Method:** `GET`
- **Response:**
  - List of CVEs for the specified year

### Get CVEs by Base Score

- **URL:** `/api/cves/score/<base_score>`
- **Method:** `GET`
- **Response:**
  - List of CVEs with a base score greater than or equal to the specified score

### Get CVEs Modified in the Last N Days

- **URL:** `/api/cves/modified/<days>`
- **Method:** `GET`
- **Response:**
  - List of CVEs modified in the last N days

## Usage

1. Open your web browser and navigate to `http://localhost:5000`.
2. Use the provided API endpoints to fetch and display CVE data.
3. The data is automatically updated every 2 hours to ensure the latest information is available.

## Notes

1. The data is downloaded and processed on runtime due to Github limited size storage.
2. The MongoDB daemon should be running in the following URI: mongodb://localhost:27017/