import requests
import json
import csv
import time
from datetime import datetime

def fetch_nvd_data(base_url, api_key, start_index=0, results_per_page=2000, csv_file='nvd_data.csv'):
    headers = {'API_KEY': api_key}
    fieldnames = ['id', 'published', 'baseScore', 'baseSeverity', 'exploitabilityScore', 'impactScore', 'version', 'vulnStatus']

    # Get the current date and format it as MMDDYYYY
    current_date = datetime.now().strftime("%m%d%Y")
    
    # Append the current date to the CSV file name
    csv_file = f'nvd_data2-{current_date}.csv'

    # Initialize the CSV writer
    with open(csv_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

    while True:
        params = {
            'startIndex': start_index,
            'resultsPerPage': results_per_page
        }

        print(f"Making request with startIndex: {start_index}, resultsPerPage: {results_per_page}")

        response = requests.get(base_url, params=params, headers=headers)

        if response.status_code != 200:
            print(f"Error: Received status code {response.status_code}")
            print(f"Response Text: {response.text}")
            break

        data = response.json()
        total_results = data.get('totalResults', 0)

        if total_results == 0:
            print("No results found.")
            break

        cve_data = data.get('vulnerabilities', [])
        
        # Write to CSV file incrementally
        with open(csv_file, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            for item in cve_data:
                cve = item.get('cve', {})
                metrics_dict = cve.get('metrics', {})
                versions = list(metrics_dict.keys())
                version_str = ", ".join([ver.split('cvssMetric')[-1] for ver in versions])

                # Use the first available metrics for other fields
                first_metrics = next(iter(metrics_dict.values()), [{}])[0]
                cvss_data = first_metrics.get('cvssData', {})

                vuln_status = cve.get('vulnStatus', "")
                
                # Skip the row if 'vulnStatus' is "Rejected" or "Reserved" although Reserved wouldn't show up in the NVD.
                if "Rejected" in vuln_status or "Reserved" in vuln_status:
                    continue
				
                row = {
                    'id': cve.get('id', ''),
                    'published': cve.get('published', ''),
                    'baseScore': cvss_data.get('baseScore', ''),
                    'baseSeverity': first_metrics.get('baseSeverity', ''),
                    'exploitabilityScore': first_metrics.get('exploitabilityScore', ''),
                    'impactScore': first_metrics.get('impactScore', ''),
                    'version': version_str,  # Store the CVSS versions as a comma-separated string
                    'vulnStatus': vuln_status

                }

                writer.writerow(row)

        if start_index + results_per_page >= total_results:
            break

        start_index += results_per_page
        time.sleep(6)  # Sleep for 6 seconds to respect rate limits

# Replace with your actual API key
api_key = "<API KEY>"

# Base URL for the NVD API
base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

fetch_nvd_data(base_url, api_key)
print(f"NVD data has been saved to nvd_data-{datetime.now().strftime('%m%d%Y')}.csv.")
