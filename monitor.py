from ollama import chat, ChatResponse
from datetime import datetime, timezone, timedelta
from pathlib import Path
import time
import requests
import csv
import json
import re

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

## Get time and set to NVD readable format ##
current_time = datetime.now(timezone.utc)
file_time = current_time.strftime("%Y%m%d%H%M%S")
last_hour_time = current_time - timedelta(hours=1) # Set search time range
search_start_time = last_hour_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
search_end_time = current_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")

# Define output folder names, and make folders if don't exist.
fn_not_ai = "not_ai"
of_not_ai = Path(fn_not_ai)
fn_is_ai = 'is_ai'
of_is_ai = Path(fn_is_ai)
of_not_ai.mkdir(parents=True, exist_ok=True)
of_is_ai.mkdir(parents=True, exist_ok=True)
fp_not_ai = of_not_ai / f'{file_time}.log'
fp_is_ai = of_is_ai / f'ai_cve_list-{file_time}.csv'


def search_cve():
    HEADERS = {

    }
    params = {
        "pubStartDate": search_start_time,
        "pubEndDate": search_end_time
    }
    try:
        response = requests.get(NVD_API_URL, params=params, headers=HEADERS, timeout=15)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"[!] API Error: {response.status_code} -- {response.text}")
    except requests.RequestException as e:
        print(f"[!] Request Error: {e}")
        return {}
    
def parse_cve(cveData):
    results = []
    for item in cveData.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        published_time = cve["published"].split("T")[0]
        desc = cve["descriptions"][0]["value"]
        score = "N/A"
        severity = "N/A"
        metrics = cve.get("metrics", {})
        if "cvssMetricV40" in metrics:
            score = metrics["cvssMetricV40"][0]["cvssData"]["baseScore"]
            severity = metrics["cvssMetricV40"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            severity = metrics["cvssMetricV2"][0]["cvssData"]["baseSeverity"]
        if severity.upper() not in ["N/A", "LOW"]:
            results.append({
                "ID": cve_id,
                "SEVERITY": severity,
                "SCORE": score,
                "PUBLISHED": published_time,
                "DESCRIPTION": desc
            })
    return results

def ai_identification(data):
    try:
        is_ai_results = []
        not_ai_results = []
        for item in data:
            if item["DESCRIPTION"]:
                cve_desc = item["DESCRIPTION"]
                response: ChatResponse = chat(model='gemma3', messages=[
                {
                    'role': 'system',
                    'content': '''
                        You are a Senior Cybersecurity Analyst specializing in AI/ML vulnerability assessment.

                        Task: Determine if the following CVE description is related to AI, LLM, or Machine Learning technologies.

                        [Decision Criteria]
                        - Answer "Yes" IF:
                        1. The vulnerability exists in AI frameworks/libraries (e.g., PyTorch, TensorFlow, LangChain, Hugging Face, Transformers).
                        2. It involves LLM-specific issues (e.g., Prompt Injection, Model Inversion, Hallucination-based exploits, Vector Database vulnerabilities).
                        3. It affects the AI training pipeline, data poisoning, or model inference processes.
                        - Answer "No" IF:
                        1. The vendor is an AI company, but the flaw is in traditional IT infrastructure (e.g., web server, OS kernel, SQL injection).
                        2. The software merely uses Python or common libraries without involving ML logic.

                        [Output Format]
                        [Related]: Yes or No
                        [Reason]: A concise one-sentence explanation in English.''',
                },
                {
                    'role': 'user',
                    'content': f'[CVE Description]{cve_desc}'
                }
                ])
                related_match = re.search(r"\[Related\]:\s*(Yes|No)", response.message.content, re.IGNORECASE)
                reason_match = re.search(r"\[Reason\]:\s*(.*)", response.message.content)
                is_ai = related_match.group(1).strip()
                reason = reason_match.group(1).strip()
                item["EXPLANATION"] = reason
                if is_ai.lower() == "yes":
                    print("yes + 1")
                    is_ai_results.append(item)
                elif is_ai.lower() == "no":
                    print("no + 1")
                    not_ai_results.append(item)
        if len(not_ai_results) != 0:
            with open(fp_not_ai, 'w', newline='', encoding='utf-8') as f:
                json.dump(not_ai_results, f, indent=4, ensure_ascii=False)
                print("CVEs not related to AI has been written in the log file.")
        return is_ai_results
    except Exception as e:
        print(f"[!]Error: {e}")
        return {}

def csvConvert(data):
    if not data:
        return
    with open(fp_is_ai, 'w', newline='', encoding='utf-8') as f:
        header_name = data[0].keys() 
        writer = csv.DictWriter(f, fieldnames=header_name)
        writer.writeheader()
        writer.writerows(data)
        print(f"[*] Writing {len(data)} new CVE into CSV file")

def runScheduler():
    seen_cves = set()
    while True:
        cveData = search_cve()
        results = parse_cve(cveData)
        print(f"{len(results)} CVEs found in total.")
        finalResults = ai_identification(results)
        new_found = []
        for item in finalResults:
            if item["ID"] not in seen_cves:
                new_found.append(item)
                seen_cves.add(item["ID"]) # label found CVE
        if new_found:
            print(f"🔥 {len(new_found)} new AI CVE found:")
            for n in new_found:
                print(f" >> {n['ID']} [{n['SEVERITY']}]")
            # Update CSV only when new CVE found
            csvConvert(new_found) 
        else:
            print("No new AI CVE found。")
            
        print("Will run again after 1 hour.")
        time.sleep(3600)

def main():
    print(f'Run time: {current_time}')
    runScheduler()

if __name__ == "__main__":
    main()
