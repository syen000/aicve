from ollama import chat, ChatResponse
from datetime import datetime, timezone, timedelta
import time
import requests
import csv
import json
import re
from dateutil.relativedelta import relativedelta

NVD_API_KEY = ""
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

currentTime = datetime.now(timezone.utc)
fileTime = currentTime.strftime("%Y%m%d%H%M%S")
# lyear1 = currentTime + relativedelta(years=-1, months=4, weeks=1, days=5, hours=-6)
# lyear2 = currentTime + relativedelta(years=-1, months=4, weeks=2, days=-2, hours=6)
# fstartTime = lyear1.strftime("%Y-%m-%dT%H:%M:%S.000Z")
# fendTime = lyear2.strftime("%Y-%m-%dT%H:%M:%S.000Z")
# lweekTime = currentTime - timedelta(days=7)
# fstartTime = lweekTime.strftime("%Y-%m-%dT%H:%M:%S.000Z")
lhourTime = currentTime - timedelta(hours=1)
fstartTime = lhourTime.strftime("%Y-%m-%dT%H:%M:%S.000Z")
fendTime = currentTime.strftime("%Y-%m-%dT%H:%M:%S.000Z")

def search_cve():
    HEADERS = {

    }
    params = {
        "pubStartDate": fstartTime,
        "pubEndDate": fendTime
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
        pubTime = cve["published"].split("T")[0]
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
                "PUBLISHED": pubTime,
                "DESCRIPTION": desc
            })
    return results

def aiIdentification(data):
    try:
        aiResults = []
        notAiResults = []
        for item in data:
            if item["DESCRIPTION"]:
                aiDesc = item["DESCRIPTION"]
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
                    'content': f'[CVE Description]{aiDesc}'
                }
                ])
                related_match = re.search(r"\[Related\]:\s*(Yes|No)", response.message.content, re.IGNORECASE)
                reason_match = re.search(r"\[Reason\]:\s*(.*)", response.message.content)
                is_ai = related_match.group(1).strip()
                reason = reason_match.group(1).strip()
                item["EXPLANATION"] = reason
                if is_ai.lower() == "yes":
                    print("yes + 1")
                    aiResults.append(item)
                else:
                    print("no + 1")
                    notAiResults.append(item)
        with open(f'notAI_{fileTime}.log', 'w', newline='', encoding='utf-8') as f:
            json.dump(notAiResults, f, indent=4, ensure_ascii=False)
            print("CVEs not related to AI has been written in the log file.")
        return aiResults
    except Exception as e:
        print(f"[!]Error: {e}")
        return {}

def csvConvert(data):
    if not data:
        return
    with open(f'cveList_{fileTime}.csv', 'w', newline='', encoding='utf-8') as f:
        headerName = data[0].keys() 
        writer = csv.DictWriter(f, fieldnames=headerName)
        writer.writeheader()
        writer.writerows(data)
        print(f"[*] Writing {len(data)} new CVE into CSV file")

def runScheduler():
    seen_cves = set()
    while True:
        cveData = search_cve()
        results = parse_cve(cveData)
        print(f"{len(results)} CVEs found in total.")
        finalResults = aiIdentification(results)
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
            print("Checking... No new AI CVE found。")
            
        time.sleep(3600)

def main():
    print(fstartTime, fendTime)
    runScheduler()

if __name__ == "__main__":
    main()