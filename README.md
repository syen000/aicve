## NVD AI Vulnerability Monitor

#### Description:
A simple tool designed to filter and identify AI-specific CVEs from the National Vulnerability Database (NVD) by integrating Ollama (local LLM). The tool uses simple logic to perform analysis, distinguishing between AI framework related vulnerabilities and unrelated keywords match noise.

LLM Utilisation Logic:
The system utilises a simple prompt instruction directs the local LLM to analyze the context of CVE descriptions, ensuring only vulnerabilities related to AI models, frameworks are flagged, while ignoring generic software that happens to contain "AI" keywords in its metadata.

#### Key Features:
- Fetches CVE data via NVD every hour.
- Leverages local LLMs (Ollama) to categorize vulnerabilities based on CVE description.
- Output log file if not AI related CVEs were found including the explanation from LLM.
- Output 

#### Usage:
Install required libraries:
```pip3 install -r requirements.txt```

Start:
```python3 monitor.py```

#### Note:
API Key is not used in this script, because of the goal of this script is to only grab the last 1 hour data, and will only run once every hour.
