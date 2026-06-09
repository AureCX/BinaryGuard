#!/usr/bin/env python3


import json
import sys
import urllib.request
import urllib.error
import os

def load_report(path):
    with open(path, "r") as f:
        return json.load(f)

def build_prompt(report):
    return f"""
You are a cybersecurity assistant.

Analyze this binary security report and explain it clearly to a non-expert.

Binary: {report['binary']}
Risk score: {report['risk_score']}/100

Protections:
- Canary: {report['protections']['canary']}
- PIE: {report['protections']['pie']}
- NX: {report['protections']['nx']}

Detected vulnerabilities:
{", ".join(report['vulnerabilities'])}

Potentially detected weak passwords:
{report['protections']['nb_potential_passwords']}

Task:
1. Explain the risks simply
2. Explain why they are dangerous
3. Suggest fixes in C for every vulnerability
4. The output is printed in a terminal, so ONLY use terminal-style text, and no "**" or Markdown text
5. If there are any weak passwords hardcoded and detected, make it the top priority.
"""

def call_ai(prompt):
    api_key = os.getenv("AI_API_KEY")

    if not api_key:
        print("Erreur : La variable d'environnement AI_API_KEY n'est pas définie.")
        sys.exit(84)
    url = "https://api.groq.com/openai/v1/chat/completions"
    data = {
            "model": "llama-3.3-70b-versatile",
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2
        }
    req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'))
    req.add_header('Content-Type', 'application/json')
    req.add_header('Authorization', f'Bearer {api_key}')
    req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
    try:
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
            print(result['choices'][0]['message']['content'])
    except urllib.error.HTTPError as e:
        print(f"Erreur HTTP de l'API : {e.code} - {e.read().decode()}")
        sys.exit(84)
    except Exception as e:
        print(f"Erreur : {e}")
        sys.exit(84)


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 ai_explainer.py report.json")
        return
    report = load_report(sys.argv[1])
    prompt = build_prompt(report)
    call_ai(prompt)


if __name__ == "__main__":
    main()