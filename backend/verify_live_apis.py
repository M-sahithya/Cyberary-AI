import urllib.request
import json

data = json.dumps({"username": "admin", "password": "CyberaryAdmin123!"}).encode("utf-8")
req = urllib.request.Request("http://localhost:8000/api/auth/login", data=data, headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req) as resp:
    res = json.loads(resp.read().decode("utf-8"))
    print("Login success:", res.get("success"))
    token = res["data"]["access_token"]
    print("Token received.")

endpoints = [
    "/api/auth/me",
    "/api/dashboard/summary",
    "/api/dashboard/threat-feed",
    "/api/threats",
    "/api/mitre/techniques",
    "/api/assets",
    "/api/vulnerabilities",
    "/api/cve",
    "/api/honeypot/sessions",
    "/api/remediation",
    "/api/agents",
    "/api/settings",
]

for ep in endpoints:
    r = urllib.request.Request(f"http://localhost:8000{ep}", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(r) as res_ep:
        d = json.loads(res_ep.read().decode("utf-8"))
        print(f"{ep} -> HTTP 200, success={d.get('success')}")

print("\nALL API ENDPOINTS TESTED SUCCESSFULLY!")
