import requests
import json

base_url = "http://localhost:8000"

if __name__ == "__main__":
    print("=== TESTING INVESTIGATION ENDPOINT ===")
    query = "How many Wazuh agents are connected?"
    print(f"Query: '{query}'")

    response = requests.post(
        f"{base_url}/api/investigate",
        json={"query": query},
        timeout=30
    )

    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"SUCCESS: {json.dumps(data, indent=2)}")
    else:
        print(f"Error: {response.text}")