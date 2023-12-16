import requests
import random
import json


def send_request(url, payload, headers):
    response = requests.post(url, json=payload, headers=headers)
    try:
        print(f"Received response with status {response.status_code}: {response.json()}")
    except ValueError:
        print(f"Received non-JSON response with status {response.status_code}")


def main():
    url = 'http://127.0.0.1:8000/webhook/torabbit'  # Replace with your target URL.
    headers = {
        'Content-Type': 'application/json',  # This is important for JSON payloads
        'Authorization': 'Bearer your_token',  # If needed, replace with your actual token
        # Add other custom headers here if necessary.
    }

    for _ in range(1000):
        # Generate a random payload.
        payload = {'data': random.randint(0, 1000)}
        
        # Send the request and print the response.
        send_request(url, payload, headers)


if __name__ == '__main__':
    main()
