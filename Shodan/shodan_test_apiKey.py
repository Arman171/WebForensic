import requests

def test_shodan_api_key(api_key):
    # Shodan API endpoint for checking API info
    url = "https://api.shodan.io/api-info"
    params = {
        "key": api_key
    }

    try:
        # Make a GET request to the Shodan API
        response = requests.get(url, params=params, timeout=10)
        
        # Check if the request was successful
        if response.status_code == 200:
            print("API key is valid!")
            print("Response:", response.json())
            return True
        elif response.status_code == 401:
            print("Invalid API key: Unauthorized")
            return False
        else:
            print(f"Error: Received status code {response.status_code}")
            print("Response:", response.text)
            return False

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return False

# Provided Shodan API key
api_key = "fsnmk9gnQp4hNMpJo3BV9CFfPMSQYgW6"

# Test the API key
test_shodan_api_key(api_key)