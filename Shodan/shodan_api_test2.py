import shodan

# Your Shodan API key
API_KEY = 'fsnmk9gnQp4hNMpJo3BV9CFfPMSQYgW6'

# Initialize the Shodan API client
api = shodan.Shodan(API_KEY)

def search_infrastructure(query):
    try:
        # Perform a Shodan search with the query related to Morocco or Laâyoune
        results = api.search(query)
        
        print(f"Results found: {results['total']}")
        
        # Print information about each result
        for result in results['matches']:
            print(f"IP: {result['ip_str']}")
            print(f"Port: {result['port']}")
            print(f"Organization: {result.get('org', 'N/A')}")
            print(f"Location: {result.get('location', {}).get('country_name', 'N/A')}")
            print(f"Data: {result['data']}")
            print("-" * 50)
    except shodan.APIError as e:
        print(f"Error: {e}")

# Define the query for infrastructure in Laâyoune or Morocco
query = 'city:Laâyoune country:Morocco'
search_infrastructure(query)
