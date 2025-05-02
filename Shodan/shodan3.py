import shodan
import csv

api_key = "api_key_here"  # Replace with your Shodan API key
api = shodan.Shodan(api_key)

# Get user input for the search query
query = input("Enter your search query: ")

try:
    # Search for the user-specified query
    results = api.search(query)

    # Open a CSV file for writing the results
    with open('search_results.csv', mode='w') as csv_file:
        fieldnames = ['IP', 'Port', 'Organization', 'Operating System', 'Hostnames', 'Data']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        writer.writeheader()
        for result in results['matches']:
            writer.writerow({'IP': result['ip_str'], 'Port': result['port'], 'Organization': result.get('org', 'N/A'), 'Operating System': result.get('os', 'N/A'), 'Hostnames': result.get('hostnames', 'N/A'), 'Data': result.get('data', 'N/A')})

    print("Results found: {} and saved in search_results.csv".format(results['total']))

except shodan.APIError as e:
    print("Error: {}".format(e))