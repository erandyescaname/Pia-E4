import logging
import shodan

# Configure logging
logging.basicConfig(filename='shodan_search.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Data: your Shodan API Key
API_KEY = 'kLCQkcEnSvA7CjtK111MTSp77eVw9Uds'


def search_shodan(query, limit=5):
    """
    Procedure: Connect to the Shodan API and perform the device search with the provided query.
    
    :param query: The query to be searched for (e.g. 'apache', 'nginx', etc.)
    :param limit: Number of results to display (default, 5)
    """
    try:
        # Connecting to the Shodan API
        api = shodan.Shodan(API_KEY)

        # Perform the search with the query and narrow the results
        results = api.search(query, limit=limit)

        # Show the number of results found
        print(f"Resultados encontrados: {results['total']}")

        # Scroll through the results and display filtered information for each device
        for result in results['matches']:
            print('---')
            print(f"IP: {result['ip_str']}")
            print(f"Puerto: {result['port']}")
            print(f"Organización: {result.get('org', 'N/A')}")
            print(f"Sistema operativo: {result.get('os', 'N/A')}")

            # Show vulnerabilities if available
            vulns = result.get('vulns', 'No vulnerabilities found')
            if vulns != 'No vulnerabilities found':
                print(f"Vulnerabilidades: {', '.join(vulns)}")
            else:
                print(f"Vulnerabilidades: {vulns}")
            print('---')

    except shodan.APIError as error:
        print(f"Error en la API de Shodan: {error}")


def main(query):
    """Main function to execute the Shodan search."""
    search_shodan(query)
