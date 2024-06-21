from opensearchpy import OpenSearch, helpers
from datetime import datetime
import re
import csv
import os
import json

# Configuration de la connexion à OpenSearch
host = 'localhost'
port = 9200
auth = ('admin', "TQEkc;*ZgPej4A3_S7hC'+")
index_name="cve"
my_date = "2023-01-01"

query_by_date = {
      "query": {
        "range": {
          "containers.cna.datePublic": {
            "gte": my_date
          }
        }
      },
      "_source": [
        "containers.cna.title",
        "cveMetadata.cveId",
        "containers.cna.descriptions.value",
        "containers.cna.affected.product",
        "containers.cna.affected.vendor",
        "containers.cna.affected.versions",
        "cveMetadata.datePublished",
        "containers.cna.references"
      ]
}

query_only_vendor_description_title = {
      "query": {
        "range": {
          "containers.cna.datePublic": {
            "gte": my_date
          }
        }
      },
      "_source": [
        "containers.cna.title",
        "cveMetadata.cveId",
        "containers.cna.descriptions.value",
        "containers.cna.affected.product",
        "containers.cna.affected.vendor",
      ]
    }

def query_scroll(client, scroll, scroll_id, results):
    while True:
        response = client.scroll(scroll_id=scroll_id, scroll=scroll)
        hits = response['hits']['hits']
        if not hits:
            break
        results.extend(hits)
        scroll_id = response['_scroll_id']
    return results

def query_opensearch(client, query):
    scroll='2m'
    
    response = client.search(
        index=index_name,
        body=query,
        scroll=scroll,
        size=20
    )

    results = response['hits']['hits']

    scroll_id = response['_scroll_id']
    
    results = query_scroll(client, scroll, scroll_id, results)

    return results

def create_csv(data):
    csv_file_path = 'example.csv'
 
    # Open the file in write mode
    with open(csv_file_path, mode='w', newline='') as file:
        # Create a csv.writer object
        writer = csv.writer(file)
        # Write data to the CSV file
        writer.writerows(data)

def normalize_vendor(src):
    version_regex = r' ?(V|v|(version ))?((\d+)|(\d+\.\d+)|(\d+\.\d+\.\d+))$'
    year_regex = r'(20\d\d)'

    src = re.sub(version_regex, '', src)
    src = re.sub(year_regex, '', src)
    # if '':
    #     return src
    # elif 'Microsoft Exchange Server' in src:
    #     return 'Microsoft Exchange Server'
    # elif 'Microsoft Dynamics 365' in src:
    #     return 'Microsoft Dynamics 365'
    # elif 'Microsoft SQL Server' in src:
    #     return 'Microsoft SQL Server'
    
    return src

def fill_data(client):
    results = query_opensearch(client, query_only_vendor_description_title)
    final_data = [['title', 'description', 'product']]
    for result in results:
        product = normalize_vendor(result['_source']['containers']['cna']['affected'][0]['product']) if 'affected' in result['_source']['containers']['cna'] else ''
        vendor = normalize_vendor(result['_source']['containers']['cna']['affected'][0]['vendor']) if 'affected' in result['_source']['containers']['cna'] else ''
        product_vendor = {
            "product": product,
            "vendor": vendor
        }
        title = result['_source']['containers']['cna']['title'] if 'title' in result['_source']['containers']['cna'] else ''
        descriptions = result['_source']['containers']['cna']['descriptions'][0]['value']
        cna = {
            title: title,
            descriptions: descriptions
        }
        if product != '' and vendor != '':
            final_data.append([title, descriptions, product])
    return final_data


def main():
    client = OpenSearch(
        hosts=[{'host': host, 'port': port}],
        http_auth=auth,
        use_ssl=True,  # Changez à True si vous utilisez SSL
        verify_certs=False,
        ssl_show_warn=False
    )
    all_data = fill_data(client)
    create_csv(all_data)

if __name__ == "__main__":
    main()