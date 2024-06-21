from opensearchpy import OpenSearch, helpers
import os
import json

host = 'localhost'
port = 9200
auth = ('admin', "TQEkc;*ZgPej4A3_S7hC'+")  

client = OpenSearch(
    hosts=[{'host': host, 'port': port}],
    http_auth=auth,
    use_ssl=True,
    verify_certs=False,
    ssl_show_warn=False
)

def load_json_files(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.json'):
                with open(os.path.join(root, file), 'r') as f:
                    yield json.load(f)

def create_bulk_actions(json_files, index_name):
    for doc in json_files:
        yield {
            "_index": index_name,
            "_source": doc
        }

json_directory = './cvelistV5/cves/2024'
index_name = 'cve'

json_files = load_json_files(json_directory)

actions = create_bulk_actions(json_files, index_name)

try:
    response = helpers.bulk(client, actions, chunk_size=500, request_timeout=60)
    print("Documents insérés avec succès dans OpenSearch.")
except helpers.BulkIndexError as e:
    print(f'Error indexing documents: {e}')
    for error in e.errors:
        print(json.dumps(error, indent=2))
# helpers.bulk(client, actions)

# print("Documents insérés avec succès dans OpenSearch.")