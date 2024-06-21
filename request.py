from opensearchpy import OpenSearch, helpers
from datetime import datetime
from obj import Software as Sft
import re
import csv
import os
import json
import nltk
from nltk.corpus import treebank

def download_nltk_feature():
    nltk.download('punkt')
    nltk.download('averaged_perceptron_tagger')
    nltk.download('treebank')
# download_nltk_feature()

# Configuration de la connexion à OpenSearch
host = 'localhost'
port = 9200
auth = ('admin', "TQEkc;*ZgPej4A3_S7hC'+")
index_name="cve"
my_date = "2024-05-01"
name_csv_file = 'all_cve_' + my_date + '.csv'

date_format = "%d/%m/%y"

# Regex version
reg_version = r'((\d+\.){1,}+\d+)'
reg_v_version = r'(v\.?\d.+)'

# IN + CD 
current_version = ['through', 'in']
before = ['until', 'till', 'before', 'ahead']
between = ['between', 'from']
patchs = ['patched', 'fixed']

class Cve(object):
    title = ""
    cveId = ""
    description = ""
    product = ""
    vendor = ""
    references = []
    datePublished = ""

    def __init__(self, title, cveId, description, product, vendor, references, datePublished):
        self.title = title
        self.cveId = cveId
        self.description = description
        self.product = product
        self.vendor = vendor
        self.references = references
        self.datePublished = datePublished


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

def fill_latex(list_cve):
    fd = open('data.tex', 'w')
    for cve in list_cve:
        for idx, row in enumerate(cve):
            if idx == 0:
                fd.write("\evidenchapterbleu{%s: %s}{1}" % (row[0], row[1]))
            else:
                fd.write(row)
    fd.close()

def latex_special_char(ref):
    ref = ref.replace('\\', '\\\\')
    ref = ref.replace('_', '\\_')
    ref = ref.replace('&', '\\&')
    ref = ref.replace('%', '\\%')
    return ref

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

'''
create csv if you want
'''
def create_csv(data):
    csv_file_path = name_csv_file
 
    # Open the file in write mode
    with open(csv_file_path, mode='w', newline='') as file:
        # Create a csv.writer object
        writer = csv.writer(file)
        # Write data to the CSV file
        writer.writerows(data)

'''
recover my software
'''
def read_calc(filename):
    all_software = []
    with open(filename) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            if line_count != 0:
                all_software.append(Sft.Software(row[0].lower(), row[1:]))
            line_count += 1
    return all_software

'''
search if one software in description

Args:
    summary: cve description tokenize (array)
    all_software: list of softwares
'''
def is_cve_in_list(summary, all_software):
    for software in all_software:
        for token in summary:
            if software.software == token.lower():
                print(software.software)
                return software
    return False

def search_signification(tagged, i, is_patch):
    if is_patch:
        # print("Fix")
        return 1
    elif tagged[i][0] in before:
        # print("Avant")
        return 2
    elif tagged[i][0] in between:
        # print("Entre")
        return 3
    elif tagged[i][0] in current_version:
        # print("Cette version")
        return 4
    # print("Je sais pas")
    return 0

'''
For example detect v.1.4 or v2.3.3
'''
def is_it_version_nn(word, code):
    return code == 'NN' and re.match(reg_v_version, word)

'''
research in all cve array if one of my csv software match with thing
'''
def research_all_cve(res_json, all_software):
    list_cve = []
    for x in res_json:
        tokens = nltk.word_tokenize(x.description)
        tagged = nltk.pos_tag(tokens)
        software = is_cve_in_list(tokens, all_software)
        if software == False:
            continue
        is_patch = False
        last_count = 0
        summary = latex_special_char(x.description)
        dt = datetime.fromisoformat(x.datePublished)
        dt_fr = dt.strftime(date_format)
        list_cve.append([
            [software.software, x.cveId],
            "\evidencontenu{%s}{%s}{" % (software.software, x.cveId),
            "Dernière update : %s\n\\bigskip\n\n\\textbf{Description :}\n%s" % (dt_fr, summary),
            '}\n'
        ])

    return list_cve

        # list_cve.append([[software.software, res_json]])
        # print(tagged)
        # for idx, tag in enumerate(tagged):
        #     if (tag[1] == 'CD' or is_it_version_nn(tag[0], tag[1])) and len(tag[0]) > 1:
        #         is_found = False
        #         for i in reversed(range(idx)):
        #             if tagged[i][1] == 'IN' or tagged[i][1] == '.':
        #                 print('Vulnerable' if not is_patch else 'Patch')
        #                 print("%s: %s" % (tag[1], tag[0]))
        #                 search_signification(tagged, i, is_patch)
        #                 print("%s: %s" % (tagged[i][1], tagged[i][0]))
        #                 is_found = True
        #                 break
        #         if not is_found:
        #             print('Vulnerable' if not is_patch else 'Patch')
        #             print("%s: %s" % (tag[1], tag[0]))

        #     if tag[1] == 'VBN' and tag[0] in patchs:
        #         is_patch = True
        # print(res_json)
            #for resultat in resultats:
            #    print(resultat[0])

'''
with query, recover all cve and stock in array

Arg:
    client: connection of opensearch
'''
def fill_data(client):
    results = query_opensearch(client, query_by_date)
    final_data = []
    # final_data = [['title', 'description', 'product']]
    for result in results:
        product = result['_source']['containers']['cna']['affected'][0]['product'] if 'affected' in result['_source']['containers']['cna'] and 'product' in result['_source']['containers']['cna']['affected'][0] else ''
        vendor = result['_source']['containers']['cna']['affected'][0]['vendor'] if 'affected' in result['_source']['containers']['cna'] and 'vendor' in result['_source']['containers']['cna']['affected'][0] else ''

        title = result['_source']['containers']['cna']['title'] if 'title' in result['_source']['containers']['cna'] else ''
        descriptions = result['_source']['containers']['cna']['descriptions'][0]['value']

        new_cve = Cve(title, result['_source']['cveMetadata']['cveId'], descriptions, product, vendor, result['_source']['containers']['cna']['references'], result['_source']['cveMetadata']['datePublished'])
        final_data.append(new_cve)
    return final_data


def main():
    client = OpenSearch(
        hosts=[{'host': host, 'port': port}],
        http_auth=auth,
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False
    )
    all_software = read_calc('./data.csv')
    all_data = fill_data(client)
    list_cve = research_all_cve(all_data, all_software)
    fill_latex(list_cve)
    # create_csv(all_data)

if __name__ == "__main__":
    main()