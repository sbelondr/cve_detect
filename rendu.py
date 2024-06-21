import csv
import argparse
import requests
import datetime
import nltk
import re
import sys
from nltk.corpus import treebank
from obj import Software as Sft

def download_nltk_feature():
    nltk.download('punkt')
    nltk.download('averaged_perceptron_tagger')
    nltk.download('treebank')

last_cve = 'CVE-2024-3864'
list_cve = []

user = 'john'
password = 'password'

url = "http://localhost:8000"

fp = open('data.tex', 'w')

date_format = "%d/%m/%y"

# Regex version
reg_version = r'((\d+\.){1,}+\d+)'
reg_v_version = r'(v\.?\d.+)'

# IN + CD 
current_version = ['through', 'in']
before = ['until', 'till', 'before', 'ahead']
between = ['between', 'from']
patchs = ['patched', 'fixed']

def fill_latex():
    for cve in list_cve:
        for idx, row in enumerate(cve):
            if idx == 0:
                fp.write("\evidenchapterbleu{%s: %s}{1}" % (row[0], row[1]))
            else:
                fp.write(row)

def search_signification(tagged, i, is_patch):
    if is_patch:
        print("Fix")
        return 1
    elif tagged[i][0] in before:
        print("Avant")
        return 2
    elif tagged[i][0] in between:
        print("Entre")
        return 3
    elif tagged[i][0] in current_version:
        print("Cette version")
        return 4
    print("Je sais pas")
    return 0

'''
For example detect v.1.4 or v2.3.3
'''
def is_it_version_nn(word, code):
    return code == 'NN' and re.match(reg_v_version, word)

def latex_special_char(ref):
    ref = ref.replace('\\', '\\\\')
    ref = ref.replace('_', '\\_')
    ref = ref.replace('&', '\\&')
    ref = ref.replace('%', '\\%')
    return ref

'''
More info for the cve
Arg:
    cve: id of the cve (ex: CVE-2022-01-01)
'''
def info_cve(cve):
    res = requests.get(url + '/api/cve/' + cve, auth=(user, password))
    res_json = res.json()
    print(res_json)

    try:
        ref = ''
        for cnt, x in enumerate(res_json['raw_nvd_data']['references']):
            ref = res_json['raw_nvd_data']['references'][cnt]['url']
            break
        ref = latex_special_char(ref)
        for x, y in res_json['raw_nvd_data']['metrics'].items():
            return "Version : %s\n\nScore: %s\n\n\\href{%s}{Lien}" % (y[0]['cvssData']['version'], y[0]['cvssData']['baseScore'], ref)
    except expression as identifier:
        return ''

def is_cve_in_list(summary, all_software):
    for software in all_software:
        if re.search(software.software, summary, re.IGNORECASE):
            return software
    return False

'''
Interprete JSON result
Args:
    res_json: json data
    vendor: society
    product: name of the software
'''
def research_all_cve(res_json, all_software):
    for x in res_json:
        if x['id'] == last_cve:
            return 0
        software = is_cve_in_list(x['summary'], all_software)
        if software == False:
            continue
        summary = x['summary']
        print('==============================================')
        print(summary)
        tokens = nltk.word_tokenize(summary)
        tagged = nltk.pos_tag(tokens)
        is_patch = False
        last_count = 0
        print(tagged)
        for idx, tag in enumerate(tagged):
            if (tag[1] == 'CD' or is_it_version_nn(tag[0], tag[1])) and len(tag[0]) > 1:
                is_found = False
                for i in reversed(range(idx)):
                    if tagged[i][1] == 'IN' or tagged[i][1] == '.':
                        print('Vulnerable' if not is_patch else 'Patch')
                        print("%s: %s" % (tag[1], tag[0]))
                        search_signification(tagged, i, is_patch)
                        print("%s: %s" % (tagged[i][1], tagged[i][0]))
                        is_found = True
                        break
                if not is_found:
                    print('Vulnerable' if not is_patch else 'Patch')
                    print("%s: %s" % (tag[1], tag[0]))

            if tag[1] == 'VBN' and tag[0] in patchs:
                is_patch = True
            #for resultat in resultats:
            #    print(resultat[0])
        summary = latex_special_char(summary)
        dt = datetime.datetime.fromisoformat(x['updated_at'])
        dt_fr = dt.strftime(date_format)
        list_cve.append([
            [software.software, x['id']],
            "\evidencontenu{%s: %s}{%s}{" % (software.society, software.software, x['id']),
            "%s\n\nDernière update : %s\n\\bigskip\n\n\\textbf{Description :}\n%s" % (info_cve(x['id']), dt_fr, summary),
            '}\n'
        ])
    return 200

'''
search for one product
https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=
Args:
    software: Sft.Software
'''
def request_cve(all_software):
    page = 1
    status_code = 200
    while status_code == 200:
        res = requests.get(url + '/api/cve?page=' + str(page), auth=(user, password))
        #res = requests.get(url + '/api/cve?vendor' + software.society + '&product=' + software.software + '&page=' + str(page), auth=(user, password))
        status_code = res.status_code
        if status_code == 200:
            res_json = res.json()
            status_code = research_all_cve(res_json, all_software)
        page += 1

def cross_data(all_software):
    #for software in all_software:
    request_cve(all_software)

def read_calc(filename):
    all_software = []
    with open(filename) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=';')
        line_count = 0
        for row in csv_reader:
            if line_count != 0:
                all_software.append(Sft.Software(row[0], row[1], row[2:]))
            line_count += 1
    return all_software

def parse_args(args):
    parser = argparse.ArgumentParser(
        prog='cvecheck',
        description='This program recover all cve and match with your software list for create a latex file.',
        epilog='Goodbye!')
    parser.add_argument('filename', help="CSV file contain list of all software to check")           # positional argument
    parser.add_argument('-a', '--api', help="Pass to opencve api: give url of the api")      # option that takes a value
    parser.add_argument('--json', help="Pass to NIST json file. Give the json file")      # option that takes a value
    parser.add_argument('-v', '--verbose', action='store_true')  # on/off flag
    args = parser.parse_args()
    print(args.filename, args.api, args.json, args.verbose)

def main(args):
    parse_args(args)
    sys.exit(0)
    all_software = read_calc('list.csv')
    cross_data(all_software)
    fill_latex()
    fp.close()

if __name__ == "__main__":
    main(sys.argv)

