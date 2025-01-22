import json
import os
import requests
import yaml
import pandas as pd
import xml.etree.ElementTree as ET


in_path = "input/Nmap"  # Change this value to folder containing all Nmap files
out_path = "nmap_out_ciphers.csv"  # Change this value to the output file name / path

ciphersuite_tech_path = "https://raw.githubusercontent.com/hcrudolph/ciphersuite.info/refs/heads/master/directory/fixtures/01_technologies.yaml"
# ciphersuite_vuln_path = "https://raw.githubusercontent.com/hcrudolph/ciphersuite.info/refs/heads/master/directory/fixtures/00_vulnerabilities.yaml"

ciphers_set = set()  # Records unique entries of ciphers found in Nmap results
df = pd.DataFrame(columns=['ip', 'port', 'cipher', 'cipher_strength', 'kex_info', 'Security',
                  'ProtocolVersion', 'KexAlgorithm', 'AuthAlgorithm', 'EncAlgorithm', 'HashAlgorithm'])
df_tls = pd.DataFrame(columns=['ip', 'port', 'tls_version'])


def load_yaml_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = yaml.safe_load(response.text)

        print(f"\t> Loaded YAML data (entries: {len(data)}) from '{url}'")
        return data

    except requests.exceptions.RequestException as e:
        raise Exception(f"\t> [ERROR] Error fetching YAML data: {e}")
    except yaml.YAMLError as e:
        raise Exception(f"\t>  [ERROR] Error parsing YAML data: {e}")


def find_fields(data, model, pk):
    for entry in data:
        if entry.get('model') == model and entry.get('pk') == pk:
            return entry.get('fields', {})
    return None


def query_cipher(cipher):
    base_url = "https://ciphersuite.info/api/cs/"
    url = f"{base_url}{cipher}/"

    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"\t> [ERROR] Error querying {cipher}: {str(e)}")
        return None


# Load ciphersuite YAML models
print("[!] Loading ciphersuite models..")
ciphersuite_model = load_yaml_from_url(ciphersuite_tech_path)


# Parse nmap ciphers into dataframe
print(f"[!] Parsing Nmap XML files under '{in_path}'..")
for root_path, dirs, files in os.walk(in_path):
    for file in files:
        file_name, file_extension = os.path.splitext(file)

        if file_extension != ".xml":
            continue

        try:
            tree = ET.parse(os.path.join(root_path, file))
            root = tree.getroot()
        except Exception as e:
            print(f"\t> [ERROR] Error parsing {file_name}: {str(e)}")

        print(f"\t> Found {file_name}")

        for host in root.findall("host"):
            ip_address = host.find("address").get("addr")  # Extract host IP

            for port in host.find("ports").findall("port"):
                # Only process ports with ciphers if the script "ssl-enum-ciphers" is present
                script = port.find("script[@id='ssl-enum-ciphers']")

                if script is None or len(script) == 0:
                    continue

                # Obtain TLS versions
                script_output = script.get("output", "")
                for line in script_output.split("\n"):

                    if "TLSv" not in line:
                        continue

                    nmap_tls_version = line.strip()[:-1]
                    df_tls = pd.concat([df_tls, pd.DataFrame([{
                        'ip': ip_address,
                        'port': port.get("portid"),
                        'tls_version': nmap_tls_version
                    }])], ignore_index=True)

                # Extract ciphers
                for cipher in script.findall(".//table[@key='ciphers']/table"):
                    nmap_cipher_name = cipher.find(
                        "elem[@key='name']").text if cipher.find("elem[@key='name']") is not None else ""
                    nmap_cipher_strength = cipher.find(
                        "elem[@key='strength']").text if cipher.find("elem[@key='strength']") is not None else ""
                    nmap_kex_info = cipher.find(
                        "elem[@key='kex_info']").text if cipher.find("elem[@key='kex_info']") is not None else ""

                    df = pd.concat([df, pd.DataFrame([{
                        'ip': ip_address,
                        'port': port.get("portid"),
                        'cipher': nmap_cipher_name,
                        'cipher_strength': nmap_cipher_strength,
                        'kex_info': nmap_kex_info
                    }])], ignore_index=True)

                    ciphers_set.add(nmap_cipher_name)

print(f"[!] Total entries extracted: {len(df.index)}")

df = df.drop_duplicates()
df_tls = df_tls.drop_duplicates()

print(f"[!] Total entries extracted (after deduplication): {len(df.index)}")
print(f"[!] Querying ciphersuite API to extract kex/auth/enc/hash alogrithms..")

model_pks = ['ProtocolVersion', 'KexAlgorithm',
             'AuthAlgorithm', 'EncAlgorithm', 'HashAlgorithm']
api_pks = ['protocol_version', 'kex_algorithm',
           'auth_algorithm', 'enc_algorithm', 'hash_algorithm']

for cipher in ciphers_set:
    api_res = query_cipher(cipher)

    if api_res is None:
        continue

    print(f"\t> cipher: {cipher}, Security: {api_res[cipher]['security']}, {', '.join(
        [f'{model_pk}: {api_res[cipher][api_pk]}' for model_pk, api_pk in zip(model_pks, api_pks)])} ")

    vulns = set()

    # Map algorithms (ciphersuite API) to vulnerabilities (ciphersuite model)
    for model_pk, api_pk in zip(model_pks, api_pks):
        model_res = find_fields(ciphersuite_model, f"directory.{
                                model_pk}", api_res[cipher][api_pk])

        if model_res is None:
            print(f"\t\t>[ERROR] error mapping {api_pk}")
            continue

        print(f"\t\t{api_pk}: {model_res['vulnerabilities']}")

        # Insert new column if the vulnerability does not already exist
        columns = list(df.columns)
        for vuln in model_res['vulnerabilities']:
            if vuln not in columns:
                df.insert(len(columns), vuln, False)

        vulns.update(model_res['vulnerabilities'])

    # Update data back to dataframe
    idx = df.index[df['cipher'] == cipher]
    df.loc[idx, ['Security'] + model_pks] = [api_res[cipher]
                                             ['security']] + [api_res[cipher][api_pk] for api_pk in api_pks]
    df.loc[idx, list(vulns)] = True

# Output results to CSV
df.to_csv(out_path, index=False)

print(f"[!] Results saved to {out_path}")
