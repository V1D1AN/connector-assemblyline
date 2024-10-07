import json
import stix2
from assemblyline_client import get_client
from pycti import OpenCTIConnectorHelper, get_config_variable
from uuid import uuid4
from typing import Any, Dict, List, Tuple
import time
import re
import itertools


# Constantes
STIX_FILE_ID = "file--{uuid4()}"
STIX_BUNDLE_ID = "bundle--{uuid4()}"

class AssemblylineConnector:
    def __init__(self):
        # Chargement de la configuration
        self.assemblyline_url = get_config_variable("ASSEMBLYLINE_URL", ["assemblyline", "url"])
        self.assemblyline_username = get_config_variable("ASSEMBLYLINE_USERNAME", ["assemblyline", "username"])
        self.assemblyline_api_key = get_config_variable("ASSEMBLYLINE_API_KEY", ["assemblyline", "api_key"])
        self.polling_interval = get_config_variable("ASSEMBLYLINE_POLLING_INTERVAL", ["assemblyline", "polling_interval"])

        # Initialisation du client Assemblyline
        self.al_client = get_client(self.assemblyline_url, apikey=(self.assemblyline_username, self.assemblyline_api_key), verify=False)

        # Initialisation de l'aide pour l'intégration avec OpenCTI
        self.helper = OpenCTIConnectorHelper({
            "connector_id": "assemblyline",
            "connector_name": "Assemblyline",
            "connector_type": "import",
            "config": {
                "assemblyline_url": self.assemblyline_url,
                "assemblyline_username": self.assemblyline_username,
                "assemblyline_api_key": self.assemblyline_api_key,
                "polling_interval": self.polling_interval
            }
        })

        print("Initialisation du connecteur Assemblyline terminée")

    def get_all_sids(self) -> List[str]:
        # Récupère tous les identifiants de soumission (SIDs) de Assemblyline
        print("Récupération des SIDs...")
        #query = f"params.submitter:{self.assemblyline_username}"
        #submissions = self.al_client.search.stream.submission(query=query)
        submissions = self.al_client.search.stream.submission(query=f"params.submitter:{self.assemblyline_username}")
        #submissions = self.al_client.search.submission(query=f"params.submitter:{self.assemblyline_username}")
        sids = [submission['sid'] for submission in submissions]
        print(f"SIDs récupérés : {sids}")
        return sids

    def get_submission_results(self, sid: str) -> Dict[str, Any]:
        # Récupère les résultats pour un identifiant de soumission donné (SID)
        print(f"Récupération des résultats pour le SID {sid}...")
        try:
            submission_details = self.al_client.submission.summary(sid)
            return submission_details
        except ValueError as e:
            self.helper.log_error(f"Échec de la récupération des résultats pour le SID {sid}.")
            return {}

    def extract_iocs(self, sid: str) -> Dict[str, List[str]]:
        # Récupère les IOCs à partir d'un identifiant de soumission (SID) dans Assemblyline
        print(f"Récupération des IOCs pour le SID {sid}...")
        try:
            submission_summary = self.al_client.submission.summary(sid)
            collected_iocs = {}
            for tag_name, tag_values in submission_summary['tags']['ioc'].items():
              for tag_value, tag_verdict, tag_safelist, classification in tag_values:
                  if ("suspicious" in str(tag_value).lower()) or ("malicious" in str(tag_value).lower()) or \
                   ("suspicious" in str(tag_verdict).lower()) or ("malicious" in str(tag_verdict).lower()) or \
                   ("suspicious" in str(tag_safelist).lower()) or ("malicious" in str(tag_safelist).lower()) or \
                   ("suspicious" in str(classification).lower()) or ("malicious" in str(classification).lower()):
                     #if tag_name.startswith('network'):
                     #   collected_iocs.setdefault(tag_name, []).append(tag_value)
                     if tag_name == "network.static.ip" or tag_name == "network.dynamic.ip":
                        collected_iocs.setdefault("ipv4-addr", []).append(f"[ipv4-addr:value = \"{tag_value}\"]")
                     elif tag_name == "network.static.domain" or tag_name == "network.dynamic.domain":
                        collected_iocs.setdefault("domain-name", []).append(f"[domain-name:value = \"{tag_value}\"]")
                     elif tag_name == "network.static.uri" or tag_name == "network.dynamic.uri":
                        collected_iocs.setdefault("url", []).append(tag_value)
                     else:
                        collected_iocs.setdefault(tag_name, []).append(tag_value)
            print(f"IOCs récupérés pour le SID {sid} : {collected_iocs}")
            return collected_iocs
        except ValueError as e:
            self.helper.log_error(f"Échec de la récupération des IOCs pour le SID {sid}.")
            return {}

    def create_stix_file_object(self, file_info: Dict) -> Dict:
        # Crée un objet STIX à partir des informations de fichier
        print("Création d'un objet STIX pour le fichier...")
        stix_file = {
            "type": "file",
            "id": f"file--{uuid4()}",
            "name": file_info.get("name"),
            "hashes": {
                "md5": file_info.get("md5"),
                "sha1": file_info.get("sha1"),
                "sha256": file_info.get("sha256")
            },
            "size": file_info.get("size"),
            "created": "2023-03-01T12:00:00.000Z" #time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }
        print(f"Objet STIX pour le fichier créé : {stix_file}")
        return stix_file

    def create_stix_ioc(self, key, value):
        key = key.replace('.', '')
        if key in ['network', 'domain', 'ip', 'uri']:
            pattern = f"[{key} = '{value}']"
        elif key == "url":
            pattern = f"[url:value = '{value}']"
        else:
            pattern = f"[{key}:value = '{value}']"
        stix_ioc = {
            "type": "indicator",
            "id": f"indicator--{uuid4()}",
            "labels": ["malicious"],
            "name": f"Exemple d'indicateur pour {key}",
            #"pattern_type": "stix",
            "pattern": pattern
        }
        return stix_ioc

    def create_stix_bundle(self, stix_objects: List[Dict]) -> str:
        # Crée un bundle STIX à partir d'une liste d'objets STIX
        print("Création d'un bundle STIX...")
        bundle = stix2.Bundle(objects=stix_objects)
        serialized_bundle = bundle.serialize()
        print(f"Bundle STIX créé : {serialized_bundle}")
        return serialized_bundle

    def process_and_send_reports(self):
        # Traite les rapports Assemblyline et les envoie à OpenCTI sous forme d'objets STIX
        sids = self.get_all_sids()
        if not sids:
            return

        for sid in sids:
            stix_objects = []
            submission_results = self.get_submission_results(sid)
            if not submission_results:
                continue

            file_info = submission_results.get("file_info", {})
            if file_info:
                stix_file = self.create_stix_file_object(file_info)
                stix_objects.append(stix_file)

            iocs = self.extract_iocs(sid)
            if iocs:
              for key, values in iocs.items():
                for value in values:
                    stix_ioc = self.create_stix_ioc(key, value)
                    stix_objects.append(stix_ioc)

            print(f"Objets STIX créés pour le SID {sid} : {stix_objects}")
            if stix_objects:
                bundle = self.create_stix_bundle(stix_objects)
                self.helper.send_stix2_bundle(bundle)
                print("Bundle STIX envoyé à OpenCTI")
            if not stix_objects:
                print("Aucun objet STIX créé pour le SID {sid}. IOCs récupérés : {iocs}")

    def run(self):
        # Boucle principale pour récupérer, traiter et envoyer les rapports à intervalles réguliers
        self.helper.log_info("Démarre du connecteur Assemblyline...")
        while True:
            try:
                self.process_and_send_reports()
            except Exception as e:
                logging.error(f"Erreur: {e}")
            time.sleep(int(self.polling_interval))

if __name__ == "__main__":
    try:
        connector = AssemblylineConnector()
        connector.run()
    except Exception as e:
        logging.error(f"Erreur : {e}")
