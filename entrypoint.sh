#!/bin/bash

# Afficher un message de démarrage
cd /opt/connector
echo "Démarrage du connecteur Assemblyline..."

# Vérifier si les variables d'environnement sont définies
if [ -z "$OPENCTI_URL" ]; then
  echo "Erreur : OPENCTI_URL n'est pas défini. Veuillez le spécifier."
  exit 1
fi

if [ -z "$OPENCTI_TOKEN" ]; then
  echo "Erreur : OPENCTI_TOKEN n'est pas défini. Veuillez le spécifier."
  exit 1
fi

if [ -z "$ASSEMBLYLINE_URL" ]; then
  echo "Erreur : ASSEMBLYLINE_URL n'est pas défini. Veuillez le spécifier."
  exit 1
fi

if [ -z "$ASSEMBLYLINE_API_KEY" ]; then
  echo "Erreur : ASSEMBLYLINE_API_KEY n'est pas défini. Veuillez le spécifier."
  exit 1
fi

# Démarrer l'application Python
python3 main.py
