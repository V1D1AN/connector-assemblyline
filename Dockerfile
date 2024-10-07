# Utilisation d'une image Python légère
FROM python:3.9-slim
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

RUN apt-get update && apt-get install -y libmagic1
# Créer un dossier de travail dans le conteneur
COPY src /opt/connector
WORKDIR /opt/connector

# Installation des dépendances Python
RUN pip3 install --no-cache-dir -r /opt/connector/requirements.txt

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
