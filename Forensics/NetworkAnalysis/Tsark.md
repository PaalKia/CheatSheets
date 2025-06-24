# TSHARK Cheat Sheet - Analyse Réseau

---

## Analyse en temps réel (capture live)

- **Démarrer une capture sur interface réseau (ex: eth0)**  
  ```bash
  tshark -i eth0

- **Limiter la capture à X paquets**
  ```bash
  tshark -i eth0 -c 100

- **Filtrer les paquets en capture (ex: HTTP uniquement)**
  ```bash
  tshark -i eth0 -f "tcp port 80"

- *Ou avec un filtre display*
    ```bash
    tshark -i eth0 -Y "http"

- **Afficher uniquement certains champs (ex: IP source et destination)**
  ```bash
  tshark -i eth0 -T fields -e ip.src -e ip.dst

- **Afficher un résumé des conversations TCP**
  ```bash
  tshark -i eth0 -q -z conv,tcp

- **Sauvegarder la capture en fichier pcap**
  ```bash
  tshark -i eth0 -w capture.pcap

- **Afficher les statistiques de protocoles en temps réel**
  ```bash
  tshark -i eth0 -q -z io,stat,5  # stats toutes les 5 secondes

  

## Analyse de fichiers PCAP

- **Lire un fichier pcap**
  ```bash
  tshark -r fichier.pcap

- **Appliquer un filtre display sur un fichier pcap**
  ```bash
  tshark -r fichier.pcap -Y "http.request.method == POST"

- **Extraire les flux TCP (sessions)**
  ```bash
  tshark -r fichier.pcap -q -z conv,tcp

- **Lister toutes les adresses IP présentes**
  ```bash
  tshark -r fichier.pcap -T fields -e ip.src -e ip.dst | sort | uniq

- **Extraire le contenu des paquets HTTP POST**
  ```bash
  tshark -r fichier.pcap -Y "http.request.method == POST" -T fields -e http.file_data

- **Extraire les noms de domaines DNS résolus**
  ```bash
  tshark -r fichier.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | sort | uniq

- **Extraire toutes les URL HTTP**
  ```bash
  tshark -r fichier.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

- **Afficher les statistiques d’IO (paquets, octets) par intervalle de temps**
  ```bash
  tshark -r fichier.pcap -q -z io,stat,10

- **Extraire les échanges TLS/SSL (handshake, alertes, etc.)**
  ```bash
  tshark -r fichier.pcap -Y "ssl || tls"

- **Extraire les adresses MAC uniques**
  ```bash
  tshark -r fichier.pcap -T fields -e eth.src -e eth.dst | sort | uniq

- **Limiter l’analyse à un protocole spécifique**
  ```bash
  tshark -r fichier.pcap -Y "tcp.port == 443"

  
