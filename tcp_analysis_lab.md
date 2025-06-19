# Guide d'expérience d'analyse TCP

## Objectif de l'expérience
Analyser le principe de fonctionnement du protocole TCP à travers l'accès aux services Web, comprendre le processus complet de connexion TCP incluant l'établissement de connexion, le transfert de données et la fermeture de connexion.

## Préparation de l'environnement expérimental
- Serveur Web (web01) pour la capture de paquets
- Machine cliente avec navigateur web
- Outil tcpdump
- Serveur HTTP simple (optionnel : Python HTTP server)
- Connexion réseau

## Étapes de l'expérience

### Étape 1 : Préparer le serveur Web

Sur le serveur web01, d'abord démarrer un serveur HTTP simple :

```bash
# Démarrer un serveur HTTP Python simple sur le port 8080
python3 -m http.server 8080

# Ou utiliser un serveur existant (Apache, Nginx, etc.)
# Vérifier que le service écoute sur le port souhaité
netstat -tuln | grep :80
```

### Étape 2 : Démarrer la capture de paquets sur le serveur Web

Sur le serveur web01, exécuter les commandes suivantes pour commencer la capture :

```bash
# Capturer les paquets TCP du port 80 ou 8080 (ports HTTP)
sudo tcpdump -i any -n -s 0 -w tcp_capture.pcap port 80 or port 8080

# Pour voir le contenu de la capture en temps réel, utiliser :
sudo tcpdump -i any -n -v port 80 or port 8080
```

Explication des paramètres :
- `-i any` : Écouter toutes les interfaces réseau
- `-n` : Ne pas résoudre les noms d'hôtes, afficher les adresses IP
- `-s 0` : Capturer les paquets complets
- `-w tcp_capture.pcap` : Sauvegarder les résultats de capture dans un fichier
- `-v` : Sortie détaillée
- `port 80 or port 8080` : Capturer le trafic des ports HTTP

### Étape 3 : Accéder au service Web depuis la machine cliente

Depuis la machine cliente, accéder au serveur web :

```bash
# Utiliser curl pour des requêtes HTTP simples
curl http://[IP_DU_SERVEUR]:8080/

# Utiliser wget pour télécharger des fichiers
wget http://[IP_DU_SERVEUR]:8080/index.html

# Ou utiliser un navigateur web pour accéder à :
# http://[IP_DU_SERVEUR]:8080/
```

Effectuer plusieurs types de requêtes :
- Requête GET simple
- Téléchargement de fichiers
- Requêtes multiples pour observer les connexions persistantes

### Étape 4 : Arrêter la capture et analyser les résultats

Arrêter tcpdump (Ctrl+C), puis analyser le fichier de capture :

```bash
# Voir le contenu du fichier de capture
tcpdump -r tcp_capture.pcap -n -v

# Statistiques de capture
tcpdump -r tcp_capture.pcap -n | wc -l

# Filtrer les paquets de handshake (SYN, SYN-ACK, ACK)
tcpdump -r tcp_capture.pcap -n 'tcp[tcpflags] & tcp-syn != 0'
```

## Analyse des résultats attendus

Vous devriez pouvoir observer le processus complet de communication TCP :

### 1. **Établissement de connexion (Handshake à 3 voies)**
   - **SYN** : Client → Serveur (demande de connexion)
   - **SYN-ACK** : Serveur → Client (acceptation + acquittement)
   - **ACK** : Client → Serveur (confirmation)

### 2. **Transfert de données**
   - **Requête HTTP** : Client → Serveur (GET /index.html)
   - **Réponse HTTP** : Serveur → Client (200 OK + contenu)
   - **Acquittements** : Confirmations bidirectionnelles

### 3. **Fermeture de connexion (Handshake à 4 voies)**
   - **FIN** : Initiateur → Récepteur (demande de fermeture)
   - **ACK** : Récepteur → Initiateur (acquittement)
   - **FIN** : Récepteur → Initiateur (fermeture réciproque)
   - **ACK** : Initiateur → Récepteur (confirmation finale)

## Analyse de la structure des paquets TCP

Un paquet TCP typique contient :
- **En-tête IP** (20 octets)
- **En-tête TCP** (20+ octets)
  - Numéros de séquence et d'acquittement
  - Drapeaux TCP (SYN, ACK, FIN, RST, PSH, URG)
  - Taille de fenêtre
  - Checksum
- **Données de l'application** (HTTP dans notre cas)

## Points d'observation importants

- **Numéros de séquence** : Suivre l'évolution des numéros de séquence
- **Contrôle de flux** : Observer la taille de fenêtre TCP
- **Retransmissions** : Identifier les paquets retransmis en cas de perte
- **Fragmentation** : Voir comment les grandes données sont segmentées

## Étape suivante
Après avoir terminé l'expérience, utiliser le script Python fourni pour générer un diagramme de séquence détaillé et un rapport d'analyse complet du processus TCP. 