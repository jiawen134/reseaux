# Guide d'expérience d'analyse UDP

## Objectif de l'expérience
Analyser le principe de fonctionnement du protocole UDP à travers les requêtes DNS, comprendre la structure et le processus de transmission des paquets UDP.

## Préparation de l'environnement expérimental
- Serveur DNS (pour la capture de paquets)
- Machine cliente (pour initier les requêtes DNS)
- Outil tcpdump
- Connexion réseau

## Étapes de l'expérience

### Étape 1 : Démarrer la capture de paquets sur le serveur DNS

Exécuter les commandes suivantes sur le serveur DNS pour commencer la capture :

```bash
# Capturer les paquets UDP du port 53 (port DNS)
sudo tcpdump -i any -n -s 0 -w dns_capture.pcap port 53

# Pour voir le contenu de la capture en temps réel, utiliser :
sudo tcpdump -i any -n -v port 53
```

Explication des paramètres :
- `-i any` : Écouter toutes les interfaces réseau
- `-n` : Ne pas résoudre les noms d'hôtes, afficher les adresses IP
- `-s 0` : Capturer les paquets complets
- `-w dns_capture.pcap` : Sauvegarder les résultats de capture dans un fichier
- `-v` : Sortie détaillée
- `port 53` : Capturer uniquement le trafic du port 53

### Étape 2 : Exécuter des requêtes DNS depuis la machine cliente

Dans un autre terminal ou sur la machine cliente, exécuter :

```bash
# Requête DNS de base
nslookup www.google.com

# Requête avec serveur DNS spécifique
nslookup www.google.com 8.8.8.8

# Requêtes pour différents types d'enregistrements
nslookup -type=MX google.com
nslookup -type=NS google.com
nslookup -type=AAAA google.com
```

### Étape 3 : Arrêter la capture et analyser les résultats

Arrêter tcpdump (Ctrl+C), puis analyser le fichier de capture :

```bash
# Voir le contenu du fichier de capture
tcpdump -r dns_capture.pcap -n -v

# Statistiques de capture
tcpdump -r dns_capture.pcap -n | wc -l
```

## Analyse des résultats attendus

Vous devriez pouvoir observer le modèle de communication UDP suivant :

1. **Requête DNS** (client → serveur DNS)
   - Port source : port aléatoire (par ex. 45123)
   - Port destination : 53
   - Protocole UDP

2. **Réponse DNS** (serveur DNS → client)
   - Port source : 53
   - Port destination : port aléatoire du client
   - Protocole UDP

## Analyse de la structure des paquets

Un paquet UDP de requête DNS typique contient :
- En-tête IP (20 octets)
- En-tête UDP (8 octets)
- Données de requête DNS

## Étape suivante
Après avoir terminé l'expérience, utiliser le script Python fourni pour générer un diagramme de séquence et un rapport d'analyse détaillé. 