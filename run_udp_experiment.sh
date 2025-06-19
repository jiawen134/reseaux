#!/bin/bash

# Script d'exécution de l'expérience d'analyse UDP
# Ce script guidera l'utilisateur à travers les étapes de l'expérience d'analyse UDP

echo "================================="
echo "    Expérience d'analyse UDP"
echo "================================="
echo

# Vérifier les permissions
if [ "$EUID" -ne 0 ]; then
    echo "❌ Veuillez exécuter ce script avec sudo pour obtenir les privilèges de capture"
    echo "   Utilisation: sudo ./run_udp_experiment.sh"
    exit 1
fi

# Vérifier les outils nécessaires
echo "🔍 Vérification des outils nécessaires..."
missing_tools=()

if ! command -v tcpdump &> /dev/null; then
    missing_tools+=("tcpdump")
fi

if ! command -v nslookup &> /dev/null; then
    missing_tools+=("nslookup")
fi

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo "❌ Outils manquants: ${missing_tools[*]}"
    echo "Veuillez installer: sudo apt-get install tcpdump dnsutils"
    exit 1
fi

echo "✅ Vérification des outils terminée"

# Configurer les paramètres de l'expérience
CAPTURE_FILE="dns_capture.pcap"
DNS_TARGET="www.google.com"
CAPTURE_DURATION=10

echo
echo "📋 Paramètres de l'expérience:"
echo "   - Fichier de capture: $CAPTURE_FILE"
echo "   - Cible de requête DNS: $DNS_TARGET"
echo "   - Durée de capture: ${CAPTURE_DURATION} secondes"
echo

# Commencer la capture
echo "🎯 Début de la capture de trafic DNS (${CAPTURE_DURATION} secondes)..."
timeout $CAPTURE_DURATION tcpdump -i any -n -s 0 -w $CAPTURE_FILE port 53 &
TCPDUMP_PID=$!

# Attendre le démarrage de tcpdump
sleep 2

echo "🔍 Exécution des requêtes DNS..."
# Exécuter plusieurs requêtes DNS pour générer du trafic
nslookup $DNS_TARGET 8.8.8.8 > /dev/null 2>&1
nslookup -type=MX google.com 8.8.8.8 > /dev/null 2>&1
nslookup -type=NS google.com 8.8.8.8 > /dev/null 2>&1
nslookup www.github.com 8.8.8.8 > /dev/null 2>&1
nslookup www.stackoverflow.com 8.8.8.8 > /dev/null 2>&1

echo "⏱️  Attente de la fin de la capture..."
wait $TCPDUMP_PID

# Vérifier le fichier de capture
if [ ! -f "$CAPTURE_FILE" ]; then
    echo "❌ Fichier de capture non généré, expérience échouée"
    exit 1
fi

PACKET_COUNT=$(tcpdump -r $CAPTURE_FILE 2>/dev/null | wc -l)
echo "✅ Capture terminée, $PACKET_COUNT paquets capturés"

# Afficher un aperçu du contenu capturé
echo
echo "📊 Aperçu des paquets:"
echo "----------------------------------------"
tcpdump -r $CAPTURE_FILE -n -c 10 2>/dev/null
echo "----------------------------------------"

echo
echo "🔬 Vous pouvez maintenant utiliser les commandes suivantes pour une analyse détaillée:"
echo
echo "1. Voir tous les paquets:"
echo "   tcpdump -r $CAPTURE_FILE -n -v"
echo
echo "2. Utiliser l'analyseur Python pour générer diagrammes et rapports:"
echo "   python3 udp_analyzer.py $CAPTURE_FILE"
echo
echo "3. Analyser manuellement des paquets spécifiques:"
echo "   tcpdump -r $CAPTURE_FILE -n -X"
echo

# Si l'analyseur Python existe, offrir l'option de l'exécuter
if [ -f "udp_analyzer.py" ]; then
    echo "🤖 Voulez-vous exécuter immédiatement l'analyseur Python? (y/n)"
    read -r response
    if [ "$response" = "y" ] || [ "$response" = "Y" ]; then
        echo "🚀 Exécution de l'analyseur..."
        python3 udp_analyzer.py $CAPTURE_FILE
    fi
fi

echo
echo "✅ Expérience d'analyse UDP terminée!"
echo "Fichiers d'expérience:"
echo "   - Fichier de capture: $CAPTURE_FILE"
if [ -f "udp_sequence_diagram.png" ]; then
    echo "   - Diagramme de séquence: udp_sequence_diagram.png"
fi
if [ -f "udp_analysis_report.md" ]; then
    echo "   - Rapport d'analyse: udp_analysis_report.md"
fi 