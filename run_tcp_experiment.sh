#!/bin/bash

# Script d'exécution de l'expérience d'analyse TCP
# Ce script guidera l'utilisateur à travers les étapes de l'expérience d'analyse TCP

echo "================================="
echo "    Expérience d'analyse TCP"
echo "================================="
echo

# Vérifier les permissions
if [ "$EUID" -ne 0 ]; then
    echo "❌ Veuillez exécuter ce script avec sudo pour obtenir les privilèges de capture"
    echo "   Utilisation: sudo ./run_tcp_experiment.sh"
    exit 1
fi

# Vérifier les outils nécessaires
echo "🔍 Vérification des outils nécessaires..."
missing_tools=()

if ! command -v tcpdump &> /dev/null; then
    missing_tools+=("tcpdump")
fi

if ! command -v curl &> /dev/null; then
    missing_tools+=("curl")
fi

if ! command -v python3 &> /dev/null; then
    missing_tools+=("python3")
fi

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo "❌ Outils manquants: ${missing_tools[*]}"
    echo "Veuillez installer: sudo apt-get install tcpdump curl python3"
    exit 1
fi

echo "✅ Vérification des outils terminée"

# Configurer les paramètres de l'expérience
CAPTURE_FILE="tcp_capture.pcap"
HTTP_PORT=8080
CAPTURE_DURATION=15

echo
echo "📋 Paramètres de l'expérience:"
echo "   - Fichier de capture: $CAPTURE_FILE"
echo "   - Port HTTP: $HTTP_PORT"
echo "   - Durée de capture: ${CAPTURE_DURATION} secondes"
echo

# Étape 1: Démarrer le serveur HTTP simple
echo "🌐 Démarrage du serveur HTTP simple sur le port $HTTP_PORT..."
python3 -m http.server $HTTP_PORT &
HTTP_SERVER_PID=$!

# Attendre que le serveur démarre
sleep 3

# Vérifier que le serveur fonctionne
if ! netstat -tuln | grep ":$HTTP_PORT " > /dev/null; then
    echo "❌ Échec du démarrage du serveur HTTP"
    kill $HTTP_SERVER_PID 2>/dev/null
    exit 1
fi

echo "✅ Serveur HTTP démarré (PID: $HTTP_SERVER_PID)"

# Étape 2: Commencer la capture TCP
echo "🎯 Début de la capture de trafic TCP (${CAPTURE_DURATION} secondes)..."
timeout $CAPTURE_DURATION tcpdump -i any -n -s 0 -w $CAPTURE_FILE port $HTTP_PORT &
TCPDUMP_PID=$!

# Attendre le démarrage de tcpdump
sleep 2

echo "📡 Génération de trafic HTTP..."
# Effectuer plusieurs requêtes HTTP pour générer du trafic TCP
for i in {1..5}; do
    echo "   Requête $i/5..."
    curl -s http://localhost:$HTTP_PORT/ > /dev/null 2>&1
    sleep 1
    
    # Requête pour un fichier inexistant (génère 404)
    curl -s http://localhost:$HTTP_PORT/nonexistent.html > /dev/null 2>&1
    sleep 1
done

echo "⏱️  Attente de la fin de la capture..."
wait $TCPDUMP_PID

# Arrêter le serveur HTTP
echo "🛑 Arrêt du serveur HTTP..."
kill $HTTP_SERVER_PID 2>/dev/null
wait $HTTP_SERVER_PID 2>/dev/null

# Vérifier le fichier de capture
if [ ! -f "$CAPTURE_FILE" ]; then
    echo "❌ Fichier de capture non généré, expérience échouée"
    exit 1
fi

PACKET_COUNT=$(tcpdump -r $CAPTURE_FILE 2>/dev/null | wc -l)
echo "✅ Capture terminée, $PACKET_COUNT paquets TCP capturés"

# Afficher un aperçu du contenu capturé
echo
echo "📊 Aperçu des paquets TCP:"
echo "----------------------------------------"
tcpdump -r $CAPTURE_FILE -n -c 10 2>/dev/null
echo "----------------------------------------"

echo
echo "🔬 Vous pouvez maintenant utiliser les commandes suivantes pour une analyse détaillée:"
echo
echo "1. Voir tous les paquets TCP:"
echo "   tcpdump -r $CAPTURE_FILE -n -v"
echo
echo "2. Filtrer les paquets de handshake:"
echo "   tcpdump -r $CAPTURE_FILE -n 'tcp[tcpflags] & tcp-syn != 0'"
echo
echo "3. Utiliser l'analyseur Python pour générer diagrammes et rapports:"
echo "   python3 tcp_analyzer.py $CAPTURE_FILE"
echo
echo "4. Analyser les connexions avec détails:"
echo "   tcpdump -r $CAPTURE_FILE -n -v -A"
echo

# Si l'analyseur Python existe, offrir l'option de l'exécuter
if [ -f "tcp_analyzer.py" ]; then
    echo "🤖 Voulez-vous exécuter immédiatement l'analyseur Python? (y/n)"
    read -r response
    if [ "$response" = "y" ] || [ "$response" = "Y" ]; then
        echo "🚀 Exécution de l'analyseur TCP..."
        python3 tcp_analyzer.py $CAPTURE_FILE
    fi
fi

echo
echo "✅ Expérience d'analyse TCP terminée!"
echo "Fichiers d'expérience:"
echo "   - Fichier de capture: $CAPTURE_FILE"
if [ -f "tcp_sequence_diagram.png" ]; then
    echo "   - Diagramme de séquence: tcp_sequence_diagram.png"
fi
if [ -f "tcp_analysis_report.md" ]; then
    echo "   - Rapport d'analyse: tcp_analysis_report.md"
fi

echo
echo "🔍 Points clés observés dans cette expérience:"
echo "   • Établissement de connexion TCP (3-way handshake)"
echo "   • Transfert de données HTTP avec contrôle de flux"
echo "   • Fermeture propre des connexions TCP"
echo "   • Comparaison avec UDP: TCP garantit la fiabilité" 