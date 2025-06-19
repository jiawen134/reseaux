#!/usr/bin/env python3
"""
Analyseur de paquets UDP
Utilisé pour analyser la communication UDP des requêtes DNS et générer des diagrammes de séquence
"""

import subprocess
import re
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
import pandas as pd
import argparse
import sys

# Configuration des polices pour le français
plt.rcParams['font.sans-serif'] = ['DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

class UDPAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        
    def parse_pcap(self):
        """Analyser le fichier pcap et extraire les informations des paquets UDP"""
        try:
            # Utiliser tcpdump pour analyser le fichier pcap
            cmd = ['tcpdump', '-r', self.pcap_file, '-n', '-t', '-v']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Erreur : impossible de lire le fichier pcap {self.pcap_file}")
                print(f"Message d'erreur : {result.stderr}")
                return False
                
            lines = result.stdout.strip().split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                    
                packet_info = self.parse_packet_line(line)
                if packet_info:
                    self.packets.append(packet_info)
                    
            print(f"Analyse réussie de {len(self.packets)} paquets")
            return True
            
        except Exception as e:
            print(f"Erreur lors de l'analyse du fichier pcap : {e}")
            return False
    
    def parse_packet_line(self, line):
        """Analyser une ligne de sortie tcpdump"""
        # Expression régulière pour correspondre aux adresses IP et ports
        pattern = r'(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+)'
        match = re.search(pattern, line)
        
        if match:
            src_ip = match.group(1)
            src_port = int(match.group(2))
            dst_ip = match.group(3)
            dst_port = int(match.group(4))
            
            # Déterminer s'il s'agit de trafic DNS (port 53)
            if src_port == 53 or dst_port == 53:
                packet_type = "Requête DNS" if dst_port == 53 else "Réponse DNS"
                
                return {
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'type': packet_type,
                    'raw_line': line
                }
        
        return None
    
    def analyze_packets(self):
        """Analyser les paquets et générer des statistiques"""
        if not self.packets:
            print("Aucun paquet valide trouvé")
            return
            
        print("\n=== Résultats de l'analyse des paquets UDP ===")
        print(f"Nombre total de paquets : {len(self.packets)}")
        
        queries = [p for p in self.packets if p['type'] == 'Requête DNS']
        responses = [p for p in self.packets if p['type'] == 'Réponse DNS']
        
        print(f"Paquets de requête DNS : {len(queries)}")
        print(f"Paquets de réponse DNS : {len(responses)}")
        
        print("\n=== Analyse des flux de communication ===")
        for i, packet in enumerate(self.packets[:10]):  # Afficher les 10 premiers paquets
            direction = "→"
            print(f"{i+1}. {packet['src_ip']}:{packet['src_port']} {direction} "
                  f"{packet['dst_ip']}:{packet['dst_port']} ({packet['type']})")
        
        if len(self.packets) > 10:
            print(f"... {len(self.packets) - 10} paquets supplémentaires")
    
    def create_sequence_diagram(self, output_file='udp_sequence_diagram.png'):
        """Créer un diagramme de séquence"""
        if not self.packets:
            print("Aucun paquet disponible pour générer le diagramme de séquence")
            return
            
        # Créer le graphique
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Obtenir les adresses IP uniques comme participants
        participants = set()
        for packet in self.packets:
            participants.add(packet['src_ip'])
            participants.add(packet['dst_ip'])
        
        participants = list(participants)
        participants.sort()
        
        # Assigner une position Y à chaque participant
        y_positions = {ip: i for i, ip in enumerate(participants)}
        
        # Dessiner les lignes verticales des participants
        for i, ip in enumerate(participants):
            ax.axvline(x=i, color='lightgray', linestyle='--', alpha=0.7)
            ax.text(i, len(self.packets) + 1, ip, rotation=45, ha='right', va='bottom')
        
        # Dessiner les flèches de messages
        for i, packet in enumerate(self.packets):
            src_x = y_positions[packet['src_ip']]
            dst_x = y_positions[packet['dst_ip']]
            y = len(self.packets) - i
            
            # Dessiner la flèche
            ax.annotate('', xy=(dst_x, y), xytext=(src_x, y),
                       arrowprops=dict(arrowstyle='->', color='blue', lw=1.5))
            
            # Ajouter l'étiquette du message
            mid_x = (src_x + dst_x) / 2
            label = f"{packet['type']} (:{packet['dst_port']})"
            ax.text(mid_x, y + 0.1, label, ha='center', va='bottom', fontsize=8)
        
        # Définir les propriétés du graphique
        ax.set_ylim(-1, len(self.packets) + 2)
        ax.set_xlim(-0.5, len(participants) - 0.5)
        ax.set_xlabel('Participants réseau')
        ax.set_ylabel('Séquence temporelle')
        ax.set_title('Diagramme de séquence des requêtes DNS UDP')
        
        # Masquer les axes non nécessaires
        ax.set_xticks([])
        ax.set_yticks([])
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"Diagramme de séquence sauvegardé dans : {output_file}")
        
        return output_file
    
    def generate_report(self, output_file='udp_analysis_report.md'):
        """Générer un rapport d'analyse"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# Rapport d'analyse des paquets UDP\n\n")
            f.write(f"## Informations statistiques de base\n")
            f.write(f"- Nombre total de paquets : {len(self.packets)}\n")
            
            queries = [p for p in self.packets if p['type'] == 'Requête DNS']
            responses = [p for p in self.packets if p['type'] == 'Réponse DNS']
            
            f.write(f"- Paquets de requête DNS : {len(queries)}\n")
            f.write(f"- Paquets de réponse DNS : {len(responses)}\n\n")
            
            f.write("## Détails des paquets\n\n")
            for i, packet in enumerate(self.packets):
                f.write(f"{i+1}. **{packet['type']}** : ")
                f.write(f"{packet['src_ip']}:{packet['src_port']} → ")
                f.write(f"{packet['dst_ip']}:{packet['dst_port']}\n")
            
            f.write("\n## Analyse des caractéristiques du protocole UDP\n\n")
            f.write("Les résultats de capture montrent les caractéristiques suivantes du protocole UDP :\n\n")
            f.write("1. **Sans connexion** : UDP n'a pas besoin d'établir une connexion, envoie directement les données\n")
            f.write("2. **Simplicité** : L'en-tête UDP ne fait que 8 octets, beaucoup plus simple que TCP\n")
            f.write("3. **Rapidité** : Les requêtes DNS sont rapides, adaptées à UDP\n")
            f.write("4. **Non-fiabilité** : UDP ne garantit pas la transmission fiable des paquets\n\n")
            
            f.write("## Conclusion\n\n")
            f.write("Grâce à cette expérience, nous avons analysé avec succès l'application du protocole UDP dans les requêtes DNS, ")
            f.write("et observé les caractéristiques simples et rapides du protocole UDP.\n")
        
        print(f"Rapport d'analyse sauvegardé dans : {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Analyseur de paquets UDP')
    parser.add_argument('pcap_file', help='Chemin du fichier pcap')
    parser.add_argument('--output-dir', default='.', help='Répertoire de sortie')
    
    args = parser.parse_args()
    
    # Créer une instance de l'analyseur
    analyzer = UDPAnalyzer(args.pcap_file)
    
    # Analyser le fichier pcap
    if not analyzer.parse_pcap():
        sys.exit(1)
    
    # Analyser les paquets
    analyzer.analyze_packets()
    
    # Générer le diagramme de séquence
    diagram_file = f"{args.output_dir}/udp_sequence_diagram.png"
    analyzer.create_sequence_diagram(diagram_file)
    
    # Générer le rapport
    report_file = f"{args.output_dir}/udp_analysis_report.md"
    analyzer.generate_report(report_file)
    
    print(f"\nAnalyse terminée ! Fichiers de sortie :")
    print(f"- Diagramme de séquence : {diagram_file}")
    print(f"- Rapport d'analyse : {report_file}")

if __name__ == '__main__':
    main() 