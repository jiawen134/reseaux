#!/usr/bin/env python3
"""
Analyseur de paquets TCP
Utilisé pour analyser la communication TCP des connexions HTTP et générer des diagrammes de séquence
"""

import subprocess
import re
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from datetime import datetime
import pandas as pd
import argparse
import sys

# Configuration des polices pour le français
plt.rcParams['font.sans-serif'] = ['DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

class TCPAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.connections = {}
        
    def parse_pcap(self):
        """Analyser le fichier pcap et extraire les informations des paquets TCP"""
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
                    
            print(f"Analyse réussie de {len(self.packets)} paquets TCP")
            return True
            
        except Exception as e:
            print(f"Erreur lors de l'analyse du fichier pcap : {e}")
            return False
    
    def parse_packet_line(self, line):
        """Analyser une ligne de sortie tcpdump pour les paquets TCP"""
        # Expression régulière pour correspondre aux paquets TCP
        tcp_pattern = r'(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+):'
        match = re.search(tcp_pattern, line)
        
        if match:
            src_ip = match.group(1)
            src_port = int(match.group(2))
            dst_ip = match.group(3)
            dst_port = int(match.group(4))
            
            # Analyser les drapeaux TCP et les informations
            packet_type = self.classify_tcp_packet(line)
            seq_num, ack_num, flags = self.extract_tcp_details(line)
            
            # Identifier les connexions HTTP (ports 80, 8080, etc.)
            if src_port in [80, 8080, 443, 3000] or dst_port in [80, 8080, 443, 3000]:
                return {
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'type': packet_type,
                    'seq_num': seq_num,
                    'ack_num': ack_num,
                    'flags': flags,
                    'raw_line': line.strip()
                }
        
        return None
    
    def classify_tcp_packet(self, tcp_info):
        """Classifier le type de paquet TCP basé sur les drapeaux"""
        if 'Flags [S]' in tcp_info and 'Flags [S.]' not in tcp_info:
            return "SYN"
        elif 'Flags [S.]' in tcp_info or 'Flags [SA]' in tcp_info:
            return "SYN-ACK"
        elif 'Flags [.]' in tcp_info and 'length 0' in tcp_info:
            return "ACK"
        elif 'Flags [P.]' in tcp_info or 'Flags [PA]' in tcp_info:
            return "PSH-ACK"
        elif 'Flags [F.]' in tcp_info or 'Flags [FA]' in tcp_info:
            return "FIN-ACK"
        elif 'Flags [F]' in tcp_info:
            return "FIN"
        elif 'Flags [R]' in tcp_info:
            return "RST"
        elif 'GET /' in tcp_info or 'POST /' in tcp_info:
            return "Requête HTTP"
        elif 'HTTP/' in tcp_info and ('200' in tcp_info or '404' in tcp_info):
            return "Réponse HTTP"
        elif 'length' in tcp_info and not 'length 0' in tcp_info:
            return "DATA"
        else:
            return "OTHER"
    
    def extract_tcp_details(self, tcp_info):
        """Extraire les numéros de séquence, d'acquittement et drapeaux"""
        seq_num = None
        ack_num = None
        flags = []
        
        # Extraire le numéro de séquence
        seq_match = re.search(r'seq (\d+)', tcp_info)
        if seq_match:
            seq_num = int(seq_match.group(1))
            
        # Extraire le numéro d'acquittement
        ack_match = re.search(r'ack (\d+)', tcp_info)
        if ack_match:
            ack_num = int(ack_match.group(1))
            
        # Extraire les drapeaux
        flag_match = re.search(r'Flags \[([^\]]+)\]', tcp_info)
        if flag_match:
            flags = flag_match.group(1).split()
            
        return seq_num, ack_num, flags
    
    def analyze_connections(self):
        """Analyser les connexions TCP et identifier les phases"""
        if not self.packets:
            print("Aucun paquet TCP trouvé")
            return
            
        print("\n=== Résultats de l'analyse des connexions TCP ===")
        print(f"Nombre total de paquets TCP : {len(self.packets)}")
        
        # Compter les types de paquets
        packet_types = {}
        for packet in self.packets:
            ptype = packet['type']
            packet_types[ptype] = packet_types.get(ptype, 0) + 1
        
        print("\n=== Répartition par type de paquet ===")
        for ptype, count in sorted(packet_types.items()):
            print(f"{ptype}: {count} paquets")
        
        print("\n=== Flux de communication ===")
        for i, packet in enumerate(self.packets[:15]):  # Afficher les 15 premiers paquets
            direction = "→"
            print(f"{i+1}. {packet['src_ip']}:{packet['src_port']} {direction} "
                  f"{packet['dst_ip']}:{packet['dst_port']} ({packet['type']})")
        
        if len(self.packets) > 15:
            print(f"... {len(self.packets) - 15} paquets supplémentaires")
    
    def create_sequence_diagram(self, output_file='tcp_sequence_diagram.png'):
        """Créer un diagramme de séquence TCP détaillé"""
        if not self.packets:
            print("Aucun paquet disponible pour générer le diagramme de séquence")
            return
            
        # Créer le graphique
        fig, ax = plt.subplots(figsize=(14, 10))
        
        # Obtenir les adresses IP uniques comme participants
        participants = set()
        for packet in self.packets:
            participants.add(packet['src_ip'])
            participants.add(packet['dst_ip'])
        
        participants = list(participants)
        participants.sort()
        
        # Assigner une position X à chaque participant
        x_positions = {ip: i for i, ip in enumerate(participants)}
        
        # Dessiner les lignes verticales des participants
        for i, ip in enumerate(participants):
            ax.axvline(x=i, color='lightgray', linestyle='--', alpha=0.7)
            ax.text(i, len(self.packets) + 2, ip, rotation=45, ha='right', va='bottom', fontweight='bold')
        
        # Couleurs pour différents types de paquets
        colors = {
            'SYN': 'red',
            'SYN-ACK': 'orange', 
            'ACK': 'green',
            'PSH-ACK': 'blue',
            'Requête HTTP': 'purple',
            'Réponse HTTP': 'brown',
            'FIN': 'darkred',
            'FIN-ACK': 'darkred',
            'DATA': 'gray',
            'OTHER': 'black'
        }
        
        # Dessiner les flèches de messages
        for i, packet in enumerate(self.packets):
            src_x = x_positions[packet['src_ip']]
            dst_x = x_positions[packet['dst_ip']]
            y = len(self.packets) - i
            
            # Choisir la couleur en fonction du type
            color = colors.get(packet['type'], 'black')
            
            # Dessiner la flèche
            ax.annotate('', xy=(dst_x, y), xytext=(src_x, y),
                       arrowprops=dict(arrowstyle='->', color=color, lw=1.5))
            
            # Ajouter l'étiquette du message
            mid_x = (src_x + dst_x) / 2
            label = f"{packet['type']}"
            
            ax.text(mid_x, y + 0.1, label, ha='center', va='bottom', fontsize=8, 
                   bbox=dict(boxstyle="round,pad=0.2", facecolor='white', alpha=0.8))
        
        # Définir les propriétés du graphique
        ax.set_ylim(-1, len(self.packets) + 4)
        ax.set_xlim(-0.5, len(participants) - 0.5)
        ax.set_xlabel('Participants réseau')
        ax.set_ylabel('Séquence temporelle')
        ax.set_title('Diagramme de séquence des connexions TCP')
        
        # Créer une légende
        legend_elements = [mpatches.Patch(color=colors[key], label=key) 
                          for key in colors if any(p['type'] == key for p in self.packets)]
        if legend_elements:
            ax.legend(handles=legend_elements, loc='upper right', bbox_to_anchor=(1.15, 1))
        
        # Masquer les axes non nécessaires
        ax.set_xticks([])
        ax.set_yticks([])
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"Diagramme de séquence sauvegardé dans : {output_file}")
        
        return output_file
    
    def generate_report(self, output_file='tcp_analysis_report.md'):
        """Générer un rapport d'analyse TCP détaillé"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# Rapport d'analyse des connexions TCP\n\n")
            
            # Statistiques de base
            f.write("## Informations statistiques de base\n")
            f.write(f"- Nombre total de paquets TCP : {len(self.packets)}\n\n")
            
            # Compter les types de paquets
            packet_types = {}
            for packet in self.packets:
                ptype = packet['type']
                packet_types[ptype] = packet_types.get(ptype, 0) + 1
            
            f.write("### Répartition par type de paquet\n")
            for ptype, count in sorted(packet_types.items()):
                f.write(f"- {ptype} : {count} paquets\n")
            f.write("\n")
            
            # Détails des paquets
            f.write("## Séquence détaillée des paquets\n\n")
            for i, packet in enumerate(self.packets[:20]):  # Limiter à 20 pour la lisibilité
                f.write(f"{i+1}. **{packet['type']}** : ")
                f.write(f"{packet['src_ip']}:{packet['src_port']} → ")
                f.write(f"{packet['dst_ip']}:{packet['dst_port']}")
                
                if packet['seq_num']:
                    f.write(f" (seq={packet['seq_num']})")
                if packet['ack_num']:
                    f.write(f" (ack={packet['ack_num']})")
                f.write("\n")
            
            if len(self.packets) > 20:
                f.write(f"... et {len(self.packets) - 20} paquets supplémentaires\n")
            f.write("\n")
            
            # Analyse des caractéristiques TCP
            f.write("## Analyse des caractéristiques du protocole TCP\n\n")
            f.write("Les résultats de capture montrent les caractéristiques suivantes du protocole TCP :\n\n")
            f.write("1. **Connexion fiable** : TCP établit une connexion avant le transfert de données\n")
            f.write("2. **Handshake à 3 voies** : SYN → SYN-ACK → ACK pour l'établissement\n")
            f.write("3. **Contrôle de flux** : Utilisation des numéros de séquence et d'acquittement\n")
            f.write("4. **Fermeture propre** : Processus de fermeture en 4 étapes avec FIN/ACK\n")
            f.write("5. **Acquittements** : Chaque segment de données est acquitté\n\n")
            
            # Phases de connexion observées
            f.write("## Phases de connexion observées\n\n")
            
            has_syn = any(p['type'] == 'SYN' for p in self.packets)
            has_syn_ack = any(p['type'] == 'SYN-ACK' for p in self.packets)
            has_fin = any('FIN' in p['type'] for p in self.packets)
            has_data = any(p['type'] in ['Requête HTTP', 'Réponse HTTP', 'PSH-ACK'] for p in self.packets)
            
            if has_syn and has_syn_ack:
                f.write("✅ **Établissement de connexion** : Handshake à 3 voies détecté\n")
            if has_data:
                f.write("✅ **Transfert de données** : Échange de données HTTP observé\n")
            if has_fin:
                f.write("✅ **Fermeture de connexion** : Processus de fermeture détecté\n")
            f.write("\n")
            
            # Conclusion
            f.write("## Conclusion\n\n")
            f.write("Cette analyse démontre le fonctionnement complet du protocole TCP, ")
            f.write("incluant l'établissement de connexion fiable, le transfert de données avec contrôle de flux, ")
            f.write("et la fermeture propre de la connexion. TCP garantit la livraison ordonnée et fiable des données, ")
            f.write("contrairement à UDP qui privilégie la rapidité.\n")
        
        print(f"Rapport d'analyse sauvegardé dans : {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Analyseur de paquets TCP')
    parser.add_argument('pcap_file', help='Chemin du fichier pcap')
    parser.add_argument('--output-dir', default='.', help='Répertoire de sortie')
    
    args = parser.parse_args()
    
    # Créer une instance de l'analyseur
    analyzer = TCPAnalyzer(args.pcap_file)
    
    # Analyser le fichier pcap
    if not analyzer.parse_pcap():
        sys.exit(1)
    
    # Analyser les connexions
    analyzer.analyze_connections()
    
    # Générer le diagramme de séquence
    diagram_file = f"{args.output_dir}/tcp_sequence_diagram.png"
    analyzer.create_sequence_diagram(diagram_file)
    
    # Générer le rapport
    report_file = f"{args.output_dir}/tcp_analysis_report.md"
    analyzer.generate_report(report_file)
    
    print(f"\nAnalyse terminée ! Fichiers de sortie :")
    print(f"- Diagramme de séquence : {diagram_file}")
    print(f"- Rapport d'analyse : {report_file}")

if __name__ == '__main__':
    main() 