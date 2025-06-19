# Rapport d'analyse des connexions TCP

## Informations statistiques de base
- Nombre total de paquets TCP : 125

### Répartition par type de paquet
- ACK : 55 paquets
- FIN-ACK : 20 paquets
- PSH-ACK : 30 paquets
- SYN : 10 paquets
- SYN-ACK : 10 paquets

## Séquence détaillée des paquets

1. **SYN** : 127.0.0.1:56270 → 127.0.0.1:8080 (seq=4036737992)
2. **SYN-ACK** : 127.0.0.1:8080 → 127.0.0.1:56270 (seq=1372362379) (ack=4036737993)
3. **ACK** : 127.0.0.1:56270 → 127.0.0.1:8080 (ack=1)
4. **PSH-ACK** : 127.0.0.1:56270 → 127.0.0.1:8080 (seq=1) (ack=1)
5. **ACK** : 127.0.0.1:8080 → 127.0.0.1:56270 (ack=78)
6. **PSH-ACK** : 127.0.0.1:8080 → 127.0.0.1:56270 (seq=1) (ack=78)
7. **ACK** : 127.0.0.1:56270 → 127.0.0.1:8080 (ack=157)
8. **PSH-ACK** : 127.0.0.1:8080 → 127.0.0.1:56270 (seq=157) (ack=78)
9. **ACK** : 127.0.0.1:56270 → 127.0.0.1:8080 (ack=1189)
10. **FIN-ACK** : 127.0.0.1:8080 → 127.0.0.1:56270 (seq=1189) (ack=78)
11. **FIN-ACK** : 127.0.0.1:56270 → 127.0.0.1:8080 (seq=78) (ack=1189)
12. **ACK** : 127.0.0.1:8080 → 127.0.0.1:56270 (ack=79)
13. **ACK** : 127.0.0.1:56270 → 127.0.0.1:8080 (ack=1190)
14. **SYN** : 127.0.0.1:56272 → 127.0.0.1:8080 (seq=1599699973)
15. **SYN-ACK** : 127.0.0.1:8080 → 127.0.0.1:56272 (seq=3699570999) (ack=1599699974)
16. **ACK** : 127.0.0.1:56272 → 127.0.0.1:8080 (ack=1)
17. **PSH-ACK** : 127.0.0.1:56272 → 127.0.0.1:8080 (seq=1) (ack=1)
18. **ACK** : 127.0.0.1:8080 → 127.0.0.1:56272 (ack=94)
19. **PSH-ACK** : 127.0.0.1:8080 → 127.0.0.1:56272 (seq=1) (ack=94)
20. **ACK** : 127.0.0.1:56272 → 127.0.0.1:8080 (ack=186)
... et 105 paquets supplémentaires

## Analyse des caractéristiques du protocole TCP

Les résultats de capture montrent les caractéristiques suivantes du protocole TCP :

1. **Connexion fiable** : TCP établit une connexion avant le transfert de données
2. **Handshake à 3 voies** : SYN → SYN-ACK → ACK pour l'établissement
3. **Contrôle de flux** : Utilisation des numéros de séquence et d'acquittement
4. **Fermeture propre** : Processus de fermeture en 4 étapes avec FIN/ACK
5. **Acquittements** : Chaque segment de données est acquitté

## Phases de connexion observées

✅ **Établissement de connexion** : Handshake à 3 voies détecté
✅ **Transfert de données** : Échange de données HTTP observé
✅ **Fermeture de connexion** : Processus de fermeture détecté

## Conclusion

Cette analyse démontre le fonctionnement complet du protocole TCP, incluant l'établissement de connexion fiable, le transfert de données avec contrôle de flux, et la fermeture propre de la connexion. TCP garantit la livraison ordonnée et fiable des données, contrairement à UDP qui privilégie la rapidité.
