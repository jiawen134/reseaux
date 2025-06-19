# Rapport d'analyse des paquets UDP

## Informations statistiques de base
- Nombre total de paquets : 16
- Paquets de requête DNS : 8
- Paquets de réponse DNS : 8

## Détails des paquets

1. **Requête DNS** : 172.23.29.19:45446 → 8.8.8.8:53
2. **Réponse DNS** : 8.8.8.8:53 → 172.23.29.19:45446
3. **Requête DNS** : 172.23.29.19:48816 → 8.8.8.8:53
4. **Réponse DNS** : 8.8.8.8:53 → 172.23.29.19:48816
5. **Requête DNS** : 172.23.29.19:60305 → 8.8.8.8:53
6. **Réponse DNS** : 8.8.8.8:53 → 172.23.29.19:60305
7. **Requête DNS** : 172.23.29.19:45669 → 8.8.8.8:53
8. **Réponse DNS** : 8.8.8.8:53 → 172.23.29.19:45669
9. **Requête DNS** : 172.23.29.19:54950 → 8.8.8.8:53
10. **Réponse DNS** : 8.8.8.8:53 → 172.23.29.19:54950
11. **Requête DNS** : 172.23.29.19:43700 → 8.8.8.8:53
12. **Réponse DNS** : 8.8.8.8:53 → 172.23.29.19:43700
13. **Requête DNS** : 172.23.29.19:35261 → 8.8.8.8:53
14. **Réponse DNS** : 8.8.8.8:53 → 172.23.29.19:35261
15. **Requête DNS** : 172.23.29.19:38251 → 8.8.8.8:53
16. **Réponse DNS** : 8.8.8.8:53 → 172.23.29.19:38251

## Analyse des caractéristiques du protocole UDP

Les résultats de capture montrent les caractéristiques suivantes du protocole UDP :

1. **Sans connexion** : UDP n'a pas besoin d'établir une connexion, envoie directement les données
2. **Simplicité** : L'en-tête UDP ne fait que 8 octets, beaucoup plus simple que TCP
3. **Rapidité** : Les requêtes DNS sont rapides, adaptées à UDP
4. **Non-fiabilité** : UDP ne garantit pas la transmission fiable des paquets

## Conclusion

Grâce à cette expérience, nous avons analysé avec succès l'application du protocole UDP dans les requêtes DNS, et observé les caractéristiques simples et rapides du protocole UDP.
