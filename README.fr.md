[English Documentation](README.md)

# GoAuthStarter

Ce dépôt sert de modèle d'authentification robuste et sécurisé, construit avec Go, et conçu pour une intégration rapide dans de futures applications web. Il fournit une base solide pour la gestion des utilisateurs, garantissant que les pratiques de sécurité courantes sont mises en œuvre dès le départ.

### Fonctionnalités

*   **Inscription et Connexion Utilisateur :** Flux sécurisés d'inscription et de connexion des utilisateurs.
*   **Authentification basée sur JWT :** Utilise les JSON Web Tokens pour une authentification sans état.
*   **Tokens de Rafraîchissement :** Implémente des tokens de rafraîchissement avec rotation pour une sécurité et une gestion de session améliorées.
*   **Vérification d'Email :** Inclut un processus de vérification des adresses email des utilisateurs.
*   **Gestion Sécurisée des Mots de Passe :** Stocke les mots de passe de manière sécurisée avec bcrypt (coût 12).
*   **Protection CSRF :** Protection contre les attaques Cross-Site Request Forgery pour les formulaires web et les appels API.
*   **Limitation de Débit Multi-niveaux :** Limitation de débit globale, stricte et par utilisateur pour prévenir les abus et les attaques par force brute.
*   **Verrouillage de Compte :** Verrouillage automatique après tentatives de connexion échouées (5 tentatives = 15 minutes de verrouillage).
*   **Liaison de Tokens :** Les tokens de rafraîchissement sont liés à l'IP et au User-Agent du client pour une sécurité renforcée.
*   **Contrôle d'Accès Basé sur les Rôles (RBAC) :** Système de rôles hiérarchique (utilisateur, modérateur, admin) avec autorisation basée sur JWT.
*   **Métriques Prometheus :** Observabilité complète avec métriques d'authentification, HTTP, sécurité et santé système.
*   **Points de Contrôle Santé :** Endpoints de santé et disponibilité compatibles Kubernetes pour la surveillance.
*   **Base de Données :** Utilise SQLite en mode WAL pour une concurrence et des performances optimales.
*   **Architecture Hexagonale :** Structure de projet suivant l'architecture hexagonale pour une meilleure maintenabilité et testabilité.

### Technologies Utilisées

*   **Go :** Le langage principal pour le backend.
*   **SQLite :** Base de données SQL légère pour la persistance des données.
*   **JWT (JSON Web Tokens) :** Pour l'authentification.
*   **Viper :** Pour la gestion de la configuration.
*   **Slog :** Journalisation structurée.

### Démarrage Rapide

Pour obtenir une copie locale fonctionnelle, suivez ces étapes simples :

1.  **Cloner le dépôt :**
    ```bash
    git clone https://github.com/Olprog59/go-authstarter.git
    cd go-authstarter
    ```
2.  **Installer les dépendances :**
    ```bash
    go mod tidy
    ```
3.  **Configurer :** Copiez `config.example.yaml` vers `config.yaml` et ajustez les paramètres si nécessaire.
4.  **Exécuter les migrations :**
    ```bash
    # (La commande de migration spécifique sera ici, par exemple, en utilisant l'outil 'migrate')
    ```
5.  **Lancer l'application :**
    ```bash
    go run cmd/server/main.go
    ```

### Utilisation

Ce modèle est conçu pour être un point de départ. Vous pouvez :

*   Dupliquer ce dépôt (fork) et l'adapter à vos besoins spécifiques de projet.
*   Intégrer la logique d'authentification et les gestionnaires dans une application Go existante.
*   L'utiliser comme référence pour implémenter des modèles d'authentification sécurisés.

### Sauvegardes de Base de Données

GoAuthStarter inclut une fonctionnalité de sauvegarde automatique de la base de données :

*   **Sauvegardes Automatiques :** Sauvegardes planifiées à intervalles configurables
*   **Politique de Rétention :** Nettoyage automatique des anciennes sauvegardes selon les jours de rétention
*   **Support SQLite :** Optimisé pour les bases de données SQLite avec mode WAL
*   **Sans Interruption :** Les sauvegardes sont effectuées sans interrompre l'application

**Configuration :**
```yaml
backup:
  enabled: true              # Activer les sauvegardes automatiques
  interval: "24h"            # Sauvegarder toutes les 24 heures
  path: "./backups"          # Répertoire de stockage
  retention_days: 7          # Conserver les sauvegardes pendant 7 jours
```

### Surveillance & Observabilité

GoAuthStarter inclut une stack d'observabilité complète pour la production :

**Métriques (Prometheus) :**
*   **Métriques d'authentification :** Tentatives de connexion, inscriptions, vérifications d'email, rafraîchissements de tokens
*   **Métriques HTTP :** Taux de requêtes, temps de réponse, codes de statut, connexions actives
*   **Métriques de sécurité :** Limitations de débit déclenchées, échecs CSRF, échecs de liaison de tokens, verrouillages de comptes
*   **Métriques système :** Connexions à la base de données, statut des tâches en arrière-plan
*   Accès : `GET /metrics`

**Logs (Grafana Loki) :**
*   **Logging centralisé :** Logs JSON structurés avec contexte complet
*   **Recherche temps réel :** Requêtes par utilisateur, IP, endpoint, erreur, etc.
*   **Agrégation de logs :** Suivi des erreurs, activité utilisateur, événements système
*   **Intégration Grafana :** Interface unifiée pour logs + métriques

**Démarrage Rapide :**
```bash
# Démarrer la stack de monitoring (Prometheus, Loki, Grafana)
docker-compose up -d

# Accéder à Grafana
open http://localhost:3000  # admin/admin
```

### Points d'Accès API

**Endpoints Publics :**
*   `POST /api/register` - Inscription utilisateur
*   `POST /api/login` - Authentification utilisateur
*   `GET /verify?token=...` - Vérification d'email
*   `POST /api/resend-verification` - Renvoyer l'email de vérification
*   `POST /api/request-password-reset` - Demander un email de réinitialisation de mot de passe
*   `POST /api/reset-password` - Réinitialiser le mot de passe avec un token

**Endpoints Authentifiés :**
*   `POST /api/refresh` - Rafraîchir le token d'accès (nécessite auth + CSRF)
*   `GET /api/me` - Obtenir l'utilisateur actuel (nécessite auth + CSRF)
*   `POST /api/logout` - Déconnexion et invalidation du refresh token (nécessite auth + CSRF)
*   `GET /` - Page d'accueil (nécessite auth)

**Endpoints Modérateur :**
*   `GET /api/moderator/stats` - Obtenir les statistiques utilisateur (nécessite rôle modérateur ou admin)

**Endpoints Admin :**
*   `GET /api/admin/users` - Lister tous les utilisateurs avec leurs rôles
*   `DELETE /api/admin/users/{id}` - Supprimer un utilisateur
*   `PATCH /api/admin/users/{id}/role` - Modifier le rôle d'un utilisateur

**Surveillance :**
*   `GET /health` - Contrôle de santé (liveness)
*   `GET /readiness` - Contrôle de disponibilité (connectivité base de données)
*   `GET /metrics` - Métriques Prometheus (nécessite authentification admin)
