# Modèle d'Authentification Go

Ce dépôt sert de modèle d'authentification robuste et sécurisé, construit avec Go, et conçu pour une intégration rapide dans de futures applications web. Il fournit une base solide pour la gestion des utilisateurs, garantissant que les pratiques de sécurité courantes sont mises en œuvre dès le départ.

### Fonctionnalités

- **Inscription et Connexion Utilisateur :** Flux sécurisés d'inscription et de connexion des utilisateurs.
- **Authentification basée sur JWT :** Utilise les JSON Web Tokens pour une authentification sans état.
- **Tokens de Rafraîchissement :** Implémente des tokens de rafraîchissement pour une sécurité et une gestion de session améliorées.
- **Vérification d'Email :** Inclut un processus de vérification des adresses email des utilisateurs.
- **Gestion Sécurisée des Mots de Passe :** Stocke les mots de passe de manière sécurisée en utilisant des méthodes de hachage standard de l'industrie.
- **Protection CSRF :** Protection contre les attaques Cross-Site Request Forgery pour les formulaires web et les appels API.
- **Limitation de Débit (Rate Limiting) :** Prévient les abus et les attaques par force brute sur les points d'accès d'authentification.
- **Base de Données :** Utilise SQLite pour sa simplicité et sa facilité de configuration.
- **Structure de Projet Organisée :** Suit les conventions courantes de structure de projet Go pour une meilleure maintenabilité.

### Technologies Utilisées

- **Go :** Le langage principal pour le backend.
- **SQLite :** Base de données SQL légère pour la persistance des données.
- **JWT (JSON Web Tokens) :** Pour l'authentification.
- **Viper :** Pour la gestion de la configuration.
- **Slog :** Journalisation structurée.

### Démarrage Rapide

Pour obtenir une copie locale fonctionnelle, suivez ces étapes simples :

1. **Cloner le dépôt :**

   ```bash
   git clone https://github.com/Olprog59/go-authentication-template.git
   cd go-authentication-template
   ```

2. **Installer les dépendances :**

   ```bash
   go mod tidy
   ```

3. **Configurer :** Copiez `config.yml.example` vers `config.yml` et ajustez les paramètres si nécessaire.
4. **Exécuter les migrations :**

   ```bash
   # (La commande de migration spécifique sera ici, par exemple, en utilisant l'outil 'migrate')
   ```

5. **Lancer l'application :**

   ```bash
   go run cmd/server/main.go
   ```

### Utilisation

Ce modèle est conçu pour être un point de départ. Vous pouvez :

- Dupliquer ce dépôt (fork) et l'adapter à vos besoins spécifiques de projet.
- Intégrer la logique d'authentification et les gestionnaires dans une application Go existante.
- L'utiliser comme référence pour implémenter des modèles d'authentification sécurisés.

---

[English Documentation](README.md)
