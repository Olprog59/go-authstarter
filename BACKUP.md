# Database Backup System

## Overview

GoAuthStarter inclut un système de backup automatique de la base de données SQLite intégré à l'application.

## Configuration

### Activer les Backups Automatiques

Dans votre fichier `config.yaml` :

```yaml
backup:
  enabled: true              # Active les backups automatiques
  interval: "24h"            # Intervalle entre les backups
  path: "./backups"          # Répertoire de stockage
  retention_days: 7          # Nombre de jours de rétention
```

### Paramètres

- **`enabled`** : Active/désactive le système de backup automatique
- **`interval`** : Fréquence des backups (ex: `1h`, `6h`, `12h`, `24h`)
- **`path`** : Chemin du répertoire où stocker les backups (créé automatiquement)
- **`retention_days`** : Nombre de jours de conservation (0 = infini)

## Format des Backups

Les fichiers de backup sont nommés selon le format :
```
<nom-base>.backup-YYYYMMDD-HHMMSS.db
```

Exemple :
```
data.sqlite.backup-20251202-143000.db
```

## Fonctionnement

### Création Automatique

Lorsque les backups sont activés :
1. Une goroutine démarre au lancement de l'application
2. Elle crée un backup selon l'intervalle configuré
3. Utilise la commande SQLite `VACUUM INTO` pour une copie cohérente
4. Nettoie automatiquement les anciens backups selon la rétention

### Rotation des Backups

Après chaque backup, le système :
- Vérifie l'âge de tous les backups existants
- Supprime ceux qui dépassent la période de rétention
- Log les suppressions avec l'âge du backup

### Logs

Le système génère les logs suivants :
```
Automatic database backup enabled (interval: 24h, retention: 7 days)
Database backup created: ./backups/data.sqlite.backup-20251202-143000.db
database backup completed successfully
Deleted old backup: data.sqlite.backup-20251125-143000.db (age: 7 days)
Cleaned up 1 old backup(s)
```

## Backup Manuel

Même sans activer les backups automatiques, vous pouvez créer un backup manuel avec SQLite :

```bash
# Via sqlite3 CLI
sqlite3 data.sqlite ".backup data.sqlite.backup-$(date +%Y%m%d-%H%M%S).db"

# Via SQL direct
sqlite3 data.sqlite "VACUUM INTO 'backup.db'"
```

## Restauration

Pour restaurer un backup :

1. **Arrêter l'application**
   ```bash
   # Arrêter le serveur
   pkill server
   ```

2. **Sauvegarder la base actuelle (optionnel)**
   ```bash
   mv data.sqlite data.sqlite.old
   ```

3. **Restaurer le backup**
   ```bash
   cp backups/data.sqlite.backup-20251202-143000.db data.sqlite
   ```

4. **Redémarrer l'application**
   ```bash
   go run cmd/server/main.go
   ```

## Sécurité

### Permissions

Les backups sont créés avec les permissions `0755` pour le répertoire et `0644` pour les fichiers.

### Limitations

- ❌ Les backups ne sont **pas chiffrés** par défaut
- ❌ Les backups ne sont **pas compressés** automatiquement
- ❌ Les backups ne sont **pas envoyés** vers un stockage distant

### Recommandations Production

Pour un environnement de production, considérez :

1. **Chiffrement** : Chiffrer les backups avec GPG
   ```bash
   gpg --encrypt --recipient your@email.com backup.db
   ```

2. **Compression** : Compresser les backups anciens
   ```bash
   gzip backups/*.backup-*.db
   ```

3. **Stockage Distant** : Synchroniser avec un service cloud
   ```bash
   # Exemple avec AWS S3
   aws s3 sync backups/ s3://your-bucket/backups/

   # Exemple avec rsync
   rsync -avz backups/ user@remote:/path/to/backups/
   ```

4. **Monitoring** : Surveiller les logs de backup via votre système de logging

## Métriques

Le système de backup expose une métrique Prometheus :
- `background_task_status{task="database_backup"}` : État de la tâche de backup

## Arrêt Gracieux

Lors de l'arrêt de l'application (`SIGTERM`, `SIGINT`) :
- La goroutine de backup se termine proprement
- Les backups en cours sont terminés avant l'arrêt
- Log : `backup goroutine stopped`

## Troubleshooting

### "cannot backup in-memory database"

Les bases de données en mémoire (`:memory:`) ne peuvent pas être sauvegardées. Utilisez une base de données sur disque.

### "failed to create backup directory"

Vérifiez les permissions du répertoire parent ou spécifiez un chemin absolu :
```yaml
backup:
  path: "/var/backups/go-authstarter"
```

### "backup execution failed: disk I/O error"

Vérifiez :
- Espace disque disponible
- Permissions d'écriture
- Intégrité de la base de données (exécutez `PRAGMA integrity_check;`)

## Exemples de Configuration

### Backup Fréquent (Développement)
```yaml
backup:
  enabled: true
  interval: "1h"      # Toutes les heures
  path: "./backups"
  retention_days: 1   # Garde 24 heures
```

### Backup Production
```yaml
backup:
  enabled: true
  interval: "6h"      # 4 fois par jour
  path: "/var/backups/app"
  retention_days: 30  # Garde 30 jours
```

### Backup Quotidien avec Longue Rétention
```yaml
backup:
  enabled: true
  interval: "24h"     # Une fois par jour
  path: "./backups"
  retention_days: 90  # Garde 3 mois
```
