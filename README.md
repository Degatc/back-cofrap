# README

## Présentation

Ce backend OpenFaaS est un PoC (Proof of Concept) pour gérer la création et l’authentification d’utilisateurs avec mot de passe sécurisé et authentification 2FA (TOTP), déployé sur Kubernetes avec OpenFaaS pour l'entreprise COFRAP.

## Prérequis

- Un cluster Kubernetes (K3s)
- Helm installé
- OpenFaaS déployé
- `faas-cli` installé
- `kubectl` configuré pour votre cluster

## Fonctionnement

1. **Kubernetes** (K3s) :

   - Fournit l’orchestration des conteneurs.
   - Nos fonctions OpenFaaS et la base PostgreSQL s’y déploient en tant que pods et services.

2. **Helm** :

   - Gère les **Charts** (paquets Kubernetes) pour installer des applications
   - Charts utilisés:
     - `openfaas/faa-netes` pour OpenFaaS
     - `bitnami/postgresql` pour PostgreSQL

3. **OpenFaaS** :

   - Expose une **API Gateway** pour  les fonctions serverless.
   - Les fonctions Python (`generate-password`, `generate-2fa`, `authenticate-user`) sont packagées et déployées via `faas-cli`.

4. **faas-cli** :

   - Outil en ligne de commande pour builder, publier et déployer les fonctions sur OpenFaaS.

5. **Docker Hub** :

   - `faas-cli build` crée localement des images Docker pour chaque fonction.

   - `faas-cli push` publie ces images sur votre compte Docker Hub (ou un autre registre OCI).

   - `faas-cli deploy` déploie ensuite la fonction dans OpenFaaS, Kubernetes  récupèrent ensuite automatiquement ces images depuis le registre pour exécuter les fonctions sur le cluster

6. **kubectl** :

   - Permet de gérer le cluster (création de namespace, visualisation des pods/services, port-forwarding, logs, secrets).

7. **PostgreSQL** :

   - Déployé via Helm (chart Bitnami) dans le même cluster.
   - Stocke la table `users` :
     - `username`, `password` (chiffré), `mfa` (secret TOTP chiffré), `gendate`, `expired`.
   - Accessible en interne via le service Kubernetes `cofrap-db-postgresql.default.svc.cluster.local:5432`.

8. **Secrets Kubernetes** :

   - `fernet-key` et `db-url` montés dans les containers des fonctions.

## Fonctions disponibles :

- `generate-password` : génère un mot de passe sécurisé (24 char.), le chiffre en base PostgreSQL et renvoie un QR-Code pour le mot de passe
- `generate-2fa` : génère un secret TOTP, le chiffre et stocke dans PostgreSQL, renvoie un QR-Code pour l’ajout à une app Authenticator ( ex: Google Authentificator )
- `authenticate-user` : authentifie l’utilisateur via mot de passe + code TOTP, gère l’expiration (6 mois)

**Worflow** :

   1. L’utilisateur appelle \`generate-password\` → mot de passe chiffré stocké + QR-Code retour.
   2. L’utilisateur appelle \`generate-2fa\` → secret TOTP chiffré stocké + QR-Code retour.
   3. L’utilisateur scanne le QR-Code dans son Authenticator, obtenant un code à 6 chifrres dynamiques.
   4. L’utilisateur appelle \`authenticate-user\` avec `username`, `password`, `code` → vérification mot de passe & TOTP, ainsi que l’expiration des identifiants.

## Utilisation

1. **Génération du mot de passe** :
   ```bash
   curl -X POST -H "Content-Type: application/json" \
        -d '{"username":"test.epsi"}' \
        http://<gateway>/function/generate-password
   ```
2. **Génération du secret 2FA** :
   ```bash
   curl -X POST -H "Content-Type: application/json" \
        -d '{"username":"test.epsi"}' \
        http://<gateway>/function/generate-2fa
   ```
3. **Authentification** :
   ```bash
   curl -X POST -H "Content-Type: application/json" \
        -d '{"username":"test.epsi", "password":"testepsi_password", "code":"testepsi_code"}' \
        http://<gateway>/function/authenticate-user
   ```


