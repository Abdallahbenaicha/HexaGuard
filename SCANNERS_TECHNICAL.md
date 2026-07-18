# HexaGuard — Manuel Technique des Scanners
**Version 3.0 — Juin 2026 — Basé sur le code source réel**

> Ce document couvre les **11 scanners** de HexaGuard avec leurs capacités exactes,
> leurs limites réelles, et des améliorations réalistes tenant compte de l'environnement
> PythonAnywhere (pas de root, pas d'outils système arbitraires).

---

## Table de Synthèse Rapide

| # | Scanner | Fichier Backend | Moteurs | Dépendances Système |
|---|---------|----------------|---------|---------------------|
| 1 | Web Application | `web_scanner.py` | `requests` natif | Aucune |
| 2 | DAST Multi-moteurs | `dast_scanner.py` | ZAP · Nuclei · Nikto | ZAP, Nuclei, Nikto (optionnels) |
| 3 | SAST Multi-langages | `sast_scanner.py` | Bandit · Semgrep · Gitleaks · Regex | Bandit, Semgrep, Gitleaks (pip/bin) |
| 4 | Réseau & Ports | `netscan_scanner.py` | Nmap | **nmap** (non disponible PythonAnywhere) |
| 5 | SSL / TLS | `ssl_scanner.py` | `ssl` Python natif + ASN.1 | Aucune |
| 6 | Dépendances | `dep_scanner.py` | OSV.dev API + Regex | Aucune |
| 7 | Config Serveur (interne) | `server_int.py` | Regex sur fichiers config | Accès SSH/fichiers requis |
| 8 | Serveur (externe) | `server_ext.py` | `requests` black-box | Aucune |
| 9 | Docker Security | `docker_scanner.py` | Analyse texte pure Python | Aucune |
| 10 | DNS & Email | `dns_scanner.py` | DNS-over-HTTPS (Cloudflare) | Aucune |
| 11 | WordPress | `wordpress_scanner.py` | `requests` HTTP probing | Aucune |

---

## 1. Scanner Web Application (`web_scanner.py`)

### 1.1 Capacités réelles
Audit passif rapide de la couche HTTP — une seule requête GET sur la page racine.

| Fonctionnalité | Détail |
|----------------|--------|
| Headers sécurité | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| Empreinte serveur | Header `Server`, `X-Powered-By` |
| Redirection HTTPS | Vérifie si HTTP → HTTPS (301/302 sécurisé) |
| Cookies | Flags `Secure`, `HttpOnly`, `SameSite` |

### 1.2 Limites réelles
| Limite | Explication |
|--------|-------------|
| Pas de crawling | Vérifie seulement la page racine — 99% du site ignoré |
| Aucun test d'injection | Zéro payload envoyé — ne détecte pas SQLi/XSS réels |
| Pas de CORS check | Ne teste pas les origines CORS permissives |

### 1.3 Améliorations réalistes (PythonAnywhere-compatible)
| Amélioration | Implémentation | Priorité |
|--------------|---------------|----------|
| Crawler léger | `BeautifulSoup` (déjà installable via pip) — extrait 10-20 sous-pages | **Haute** |
| CORS check | Requête avec `Origin: https://evil.com` — détecte `Access-Control-Allow-Origin: *` | **Haute** |
| Robots.txt & sitemap | Révèle la structure interne (chemins sensibles exposés) | Moyenne |
| Cookie audit | Analyser tous les cookies de toutes les pages crawlées | Moyenne |

---

## 2. Scanner DAST Multi-moteurs (`dast_scanner.py`)

### 2.1 Capacités réelles
Orchestrateur d'analyse dynamique utilisant jusqu'à 3 moteurs en parallèle via `ThreadPoolExecutor`.

| Moteur | Fonctionnement réel | Disponibilité PythonAnywhere |
|--------|--------------------|-----------------------------|
| OWASP ZAP | Démon + API REST — spider actif + injections XSS/SQLi/CSRF | ❌ Non installable |
| Nuclei | CLI + 9000+ templates YAML CVE | ❌ Non installable |
| Nikto | Perl CLI — vérification config serveur + fichiers défaut | ❌ Non installable (Perl root requis) |
| **Fallback natif** | `requests` avec payloads XSS/SQLi basiques si aucun outil n'est installé | ✅ Toujours actif |

> **Important PythonAnywhere :** Les 3 outils externes ne sont pas disponibles sur le plan gratuit/standard.
> Le scanner fonctionne en mode dégradé avec le fallback natif uniquement.

### 2.2 Limites réelles
| Limite | Explication technique |
|--------|----------------------|
| Temps d'exécution | ZAP + Nuclei peuvent prendre 15-30 min sur un site moyen |
| Auth SSO/MFA | Incapable de scanner derrière un portail SSO sans Selenium |
| Boîte noire | Déduit les failles depuis le comportement HTTP — ne voit pas le code |
| WAF blocking | Le trafic massif peut être bloqué comme DDoS par un WAF |

### 2.3 Améliorations réalistes
| Amélioration | Implémentation | Réalisme PythonAnywhere |
|--------------|---------------|------------------------|
| Throttle intelligent | Ralentir si le serveur répond 429 — déjà pertinent avec notre rate-limiter | ✅ Faisable en pur Python |
| Auth Bearer | Accepter un token JWT en paramètre et l'injecter dans les headers | ✅ Simple à implémenter |
| IAST Integration | Agent côté serveur cible — **IRRÉALISTE** pour un scanner SaaS externe | ❌ Impossible sans accès au serveur cible |

---

## 3. Scanner SAST Multi-langages (`sast_scanner.py`)

### 3.1 Capacités réelles
Analyse statique du code source uploadé (ZIP) via 4 moteurs.

| Moteur | Ce qu'il fait vraiment | Langages |
|--------|----------------------|----------|
| **Bandit** | Linter sécurité Python (PyCQA) — détecte `eval()`, `subprocess`, SQL concat | Python uniquement |
| **Semgrep** | AST polyglotte — règles OWASP Top 10 + CWE 25 | Python, JS, Java, Go, PHP |
| **Gitleaks** | Détection secrets hardcodés (clés AWS, tokens GitHub, Stripe) | Tous fichiers texte |
| **Scanner Natif** | Fallback regex — détecte `eval()`, `os.system()`, mots de passe dans le code | Python (secours) |

Sécurité : l'archive ZIP est décompressée dans un répertoire temporaire isolé avec protection anti-Zip Bomb et anti-Directory Traversal (`../`).

### 3.2 Limites réelles
| Limite | Explication |
|--------|-------------|
| Faux positifs | S'alarme sur `test_password` ou code mort dans `/tests/` |
| Pas de Taint Tracking inter-fichiers | Analyse fichier par fichier — ne suit pas le flux `input() → sql.execute()` entre modules |
| Contexte WAF ignoré | Signale des failles potentiellement mitigées par un WAF upstream |

### 3.3 Améliorations réalistes
| Amélioration | Implémentation | Réalisme |
|--------------|---------------|----------|
| **Filtres ARIA** | Envoyer les résultats bruts à ARIA (notre IA) pour éliminer les faux positifs évidents | ✅ Déjà disponible via ChatPage |
| Contextualisation `.gitignore` | Ignorer automatiquement les fichiers dans `node_modules/`, `__pycache__/`, `/tests/` | ✅ Simple à implémenter |
| Scan Diff Git | Ne scanner que les fichiers modifiés depuis le dernier commit | ✅ Faisable avec `git diff --name-only` |
| Taint Analysis (CodeQL) | Suivi du flux de données inter-fichiers | ❌ Nécessite CodeQL CLI — non disponible PythonAnywhere |

---

## 4. Scanner Réseau & Ports (`netscan_scanner.py`)

### 4.1 Capacités réelles
Cartographie de la surface d'attaque réseau externe.

| Fonctionnalité | Détail |
|----------------|--------|
| Port scan TCP | Wrapper python-nmap — scan SYN (Half-open) |
| Fingerprinting | Bannières et OS detection (Nmap `-sV -O`) |
| Scripts NSE | Scripts Nmap pour CVEs spécifiques (`--script vuln`) |

### 4.2 Limites réelles
| Limite | Explication |
|--------|-------------|
| **Non disponible PythonAnywhere** | Nmap nécessite des raw sockets (root/CAP_NET_RAW) — **bloqué en production** |
| Firewall/IDS | Les scans massifs déclenchent les IDS/IPS |
| Pas de contexte HTTP | Connaît le port ouvert, mais pas ce qui tourne dessus (chemin web) |

### 4.3 Améliorations réalistes
| Amélioration | Implémentation | Réalisme PythonAnywhere |
|--------------|---------------|------------------------|
| Scan TCP pur Python | `socket.connect_ex()` en parallèle — sans Nmap, sans root | ✅ Faisable en production |
| Banner grabbing natif | Lire les 512 premiers bytes d'une connexion TCP pour fingerprinter | ✅ Faisable |
| Timing évasif (-T2) | Nmap `--timing polite` — ralentit pour passer sous le radar IDS | Dépend de l'installation Nmap |
| **IP Rotation via Tor** | Distribuer le scan sur des proxies Tor/VPN | ⚠️ Réservé aux pentesters autorisés — risque légal en usage SaaS |

---

## 5. Scanner SSL / TLS (`ssl_scanner.py`)

### 5.1 Capacités réelles
Audit cryptographique de la couche transport via `ssl` Python natif — zéro dépendance externe.

| Fonctionnalité | Détail |
|----------------|--------|
| Expiration | Alerte si certificat expire dans < 30 jours |
| Protocoles | Détecte SSLv2/v3, TLS 1.0/1.1 (dépréciés) |
| Ciphers faibles | Absence de Forward Secrecy, algorithmes MD5/RC4 |
| Parsing ASN.1 | Extrait SAN, issuer, dates directement du certificat X.509 |

### 5.2 Limites réelles
| Limite | Explication |
|--------|-------------|
| Port 443 uniquement | N'audite pas TLS sur ports non-standard (8443, 5432, 993, 465) |
| Pas de Heartbleed/POODLE | Ces attaques nécessitent des payloads malformés spéciaux |
| Pas de CT Log check | Ne vérifie pas si le certificat est dans Certificate Transparency |

### 5.3 Améliorations réalistes
| Amélioration | Implémentation | Réalisme PythonAnywhere |
|--------------|---------------|------------------------|
| **SSLyze** (pip install sslize) | Bibliothèque Python pure — teste POODLE, BEAST, ROBOT, Heartbleed | ✅ Installable via pip |
| Multi-ports | Coupler avec le Network Scanner — scanner tous les ports TLS découverts | ✅ Faisable |
| CT Log check | API `crt.sh` (HTTPS GET) — vérifie les sous-domaines exposés | ✅ Faisable sans dépendance |

---

## 6. Scanner Dépendances (`dep_scanner.py`)

### 6.1 Capacités réelles
Supply Chain Analysis (SCA) via l'API Google OSV.dev.

| Fonctionnalité | Détail |
|----------------|--------|
| SCA / SBOM | Parse `requirements.txt`, `package.json`, `composer.json`, `Gemfile` |
| Mapping CVE | Croise avec OSV.dev en temps réel |
| Détection malwares | Dépendances abandonnées ou typosquat |
| Versions exactes | Extrait les versions des lockfiles |

### 6.2 Limites réelles
| Limite | Explication |
|--------|-------------|
| Faux positifs structurels | Signale une lib vulnérable même si la fonction faillible n'est jamais appelée |
| Pas de dépendances transitives | Sans lockfile complet, les sous-dépendances sont ignorées |
| API OSV rate limit | Nombreuses requêtes API en parallèle peuvent être throttlées |

### 6.3 Améliorations réalistes
| Amélioration | Implémentation | Réalisme |
|--------------|---------------|----------|
| Reachability Analysis | Croiser avec l'AST du SAST — vérifier si la fonction vulnérable est appelée | ✅ Faisable (Bandit AST) |
| **Syft** (SBOM auto) | Génère l'arbre de dépendances transitives même sans lockfile | ❌ Nécessite installation binaire |
| Batch OSV API | Envoyer 100 packages en une seule requête POST au lieu de 100 appels | ✅ Simple optimisation |

---

## 7. Audit Configuration Serveur — Interne (`server_int.py`)

### 7.1 Capacités réelles
Analyse de fichiers de configuration Nginx/Apache/SSH via Regex sur le système de fichiers local.

| Fonctionnalité | Détail |
|----------------|--------|
| Nginx masquage | Vérifie `server_tokens off` |
| SSH durcissement | Vérifie `PermitRootLogin no` |
| TLS serveur | Vérifie `ssl_protocols TLSv1.2+` dans nginx.conf |

> **Requis :** Accès SSH au serveur ou upload du fichier de config.

### 7.2 Limites réelles
| Limite | Explication |
|--------|-------------|
| Statique uniquement | Ne lit pas la config chargée en mémoire par le démon |
| Inclusions externes | Ne suit pas les directives `include conf.d/*` |

### 7.3 Améliorations réalistes
| Amélioration | Implémentation | Réalisme |
|--------------|---------------|----------|
| Parser `crossplane` (pip) | Parse Nginx comme un AST — fusionne tous les `include` | ✅ Installable via pip |
| Apache `configparser` | Parser structuré pour `.conf` Apache | ✅ Stdlib Python |

---

## 8. Serveur Externe — Black Box (`server_ext.py`)

> **Ce scanner manquait dans le PDF V2 — couverture exclusive ici.**

### 8.1 Capacités réelles
Audit externe complet sans accès SSH — connexions HTTP uniquement.

| Fonctionnalité | Détail |
|----------------|--------|
| Headers sécurité | HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| Trafic parallèle | `ThreadPoolExecutor` — plusieurs checks simultanés |
| Détection version | Apache/Nginx version depuis le header `Server` → mapping CVE |
| Chemins sensibles | `/admin`, `/.git/`, `/phpinfo.php`, `/.env` — détection exposition |
| HTTP Methods | `TRACE`, `CONNECT`, `PUT` — méthodes dangereuses activées |
| TLS externe | Vérification certificat et protocoles depuis l'extérieur |

### 8.2 Limites réelles
| Limite | Explication |
|--------|-------------|
| Header obfuscation | Un serveur bien configuré cache sa version (`server_tokens off`) |
| WAF interception | Les chemins sensibles peuvent retourner 200 (WAF honeypot) |

### 8.3 Améliorations réalistes
| Amélioration | Implémentation | Réalisme |
|--------------|---------------|----------|
| Détection WAF | Fingerprinting des réponses WAF (Cloudflare, Akamai, AWS Shield) | ✅ Heuristiques HTTP |
| Subdomain takeover | Vérifier si des CNAMEs pointent vers des services inexistants | ✅ DNS-over-HTTPS |

---

## 9. Docker Security (`docker_scanner.py`)

> **Nouveau scanner — non couvert par PDF V2.**

### 9.1 Capacités réelles
Analyse statique de `Dockerfile` et `docker-compose.yml` — pur Python, zéro dépendance externe.

| Vérification | Description | Sévérité |
|--------------|-------------|----------|
| Pas de USER directive | Container tourne en root | HIGH |
| `USER root` explicite | Root intentionnel | HIGH |
| Image `:latest` | Pas de version pinned — reproductibilité brisée | MEDIUM |
| `ADD` au lieu de `COPY` | ADD peut extraire des archives distantes non sécurisées | MEDIUM |
| Ports sensibles exposés | SSH(22), Telnet(23), Docker API(2375), MySQL(3306) | HIGH/CRITICAL |
| Secrets dans `ENV` | Mots de passe/clés dans les variables d'environnement | CRITICAL |
| `curl \| bash` pattern | Supply chain attack — exécution de code non vérifié | CRITICAL |
| `chmod 777` | Permissions monde-accessible | HIGH |
| Pas de `HEALTHCHECK` | Impossible de détecter les containers crashés | LOW |
| `privileged: true` | Accès root au host depuis le container | CRITICAL |
| Docker socket monté | `/var/run/docker.sock` = accès total au host | CRITICAL |
| `network_mode: host` | Contourne l'isolation réseau Docker | HIGH |
| `cap_add: [ALL]` | Toutes les capacités kernel accordées | CRITICAL |

### 9.2 Limites réelles
| Limite | Explication |
|--------|-------------|
| Analyse statique uniquement | Ne lance pas le container — ne détecte pas les vulns runtime |
| Pas de scan d'image | N'analyse pas les layers de l'image Docker (Trivy, Grype) |

### 9.3 Améliorations réalistes
| Amélioration | Implémentation | Réalisme PythonAnywhere |
|--------------|---------------|------------------------|
| **Grype** (SBOM image) | Scanner CVE des layers Docker | ❌ Nécessite Docker daemon |
| Secrets dans COPY | Détecter si des fichiers `.env`, `*.key` sont copiés dans l'image | ✅ Analyse du Dockerfile |
| Hadolint rules | Intégrer les règles de best practices Dockerfile | ✅ Implémentable en Python |

---

## 10. DNS & Email Security (`dns_scanner.py`)

> **Nouveau scanner — non couvert par PDF V2.**

### 10.1 Capacités réelles
Audit DNS complet via DNS-over-HTTPS (API Cloudflare) — zéro dépendance externe, fonctionne sur PythonAnywhere.

| Vérification | Description | RFC/Standard |
|--------------|-------------|--------------|
| SPF | Politique d'envoi email, force (`-all` vs `+all`) | RFC 7208 |
| DMARC | Politique de rejet email (`reject`/`quarantine`/`none`) | RFC 7489 |
| DKIM | Probe de 7 sélecteurs communs (`default`, `google`, `mail`...) | RFC 6376 |
| MX | Présence des serveurs mail | RFC 5321 |
| CAA | Autorisation émission de certificat (empêche CA rogue) | RFC 8659 |
| DNSSEC | Présence des enregistrements DS (signature zone) | RFC 4033 |
| Zone Transfer | Tentative AXFR (toujours bloquée sur serveurs sécurisés) | RFC 5936 |
| HTTP Security Headers | HSTS, X-Frame-Options, CSP sur le domaine principal | OWASP |

### 10.2 Limites réelles
| Limite | Explication |
|--------|-------------|
| DKIM sélecteurs fixes | Sonde uniquement 7 sélecteurs — sélecteur custom non détecté |
| DoH uniquement | Pas de requêtes DNS natives (port 53 bloqué PythonAnywhere) |
| Pas de DNSSEC validation | Vérifie la présence des DS mais ne valide pas la chaîne de signature |

### 10.3 Améliorations réalistes
| Amélioration | Implémentation | Réalisme |
|--------------|---------------|----------|
| Sélecteurs DKIM dynamiques | Chercher les sélecteurs dans les emails headers ou crawl du site | ✅ Faisable |
| MX security score | Vérifier si les serveurs MX sont dans des listes noires (DNSBL) | ✅ API publiques |
| BIMI check | Brand Indicators for Message Identification — nouveau standard email | ✅ Enregistrement DNS TXT |

---

## 11. WordPress Audit (`wordpress_scanner.py`)

> **Nouveau scanner — non couvert par PDF V2.**

### 11.1 Capacités réelles
Audit non destructif d'une installation WordPress via HTTP read-only.

| Vérification | Description | Risque |
|--------------|-------------|--------|
| Détection WP | Confirme que le site est WordPress (meta generator, wp-login) | INFO |
| Version disclosure | Via `readme.html` ou `<meta name="generator">` | HIGH |
| User enumeration REST | `/wp-json/wp/v2/users` expose les usernames | HIGH |
| xmlrpc.php | Vecteur brute-force et SSRF | HIGH |
| Debug log | `/wp-content/debug.log` peut contenir données sensibles | CRITICAL |
| wp-cron.php | Peut être utilisé pour attaques DoS | MEDIUM |
| wp-config.php | Doit retourner 403/404 — si accessible = credential leak | CRITICAL |
| Username 'admin' | Username par défaut — facilite brute-force | MEDIUM |
| Security headers | X-Frame-Options, CSP, X-Content-Type-Options | MEDIUM |
| HTTPS redirect | HTTP → HTTPS obligatoire | HIGH |
| Version EOL | Versions avec CVEs critiques connues | CRITICAL |

### 11.2 Limites réelles
| Limite | Explication |
|--------|-------------|
| Pas d'authentification | Ne peut pas auditer les plugins derrière un portail auth |
| Pas de scan de plugins | Ne liste pas les plugins installés (enumération via `/wp-content/plugins/`) |
| Rate limiting WP | Certaines installations bloquent les requêtes répétées |

### 11.3 Améliorations réalistes
| Amélioration | Implémentation | Réalisme |
|--------------|---------------|----------|
| Plugin enumeration | Probe des 100 plugins les plus populaires | ✅ Simple HTTP probe |
| WPScan API | API publique WPScan pour CVEs plugins/themes | ✅ HTTPS GET, PythonAnywhere compatible |
| Credential stuffing check | Tester si le formulaire login répond à `admin/admin` | ✅ Lecture seule (pas d'auth réussie) |

---

## Matrice de Priorité d'Amélioration

| Priorité | Amélioration | Scanner | Effort | Impact |
|----------|-------------|---------|--------|--------|
| 🔴 1 | Crawler BeautifulSoup | Web | 2h | Très Haut |
| 🔴 2 | CORS check | Web | 30min | Haut |
| 🔴 3 | SSLyze integration | SSL | 1h | Haut |
| 🔴 4 | ARIA filtre faux positifs SAST | SAST | 3h | Haut |
| 🟡 5 | CT Log check (crt.sh) | SSL | 1h | Moyen |
| 🟡 6 | WPScan API plugins | WordPress | 2h | Moyen |
| 🟡 7 | DKIM sélecteurs dynamiques | DNS | 2h | Moyen |
| 🟡 8 | Auth Bearer (DAST) | DAST | 1h | Moyen |
| 🟢 9 | Batch OSV API | Deps | 30min | Faible |
| 🟢 10 | Parser crossplane (Nginx) | Config | 1h | Faible |

---

## Corrections par rapport au PDF V2

| Point PDF V2 | Statut | Correction |
|--------------|--------|------------|
| IAST Integration (DAST) | ❌ Irréaliste | Nécessite un agent côté serveur cible — impossible pour un scanner SaaS externe |
| Rotation IP via Tor (Network) | ⚠️ Risque légal | Valide en pentest autorisé uniquement — à ne jamais activer en mode SaaS par défaut |
| testssl.sh (SSL) | ⚠️ PythonAnywhere | Remplacer par **SSLyze** (pip install) — même capacité, 100% Python |
| Scanner Réseau disponible | ❌ Erreur PythonAnywhere | Nmap nécessite raw sockets (root) — **non fonctionnel en production** |
| 3 scanners manquants | ❌ Omission | Docker, DNS, WordPress absents du PDF V2 |
| Server External (`server_ext.py`) | ❌ Omission | Scanner distinct de `server_int.py` — non documenté dans PDF V2 |
