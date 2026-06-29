#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HexaGuard Manuel Analytique V4 — Generator
Architecture Cible : sans contraintes d'hebergement
"""

from fpdf import FPDF

# ── Palette ────────────────────────────────────────────────────────────────────
NAVY    = (10,  25,  50)
TEAL    = (0,  150, 180)
TEAL_LT = (0,  190, 220)
WHITE   = (255, 255, 255)
DARK    = (20,  20,  30)
GRAY    = (120, 120, 130)
ROW_A   = (245, 249, 254)
ROW_B   = (255, 255, 255)
ACCENT  = (0,  120, 150)

M  = 15           # margin mm
PW = 210          # page width A4
PH = 297          # page height A4
CW = PW - 2 * M  # content width

# ── Scanner Content ────────────────────────────────────────────────────────────
SCANNERS = [
    # 1 ─ Web Application
    {
        "num"  : "1",
        "title": "SCANNER WEB APPLICATION",
        "file" : "web_scanner.py",
        "desc" : (
            "Audit passif de la couche HTTP base sur une requete initiale (GET). "
            "Analyse les headers de securite, l'empreinte serveur, la configuration "
            "des cookies et les methodes HTTP exposees."
        ),
        "caps" : [
            ("Headers securite",
             "Verifie HSTS, CSP, X-Frame-Options, X-Content-Type-Options, "
             "Referrer-Policy et Permissions-Policy."),
            ("Empreinte serveur",
             "Analyse Server, X-Powered-By et X-Generator "
             "pour reveler la stack technique cote serveur."),
            ("Redirection HTTPS",
             "Verifie si HTTP redirige vers HTTPS (301/302) "
             "et si HSTS preload est correctement active."),
            ("Cookies",
             "Controle les attributs Secure, HttpOnly, SameSite "
             "et le prefixe __Host- pour une isolation maximale."),
            ("Methodes HTTP",
             "Detecte les methodes dangereuses activees via OPTIONS : "
             "PUT, DELETE, TRACE, CONNECT."),
        ],
        "limits": [
            ("Pas de crawling",
             "Ne verifie que la racine '/', ignorant 99% du contenu reel du site."),
            ("Aucun test actif",
             "Zero payload envoye - ne detecte pas les failles XSS ou SQLi reelles."),
            ("Pas de CORS check",
             "Ne teste pas les politiques CORS permissives "
             "(Access-Control-Allow-Origin: *)."),
            ("Pas d'enumeration",
             "Ne teste pas les chemins sensibles courants "
             "(/admin, /.git, /backup, /.env)."),
            ("Cache/CDN opaque",
             "Un CDN peut masquer la vraie configuration "
             "du serveur d'origine derriere le cache."),
        ],
        "amels": [
            ("Crawler leger (BeautifulSoup)",
             "Extraire 10-20 sous-pages pour verifier la coherence "
             "des headers sur tout le site. Priorite Haute."),
            ("Test CORS actif",
             "Envoyer des requetes avec Origin: https://evil.com "
             "pour capturer les configs CORS permissives. Priorite Haute."),
            ("Audit robots.txt & sitemap",
             "Analyser robots.txt et sitemap.xml pour reveler "
             "la structure et les chemins sensibles exposes. Priorite Moyenne."),
            ("Enumeration de chemins",
             "Tester /admin, /.git, /.env, /backup "
             "via une wordlist de 500 entrees. Priorite Moyenne."),
            ("Detection WAF",
             "Fingerprinting des WAF via headers caracteristiques "
             "et reponses a des payloads inoffensifs. Priorite Basse."),
        ],
    },
    # 2 ─ DAST
    {
        "num"  : "2",
        "title": "SCANNER DAST MULTI-MOTEURS",
        "file" : "dast_scanner.py",
        "desc" : (
            "Orchestrateur d'analyse dynamique utilisant 3 moteurs externes "
            "(OWASP ZAP, Nuclei, Nikto) et un moteur natif de secours. "
            "Approche boite noire : deduit les vulnerabilites depuis "
            "le comportement HTTP observable."
        ),
        "caps" : [
            ("OWASP ZAP",
             "Demon + API REST - spidering actif + injections "
             "XSS/SQLi/CSRF automatisees avec rapport detaille."),
            ("Nuclei",
             "CLI/Cloud - plus de 9 000 templates YAML "
             "orientes CVE et expositions publiques connues."),
            ("Nikto",
             "Verification des configurations serveurs web "
             "et detection de fichiers obsoletes ou dangereux."),
            ("Fallback Natif",
             "Utilise requests avec des payloads basiques "
             "si les moteurs externes sont inactifs ou absents."),
        ],
        "limits": [
            ("Temps d'execution massif",
             "ZAP + Nuclei peuvent prendre 15 a 30 minutes sur un site moyen."),
            ("Authentification complexe",
             "Incapable de scanner derriere des portails SSO ou MFA "
             "sans Selenium/Playwright."),
            ("Blocage WAF",
             "Le trafic massif est souvent bloque comme une attaque DDoS, "
             "aveuglant le scanner et produisant des faux negatifs."),
            ("Approche Boite Noire",
             "Deduit les failles uniquement via le comportement HTTP, "
             "sans voir le code source."),
            ("GraphQL non couvert",
             "Les endpoints GraphQL non-REST echappent "
             "au spidering standard de ZAP/Nikto."),
        ],
        "amels": [
            ("Support Auth Bearer/JWT",
             "Accepter des tokens de session et les injecter dynamiquement "
             "pour scanner les zones authentifiees. Priorite Haute."),
            ("Throttle intelligent",
             "Auto-ralentissement si reponse 429 - backoff exponentiel "
             "pour eviter le bannissement IP. Priorite Haute."),
            ("Scanner GraphQL",
             "Detecter les endpoints GraphQL et tester l'introspection "
             "et les injections specifiques. Priorite Moyenne."),
            ("Test JWT",
             "Tester : alg:none, secret HS256 faible, "
             "expiration ignoree. Priorite Moyenne."),
            ("Vision Produit - Agent IAST Optionnel",
             "Module agent installable par le client pour corroler "
             "l'attaque DAST avec la ligne de code exacte. "
             "Requiert accord contractuel explicite. Long terme."),
        ],
    },
    # 3 ─ SAST
    {
        "num"  : "3",
        "title": "SCANNER SAST MULTI-LANGAGES",
        "file" : "sast_scanner.py",
        "desc" : (
            "Analyse statique concurrente de code source via 4 moteurs dedies "
            "(Bandit, Semgrep, Gitleaks, Natif). Detecte les vulnerabilites "
            "dans le code, les secrets hardcodes et les patterns dangereux "
            "sans executer le programme."
        ),
        "caps" : [
            ("Bandit (Python)",
             "Linter securite : detecte eval(), exec(), subprocess, "
             "injections SQL et deserialisation non securisee."),
            ("Semgrep (Polyglotte)",
             "Analyse AST multi-langages avec regles OWASP Top 10 "
             "et CWE Top 25. Supporte Python, JS, Java, Go."),
            ("Gitleaks",
             "Detection de secrets hardcodes : cles AWS, tokens GitHub, "
             "Stripe, mots de passe en clair."),
            ("Scanner Natif",
             "Fallback regex ciblant les patterns critiques "
             "sans dependances systeme externes."),
        ],
        "limits": [
            ("Faux positifs structurels",
             "Alarme sur du code mort (dans /tests/) "
             "ou des variables mockees ('test_password')."),
            ("Manque de Taint Tracking",
             "Analyse par fichier : ne suit pas le flux de donnees "
             "entre plusieurs modules ou microservices."),
            ("Contexte d'execution ignore",
             "Signale des failles pouvant etre mitigees "
             "par des WAF ou des wrappers globaux."),
            ("Secrets hors code ignores",
             "Gitleaks scanne le code commite mais pas "
             "les fichiers .env non versionnees."),
            ("Dependances transitives",
             "Ne resout pas l'arbre complet des imports "
             "entre fichiers et modules."),
        ],
        "amels": [
            ("Filtres IA (ARIA)",
             "Envoyer les resultats bruts au moteur IA pour evaluer "
             "la pertinence reelle et eliminer les faux positifs. "
             "Deja disponible dans HexaGuard."),
            ("Taint Analysis (CodeQL)",
             "Integrer CodeQL pour un suivi complet : "
             "entree utilisateur -> execution base de donnees. Priorite Haute."),
            ("Scan Diff & .gitignore",
             "Ne scanner que les fichiers modifies via 'git diff' "
             "pour une integration CI/CD ultrarapide. Priorite Haute."),
            ("Analyse fichiers .env",
             "Etendre Gitleaks aux fichiers d'environnement non commites "
             "via upload direct securise. Priorite Moyenne."),
            ("Detection Dependency Confusion",
             "Verifier si les noms de packages internes existent "
             "sur PyPI/npm (risque supply chain). Priorite Moyenne."),
        ],
    },
    # 4 ─ Réseau
    {
        "num"  : "4",
        "title": "SCANNER RESEAU & PORTS",
        "file" : "netscan_scanner.py",
        "desc" : (
            "Cartographie de la surface d'attaque reseau externe. "
            "Decouverte des services exposes, fingerprinting OS "
            "et bannieres logicielles. Requiert des privileges adaptes "
            "pour un scan SYN optimal (root ou NET_RAW capability)."
        ),
        "caps" : [
            ("Scan TCP (Nmap)",
             "Decouverte des services exposes avec un scan furtif SYN Half-open. "
             "Plage de ports configurable par l'utilisateur."),
            ("Fingerprinting",
             "Detection precise des OS et bannieres logicielles "
             "via les options Nmap -sV -O."),
            ("Scripts NSE",
             "Execution de scripts Nmap pour valider "
             "des vulnerabilites connues (CVE) sur les services detectes."),
            ("Banner Grabbing",
             "Extraction de la version exacte des services "
             "pour croisement avec la base CVE."),
        ],
        "limits": [
            ("Bloque par IDS/IPS",
             "Les scans massifs declenchent les pare-feu "
             "et systemes de prevention d'intrusion (Snort, Suricata)."),
            ("Pas de contexte applicatif",
             "Sait que le port 80 est ouvert mais n'inspecte pas "
             "l'arborescence web ni les services derriere."),
            ("Requiert root/raw sockets",
             "Pour le scan SYN Half-open optimal. "
             "Sans root : scan TCP connect degrade uniquement."),
            ("UDP ignore",
             "Services DNS (53), SNMP (161), NTP (123), IPSec (500) "
             "sur UDP non couverts par defaut."),
            ("Pas d'intelligence IP",
             "Ne croise pas l'IP avec les donnees BGP, ASN "
             "ou les listes de reputation (listes noires)."),
        ],
        "amels": [
            ("Scan Natif Multi-thread",
             "Implementer socket.connect_ex() en parallele "
             "comme fallback performant sans root. Priorite Haute."),
            ("Timing evasif (-T2)",
             "Espacer dynamiquement les requetes "
             "pour passer sous le radar des IDS actifs. Priorite Haute."),
            ("Rotation IP - Pool Dedie",
             "Proxy pool proprietaire (NON Tor) comme Qualys/Tenable - "
             "legal, stable, sans risque de bannissement. Priorite Moyenne."),
            ("Scan UDP partiel",
             "Cibler les ports UDP critiques : 53 (DNS), 161 (SNMP), "
             "123 (NTP), 500 (IPSec). Priorite Moyenne."),
            ("Intelligence IP (ASN/Reputation)",
             "Croiser avec Shodan/WHOIS pour le contexte d'exposition "
             "et les listes noires publiques. Priorite Basse."),
        ],
    },
    # 5 ─ SSL
    {
        "num"  : "5",
        "title": "SCANNER SSL / TLS",
        "file" : "ssl_scanner.py",
        "desc" : (
            "Audit cryptographique de la couche de transport. "
            "Verifie l'expiration, les protocoles deprecies, "
            "les algorithmes faibles et la validite de la chaine "
            "de certificats X.509."
        ),
        "caps" : [
            ("Expiration",
             "Alerte si le certificat expire dans moins de 30 jours. "
             "Seuil configurable."),
            ("Protocoles",
             "Detecte SSLv2/v3 et TLS 1.0/1.1 "
             "deprecies (RFC 8996 - mars 2021)."),
            ("Ciphers faibles",
             "Verifie l'absence de Forward Secrecy "
             "et les algorithmes vulnerables : RC4, DES, NULL, EXPORT."),
            ("Parsing ASN.1",
             "Extrait SAN, issuer, subject et dates "
             "directement du certificat X.509."),
            ("Chain validation",
             "Verifie la chaine de certificats "
             "jusqu'au CA racine de confiance."),
        ],
        "limits": [
            ("Port 443 uniquement",
             "Ignore les autres ports TLS : 8443, IMAPS (993), "
             "SMTPS (465), LDAPS (636), PostgreSQL (5432)."),
            ("Pas de POODLE/Heartbleed",
             "Ces failles requierent des handshakes volontairement malformes "
             "que la librairie ssl native Python ne permet pas."),
            ("Pas de verification CT",
             "Ne verifie pas si le certificat est present "
             "dans les logs de Certificate Transparency."),
            ("Pas d'OCSP",
             "Ne verifie pas si le certificat est revoque "
             "via OCSP ou CRL (Certificate Revocation List)."),
            ("Pas de test HTTP/2",
             "Ne detecte pas les problemes lies a ALPN "
             "et a la negociation de protocole HTTP/2 ou HTTP/3."),
        ],
        "amels": [
            ("Integration SSLyze",
             "Remplacer la lib ssl native par SSLyze (pure Python) "
             "pour detecter ROBOT, BEAST, POODLE, Heartbleed. Priorite Haute."),
            ("CT Log Check (crt.sh API)",
             "Interroger crt.sh pour decouvrir des sous-domaines caches "
             "lies au certificat principal. Priorite Haute."),
            ("Multi-Ports TLS",
             "Coupler avec le Network Scanner pour verifier TLS "
             "sur l'ensemble des ports ouverts. Priorite Moyenne."),
            ("Verification OCSP",
             "Verifier la revocation du certificat en temps reel "
             "via OCSP stapling. Priorite Moyenne."),
            ("Score Mozilla Observatory",
             "Integrer le scoring SSL de Mozilla Observatory "
             "pour un rapport standardise et comparable. Priorite Basse."),
        ],
    },
    # 6 ─ Dépendances
    {
        "num"  : "6",
        "title": "SCANNER DE DEPENDANCES",
        "file" : "dep_scanner.py",
        "desc" : (
            "Supply Chain Analysis via l'API Google OSV.dev. "
            "Parse les fichiers de dependances (requirements.txt, package.json, "
            "composer.json), extrait les versions exactes "
            "et croise avec la base CVE en temps reel."
        ),
        "caps" : [
            ("SCA & SBOM",
             "Parse requirements.txt, package.json, composer.json "
             "et extrait les versions exactes de chaque paquet."),
            ("Mapping CVE",
             "Croise l'inventaire avec OSV.dev "
             "en temps reel pour chaque version declaree."),
            ("Detection de malwares",
             "Repere les dependances obsoletes, abandonnees "
             "ou potentiellement typosquatees."),
        ],
        "limits": [
            ("Faux positifs structurels",
             "Signale la librairie entiere comme vulnerable, "
             "meme si la fonction affectee n'est pas appelee."),
            ("Dependances transitives",
             "Sans fichier lock strict (poetry.lock, yarn.lock), "
             "les sous-dependances critiques sont ignorees."),
            ("Rate Limiting API OSV",
             "Des centaines de requetes individuelles "
             "peuvent saturer et ralentir l'API OSV.dev."),
            ("Source unique",
             "OSV.dev peut avoir des delais sur les CVE recents "
             "versus NVD ou GitHub Advisory Database."),
            ("Pas de controle de licence",
             "Ne detecte pas les conflits de licences GPL "
             "dans les projets proprietaires."),
        ],
        "amels": [
            ("Batch OSV API",
             "Envoyer les packages par lots de 100 via une seule requete POST - "
             "reduction de 90% du temps d'execution. Priorite Haute."),
            ("Generation SBOM (Syft)",
             "Utiliser Syft pour resoudre l'arbre de dependances complet "
             "meme sans fichier lock. Priorite Haute."),
            ("Reachability Analysis",
             "Croiser avec l'AST Semgrep pour confirmer "
             "si le code vulnerable est effectivement appele. Priorite Haute."),
            ("Source Secondaire NVD",
             "Fallback API NVD pour les CVE non encore indexes sur OSV. "
             "Priorite Moyenne."),
            ("Controle de Licences",
             "Detecter les conflits : GPL dans un projet proprietaire. "
             "Priorite Basse."),
        ],
    },
    # 7 ─ Config Serveur
    {
        "num"  : "7",
        "title": "SCANNER CONFIGURATION SERVEUR",
        "file" : "server_scanner.py",
        "desc" : (
            "Audit de la configuration des serveurs web (Apache, Nginx) "
            "via l'analyse des headers HTTP exposes et des fichiers accessibles. "
            "Detecte les mauvaises pratiques de durcissement (hardening)."
        ),
        "caps" : [
            ("Directives serveur",
             "Verifie ServerTokens, ServerSignature, autoindex "
             "via les headers de reponse HTTP."),
            ("Fichiers sensibles exposes",
             "Detecte l'accessibilite publique de .htaccess, "
             ".env, .git, web.config, phpinfo.php."),
            ("Headers de securite",
             "Croise avec le scanner web pour coherence "
             "de la politique de securite globale."),
            ("Modules dangereux",
             "Detecte mod_status, mod_info actives "
             "sans authentification (Apache)."),
            ("Version disclosure",
             "Repere la divulgation de version "
             "dans les pages d'erreur (404, 500)."),
        ],
        "limits": [
            ("Vue externe uniquement",
             "Ne peut inspecter que ce qui est expose via HTTP - "
             "pas les fichiers de config internes (/etc/nginx/)."),
            ("Pas de baseline CIS",
             "Ne compare pas la config contre les benchmarks "
             "CIS Apache/Nginx officiels."),
            ("Pas de detection backup",
             "Ne cherche pas systematiquement les fichiers "
             "de backup (.bak, .old, .orig, ~)."),
            ("Pas d'auth config",
             "Ne verifie pas la robustesse des zones protegees "
             "par Basic Auth ou Digest Auth."),
        ],
        "amels": [
            ("CIS Benchmark Mapping",
             "Croiser les resultats avec le CIS Apache/Nginx Benchmark "
             "pour un score de conformite officiel. Priorite Haute."),
            ("Detection Backup Files",
             "Tester .bak, .old, .orig, ~, .swp "
             "sur les configs et fichiers connus. Priorite Haute."),
            ("Test Directory Listing",
             "Verifier si l'autoindex est actif "
             "sur les repertoires sensibles. Priorite Moyenne."),
            ("Integration SCAP",
             "Support du protocole SCAP pour echange standardise "
             "des resultats avec les SIEMs d'entreprise. Priorite Basse."),
        ],
    },
    # 8 ─ Serveur Externe
    {
        "num"  : "8",
        "title": "SCANNER SERVEUR EXTERNE",
        "file" : "server_ext.py",
        "desc" : (
            "Reconnaissance passive de la surface d'attaque reseau "
            "depuis une perspective externe. Exploite des donnees OSINT "
            "(Shodan, headers HTTP) sans envoyer de scan actif vers la cible."
        ),
        "caps" : [
            ("Integration Shodan",
             "Interroge l'API Shodan : ports decouverts, "
             "services, bannieres et CVE connus pour l'IP cible."),
            ("Headers HTTP externes",
             "Analyse les headers de reponse "
             "depuis la perspective d'un client externe."),
            ("Reputation IP",
             "Verifie si l'IP cible figure "
             "dans des listes noires (spam, malware, botnet)."),
            ("Correlation ports/services",
             "Croise les ports ouverts avec les services attendus "
             "pour detecter les expositions anormales."),
        ],
        "limits": [
            ("Depend de Shodan",
             "Les resultats sont lies a la frequence de scan de Shodan - "
             "potentiellement obsoletes de plusieurs jours."),
            ("Pas de scan actif",
             "Ne sonde pas directement les ports - "
             "se base sur les donnees Shodan indexees."),
            ("Rate limiting Shodan",
             "L'API gratuite est tres limitee "
             "en nombre de requetes par mois."),
            ("Vue externe uniquement",
             "Ne voit pas la surface d'attaque interne "
             "ni les services sur des plages IP privees (RFC 1918)."),
        ],
        "amels": [
            ("Source Secondaire Censys",
             "Completer Shodan avec Censys.io "
             "pour des donnees plus fraiches et exhaustives. Priorite Haute."),
            ("Scan Actif Complementaire",
             "socket.connect_ex() sur ports critiques "
             "pour verification en temps reel. Priorite Haute."),
            ("Threat Intelligence",
             "Croiser l'IP avec VirusTotal et AlienVault OTX "
             "pour le contexte menace complet. Priorite Moyenne."),
            ("Historique DNS Passif",
             "Comparer DNS actuel vs historique PassiveDNS "
             "pour detecter les changements suspects recents. Priorite Basse."),
        ],
    },
    # 9 ─ Docker
    {
        "num"  : "9",
        "title": "SCANNER DOCKER",
        "file" : "docker_scanner.py",
        "desc" : (
            "Analyse statique des images Docker : detection des mauvaises pratiques "
            "dans le Dockerfile, des secrets hardcodes et des packages "
            "systeme vulnerables via croisement CVE."
        ),
        "caps" : [
            ("Analyse Dockerfile",
             "Detecte : user root, ports exposes inutiles, "
             "secrets dans ENV/ARG, absence de multi-stage build."),
            ("CVE Mapping packages",
             "Croise les packages systeme installes dans l'image "
             "avec OSV/NVD pour les CVE connus."),
            ("Layer Analysis",
             "Inspecte chaque layer Docker pour detecter des secrets "
             "introduits puis supprimes (persistants dans l'historique)."),
            ("Bonnes pratiques",
             "Verifie multi-stage build, image de base officielle, "
             "absence de 'curl | bash' piping dangereux."),
        ],
        "limits": [
            ("Acces daemon requis",
             "Necessite l'acces au daemon Docker du serveur "
             "pour analyser les images locales."),
            ("Images privees",
             "Ne peut analyser les images derriere un registry prive "
             "sans credentials explicites."),
            ("Analyse statique uniquement",
             "Ne voit pas le comportement a l'execution - "
             "un process malveillant au runtime est invisible."),
            ("Orchestration non couverte",
             "Ne couvre pas les policies Kubernetes (RBAC) "
             "ou Docker Compose multi-services."),
        ],
        "amels": [
            ("Integration Trivy",
             "Remplacer le scanner natif par Trivy (Aqua Security) "
             "pour une couverture CVE exhaustive et mise a jour. Priorite Haute."),
            ("Registry Scan",
             "Support Docker Hub, ECR et GCR "
             "avec credentials chiffres pour les images privees. Priorite Haute."),
            ("Runtime Security (Falco)",
             "Coupler avec Falco pour detecter "
             "les comportements suspects en production (syscall monitoring). Priorite Moyenne."),
            ("Audit Kubernetes",
             "Etendre a l'audit des policies Kubernetes : "
             "RBAC, PodSecurityPolicy, NetworkPolicy. Priorite Moyenne."),
        ],
    },
    # 10 ─ DNS
    {
        "num"  : "10",
        "title": "SCANNER DNS & EMAIL",
        "file" : "dns_scanner.py",
        "desc" : (
            "Audit de la configuration DNS et de la securite email. "
            "Utilise DNS-over-HTTPS (Cloudflare DoH) pour la resolution, "
            "verifie SPF/DKIM/DMARC et detecte les sous-domaines exposes "
            "via Certificate Transparency."
        ),
        "caps" : [
            ("Enregistrements DNS",
             "A, AAAA, MX, NS, CNAME, TXT - resolution "
             "via DNS-over-HTTPS Cloudflare (pas de raw socket requis)."),
            ("Securite Email",
             "Verifie SPF (anti-relais), DKIM (signature cryptographique) "
             "et DMARC (politique de rejet/quarantaine)."),
            ("Zone Transfer (AXFR)",
             "Tente un transfert de zone pour detecter "
             "les serveurs DNS mal configures."),
            ("Certificate Transparency",
             "Croise avec crt.sh pour decouvrir "
             "des sous-domaines caches lies au certificat."),
        ],
        "limits": [
            ("DNS-over-HTTPS uniquement",
             "Pas de resolution recursive native - "
             "depend de la disponibilite de l'API Cloudflare DoH."),
            ("Pas de DNSSEC",
             "Ne verifie pas la signature cryptographique "
             "des zones DNS (RRSIG, DS records)."),
            ("Subdomain takeover passif",
             "Identifie les CNAME suspects "
             "mais ne teste pas activement la prise de controle."),
            ("Email passif uniquement",
             "Verifie les enregistrements DNS "
             "mais n'envoie pas d'email de test pour valider DKIM."),
        ],
        "amels": [
            ("Validation DNSSEC",
             "Verifier la signature cryptographique des zones DNS "
             "pour detecter le DNS poisoning. Priorite Haute."),
            ("Subdomain Takeover Actif",
             "Detecter les CNAMEs pointant vers des services abandonnes "
             "(GitHub Pages, S3, Heroku). Priorite Haute."),
            ("DNS History (PassiveDNS)",
             "Comparer DNS actuel vs historique "
             "pour detecter des changements suspects recents. Priorite Moyenne."),
            ("MTA-STS & BIMI",
             "Verifier MTA-STS (securite transport email) "
             "et BIMI (branding email authentifie). Priorite Basse."),
        ],
    },
    # 11 ─ WordPress
    {
        "num"  : "11",
        "title": "SCANNER WORDPRESS",
        "file" : "wordpress_scanner.py",
        "desc" : (
            "Audit de securite dedie aux sites WordPress. "
            "Detection de version, audit des plugins et themes, "
            "enumeration des utilisateurs via l'API REST "
            "et verification des fichiers sensibles exposes."
        ),
        "caps" : [
            ("Detection de version",
             "Detecte la version WordPress via meta generator, "
             "readme.html et feed RSS."),
            ("Audit Plugins/Themes",
             "Liste les plugins actifs et croise "
             "avec la WPScan Vulnerability Database."),
            ("Enumeration utilisateurs",
             "Teste /wp-json/wp/v2/users "
             "pour l'exposition des comptes administrateurs."),
            ("Fichiers sensibles",
             "Verifie xmlrpc.php, wp-config.php.bak, "
             "debug.log, wp-cron.php exposes publiquement."),
        ],
        "limits": [
            ("Version masquable",
             "Si la version est masquee par un plugin de securite, "
             "la precision de l'audit CVE est reduite."),
            ("WPScan API limitee",
             "La base CVE WPScan est rate-limited "
             "sur le plan gratuit (25 requetes/jour)."),
            ("Pas de brute force",
             "Ne teste pas les mots de passe - "
             "hors scope ethique pour un scanner SaaS."),
            ("CMS non WordPress ignores",
             "Ne couvre pas Drupal, Joomla, PrestaShop "
             "representant 20% du marche CMS."),
        ],
        "amels": [
            ("Integration WPScan CLI",
             "Integrer WPScan directement pour un scan complet "
             "avec base CVE officielle mise a jour quotidiennement. Priorite Haute."),
            ("Support Joomla & Drupal",
             "Etendre le scanner CMS a Joomla et Drupal "
             "avec leurs propres bases de vulnerabilites. Priorite Haute."),
            ("REST API Audit",
             "Scanner tous les endpoints /wp-json/ "
             "pour detecter les donnees utilisateurs exposees. Priorite Moyenne."),
            ("Login Protection Check",
             "Tester /wp-login.php pour la protection brute force : "
             "lockout, 2FA, Captcha. Priorite Basse."),
        ],
    },
]


# ── PDF Class ──────────────────────────────────────────────────────────────────
class PDF(FPDF):

    def footer(self):
        self.set_y(-15)
        self.set_draw_color(*TEAL)
        self.set_line_width(0.4)
        self.line(M, PH - 17, PW - M, PH - 17)
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*GRAY)
        self.set_x(M)
        self.cell(CW / 2, 5, "HexaGuard - Manuel Analytique V4 (Architecture Cible)", 0, 0, "L")
        self.cell(CW / 2, 5, f"Page {self.page_no()}", 0, 0, "R")

    # ── helpers ──────────────────────────────────────────────────────────────

    def hline(self, color=TEAL, lw=0.4):
        self.set_draw_color(*color)
        self.set_line_width(lw)
        self.line(M, self.get_y(), PW - M, self.get_y())

    def row_height(self, texts, widths, font_sizes, bold_flags):
        """Estimate height of a table row."""
        LINE_H = 5
        PAD    = 4
        max_h  = LINE_H + PAD
        for txt, w, fs, bold in zip(texts, widths, font_sizes, bold_flags):
            self.set_font("Helvetica", "B" if bold else "", fs)
            try:
                lines = self.multi_cell(w - 4, LINE_H, txt, split_only=True)
                n = len(lines)
            except Exception:
                n = max(1, int(self.get_string_width(txt) / (w - 4)) + 1)
            h = n * LINE_H + PAD
            max_h = max(max_h, h)
        return max_h

    def draw_cell(self, x, y, w, h, text, fs, bold, bg, fg):
        LINE_H = 5
        PAD    = 2
        self.set_fill_color(*bg)
        self.rect(x, y, w, h, "F")
        self.set_draw_color(190, 210, 225)
        self.set_line_width(0.2)
        self.rect(x, y, w, h)
        self.set_font("Helvetica", "B" if bold else "", fs)
        self.set_text_color(*fg)
        self.set_xy(x + PAD, y + PAD)
        self.multi_cell(w - 2 * PAD, LINE_H, text, 0, "L")

    def draw_table(self, headers, rows, col_widths, fs=8.5):
        """Draw full table with header row and data rows."""
        all_rows  = [headers] + rows
        is_header = [True] + [False] * len(rows)

        for ri, (row, hdr) in enumerate(zip(all_rows, is_header)):
            bold_f = [hdr] * len(row)
            h = self.row_height(row, col_widths, [fs] * len(row), bold_f)

            if self.get_y() + h > PH - 25:
                self.add_page()

            y0 = self.get_y()
            x0 = M
            for ci, (txt, cw) in enumerate(zip(row, col_widths)):
                x  = x0 + sum(col_widths[:ci])
                bg = NAVY if hdr else (ROW_A if ri % 2 == 0 else ROW_B)
                fg = WHITE if hdr else DARK
                self.draw_cell(x, y0, cw, h, txt, fs, hdr, bg, fg)
            self.set_y(y0 + h)
        self.ln(4)

    # ── page elements ─────────────────────────────────────────────────────────

    def cover_page(self):
        self.add_page()

        # Top navy bar
        self.set_fill_color(*NAVY)
        self.rect(0, 0, PW, 14, "F")
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*TEAL_LT)
        self.set_xy(0, 3)
        self.cell(PW, 8, "RAPPORT D'ANALYSE TECHNIQUE EXHAUSTIF V4", 0, 0, "C")

        # Teal accent line
        self.set_fill_color(*TEAL)
        self.rect(0, 14, PW, 1.5, "F")

        # Title block
        self.set_y(55)
        self.set_font("Helvetica", "B", 38)
        self.set_text_color(*TEAL)
        self.cell(CW + 2 * M, 18, "HexaGuard Scanner Engine", 0, 1, "C")

        # Subtitle
        self.set_font("Helvetica", "", 13)
        self.set_text_color(*GRAY)
        self.cell(CW + 2 * M, 8, "Manuel Analytique Complet - 11 Scanners", 0, 1, "C")

        # Divider
        self.ln(6)
        self.set_draw_color(*TEAL)
        self.set_line_width(1.2)
        self.line(M + 30, self.get_y(), PW - M - 30, self.get_y())
        self.ln(10)

        # Philosophy box
        self.set_fill_color(245, 249, 254)
        self.set_draw_color(*TEAL)
        self.set_line_width(0.5)
        phi_x = M + 10
        phi_w = CW - 20
        self.rect(phi_x, self.get_y(), phi_w, 22, "FD")
        self.set_font("Helvetica", "BI", 10)
        self.set_text_color(*NAVY)
        self.set_xy(phi_x + 5, self.get_y() + 4)
        self.multi_cell(phi_w - 10, 6,
            "Notre philosophie : Autocritique constante.\n"
            "Identifier les limites avec honnetete, puis proposer "
            "des ameliorations concretes pour les depasser.", 0, "C")
        self.ln(16)

        # Metadata table
        meta = [
            ("Base Documentaire",
             "Analyse du code source reel + V3 PDF + "
             "SCANNERS_TECHNICAL.md"),
            ("Couverture",
             "11 scanners (vs 6 dans la V3)"),
            ("Architecture Cible",
             "Cloud dedie, sans contraintes d'hebergement"),
            ("Date", "Juin 2026"),
            ("Version", "V4 - Edition Complete"),
        ]
        self.set_x(M + 10)
        col_w = [50, CW - 20 - 50]
        for k, v in meta:
            y0 = self.get_y()
            h  = self.row_height([k, v], col_w, [9, 9], [True, False])
            x0 = M + 10
            self.draw_cell(x0,          y0, col_w[0], h, k, 9, True,  NAVY,  WHITE)
            self.draw_cell(x0+col_w[0], y0, col_w[1], h, v, 9, False, ROW_A, DARK)
            self.set_y(y0 + h)

    def toc_page(self):
        self.add_page()
        self.set_y(M + 5)
        self.set_font("Helvetica", "B", 16)
        self.set_text_color(*NAVY)
        self.cell(CW, 10, "Table des Matieres", 0, 1, "L")
        self.hline()
        self.ln(5)

        groups = [
            ("GROUPE A - Scanners Applicatifs", [
                ("1", "Scanner Web Application",     "web_scanner.py"),
                ("2", "Scanner DAST Multi-Moteurs",  "dast_scanner.py"),
                ("3", "Scanner SAST Multi-Langages", "sast_scanner.py"),
                ("4", "Scanner Reseau & Ports",      "netscan_scanner.py"),
            ]),
            ("GROUPE B - Scanners Infrastructure", [
                ("5",  "Scanner SSL / TLS",              "ssl_scanner.py"),
                ("6",  "Scanner de Dependances",         "dep_scanner.py"),
                ("7",  "Scanner Configuration Serveur",  "server_scanner.py"),
                ("8",  "Scanner Serveur Externe",        "server_ext.py"),
            ]),
            ("GROUPE C - Scanners Specialises", [
                ("9",  "Scanner Docker",    "docker_scanner.py"),
                ("10", "Scanner DNS & Email", "dns_scanner.py"),
                ("11", "Scanner WordPress", "wordpress_scanner.py"),
            ]),
        ]

        for group_title, items in groups:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*TEAL)
            self.cell(CW, 7, group_title, 0, 1, "L")
            self.set_draw_color(*TEAL)
            self.set_line_width(0.3)
            self.line(M, self.get_y(), M + 80, self.get_y())
            self.ln(2)

            for num, title, fname in items:
                self.set_font("Helvetica", "", 9.5)
                self.set_text_color(*DARK)
                self.set_x(M + 5)
                self.cell(8, 6, f"{num}.", 0, 0, "L")
                self.cell(CW - 80, 6, title, 0, 0, "L")
                self.set_font("Helvetica", "I", 8)
                self.set_text_color(*GRAY)
                self.cell(70, 6, fname, 0, 1, "R")
            self.ln(3)

        # Note bas
        self.ln(5)
        self.set_fill_color(245, 249, 254)
        self.set_draw_color(*TEAL)
        self.set_line_width(0.4)
        self.rect(M, self.get_y(), CW, 18, "FD")
        self.set_xy(M + 4, self.get_y() + 3)
        self.set_font("Helvetica", "B", 8.5)
        self.set_text_color(*NAVY)
        self.cell(CW - 8, 5, "Structure par scanner (sections 1 a 11) :", 0, 1, "L")
        self.set_x(M + 4)
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*DARK)
        self.cell(CW - 8, 5,
            "X.1 Capacites & Perimetre d'Action  |  "
            "X.2 Limites Reelles & Autocritique  |  "
            "X.3 Ameliorations Proposees", 0, 1, "L")

    def scanner_section(self, s):
        self.add_page()

        # ── Section header ────────────────────────────────────────────────────
        self.set_fill_color(*NAVY)
        self.rect(M, self.get_y(), CW, 24, "F")
        # Left teal strip
        self.set_fill_color(*TEAL)
        self.rect(M, self.get_y(), 3, 24, "F")

        hdr_y = self.get_y()
        self.set_xy(M + 7, hdr_y + 3)
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*WHITE)
        self.cell(CW - 7, 8, f"{s['num']}. {s['title']}", 0, 1, "L")
        self.set_x(M + 7)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*TEAL_LT)
        self.cell(CW - 7, 5, f"Fichier source : {s['file']}", 0, 1, "L")
        self.set_y(hdr_y + 24)
        self.ln(5)

        # ── Description ───────────────────────────────────────────────────────
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*DARK)
        self.multi_cell(CW, 5, s["desc"], 0, "J")
        self.ln(5)

        # ── 1. Capacites ──────────────────────────────────────────────────────
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*TEAL)
        self.cell(CW, 7, f"{s['num']}.1  Capacites et Perimetre d'Action", 0, 1, "L")
        self.hline()
        self.ln(3)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*GRAY)
        self.cell(CW, 5,
            "Ce que le scanner fait actuellement en production :", 0, 1, "L")
        self.ln(2)
        w1, w2 = 50, CW - 50
        self.draw_table(
            ["Fonctionnalite", "Detail de l'analyse"],
            list(s["caps"]),
            [w1, w2],
        )

        # ── 2. Limites ────────────────────────────────────────────────────────
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*TEAL)
        self.cell(CW, 7, f"{s['num']}.2  Limites Reelles et Autocritique", 0, 1, "L")
        self.hline()
        self.ln(3)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*GRAY)
        self.cell(CW, 5,
            "Ce que le scanner ne fait PAS et pourquoi :", 0, 1, "L")
        self.ln(2)
        self.draw_table(
            ["Limite (Ce qu'il ne fait pas)", "Explication technique"],
            list(s["limits"]),
            [60, CW - 60],
        )

        # ── 3. Ameliorations ──────────────────────────────────────────────────
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*TEAL)
        self.cell(CW, 7, f"{s['num']}.3  Ameliorations Proposees pour l'Architecture Cible", 0, 1, "L")
        self.hline()
        self.ln(3)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*GRAY)
        self.cell(CW, 5,
            "Axes de R&D concrets pour depasser les limites actuelles :", 0, 1, "L")
        self.ln(2)
        self.draw_table(
            ["Axe d'Amelioration", "Description Technologique / Impact"],
            list(s["amels"]),
            [55, CW - 55],
        )


def generate():
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=25)
    pdf.set_margins(M, M, M)

    pdf.cover_page()
    pdf.toc_page()

    for scanner in SCANNERS:
        pdf.scanner_section(scanner)

    out = "HexaGuard_Manuel_Analytique_Scanners_V4.pdf"
    pdf.output(out)
    print(f"[OK] Generated: {out}")
    print(f"[OK] Pages: {pdf.page}")


if __name__ == "__main__":
    generate()
