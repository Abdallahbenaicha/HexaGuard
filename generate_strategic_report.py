# -*- coding: utf-8 -*-
"""SecurAX Strategic Business Report 2026 — PDF Generator"""

from fpdf import FPDF
import os

# ── Palette ──────────────────────────────────────────────────────────────────
NAVY    = (10,  25,  50)
TEAL    = (0,  150, 180)
TEAL_LT = (0,  190, 220)
WHITE   = (255, 255, 255)
DARK    = (20,  20,  30)
GRAY    = (100, 100, 110)
GOLD    = (200, 160,  30)
GREEN   = (30,  160,  80)
RED     = (180,  40,  40)
ORANGE  = (200, 100,  20)
ROW_A   = (245, 249, 254)
ROW_B   = (255, 255, 255)
WARN    = (255, 245, 220)
SUCCESS = (220, 245, 230)
DANGER  = (250, 225, 225)

M  = 14
PW = 210
PH = 297
CW = PW - 2 * M  # 182 mm


class PDF(FPDF):

    _TRANS = str.maketrans({
        0x2014: ' - ', 0x2013: ' - ', 0x2022: '*',
        0x2192: '->', 0x2019: "'", 0x2018: "'",
        0x201d: '"', 0x201c: '"', 0x00b7: '.',
        0x2026: '...', 0x20ac: 'EUR', 0x00a0: ' ',
        0x2264: '<=', 0x2265: '>=',
        0x0153: 'oe', 0x0152: 'OE', 0x00e6: 'ae', 0x00c6: 'AE',
        0x00fe: 'th', 0x00f0: 'd', 0x0141: 'L', 0x0142: 'l',
    })

    def normalize_text(self, text):
        import unicodedata
        text = text.translate(self._TRANS)
        out = []
        for ch in text:
            try:
                ch.encode('latin-1')
                out.append(ch)
            except UnicodeEncodeError:
                nkfd = unicodedata.normalize('NFKD', ch)
                ascii_ch = nkfd.encode('ascii', errors='ignore').decode('ascii')
                out.append(ascii_ch or '?')
        return super().normalize_text(''.join(out))

    def footer(self):
        self.set_y(-12)
        self.set_draw_color(*TEAL)
        self.set_line_width(0.4)
        self.line(M, self.get_y(), PW - M, self.get_y())
        self.set_y(-10)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*GRAY)
        self.cell(CW // 2, 5, "SecurAX — Rapport Stratégique 2026", align="L")
        self.cell(CW // 2, 5, f"Page {self.page_no()}", align="R")

    def _fill(self, r, g, b):
        self.set_fill_color(r, g, b)

    def hline(self, y=None, color=TEAL, w=0.5):
        if y is None:
            y = self.get_y()
        self.set_draw_color(*color)
        self.set_line_width(w)
        self.line(M, y, PW - M, y)

    def section_title(self, num, title, color=NAVY):
        self.ln(4)
        self._fill(*color)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 12)
        self.cell(CW, 8, f"  {num}. {title}", fill=True, ln=True)
        self.ln(3)
        self.set_text_color(*DARK)

    def sub_title(self, title, color=TEAL):
        self.ln(2)
        self.set_text_color(*color)
        self.set_font("Helvetica", "B", 10)
        self.cell(CW, 6, title, ln=True)
        self.set_draw_color(*color)
        self.set_line_width(0.3)
        self.line(M, self.get_y(), M + 80, self.get_y())
        self.ln(2)
        self.set_text_color(*DARK)

    def body(self, text, size=8.5):
        self.set_font("Helvetica", "", size)
        self.set_text_color(*DARK)
        self.multi_cell(CW, 5, text)
        self.ln(1)

    def bullet(self, items, color=TEAL):
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*DARK)
        for item in items:
            self.set_x(M)
            self.set_fill_color(*color)
            cx = self.get_x()
            cy = self.get_y() + 2
            self.ellipse(cx, cy, 1.5, 1.5, "F")
            self.set_x(M + 4)
            self.multi_cell(CW - 4, 5, item)
        self.ln(1)

    def _row_h(self, cols, widths, size=8):
        self.set_font("Helvetica", "", size)
        max_h = 5
        for text, w in zip(cols, widths):
            lines = self.multi_cell(w - 2, 4.5, text, dry_run=True, output="LINES")
            h = max(5, len(lines) * 4.5 + 2)
            max_h = max(max_h, h)
        return max_h

    def table(self, headers, rows, widths=None, header_color=NAVY, row_colors=(ROW_A, ROW_B)):
        if widths is None:
            per = CW // len(headers)
            widths = [per] * len(headers)

        # Header
        self._fill(*header_color)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 8)
        x0 = M
        for h, w in zip(headers, widths):
            self.set_xy(x0, self.get_y())
            self.cell(w, 6, h, fill=True, border=0)
            x0 += w
        self.ln(6)

        # Rows
        self.set_text_color(*DARK)
        for i, row in enumerate(rows):
            rh = self._row_h(row, widths)
            if self.get_y() + rh > PH - 20:
                self.add_page()
            self._fill(*row_colors[i % 2])
            x0 = M
            y0 = self.get_y()
            for cell, w in zip(row, widths):
                self.set_xy(x0, y0)
                self.set_fill_color(*row_colors[i % 2])
                self.multi_cell(w, 4.5, cell, fill=True, border=0)
                x0 += w
            self.set_y(y0 + rh)
        self.ln(3)

    def kpi_row(self, items):
        """items = list of (label, value, color)"""
        n = len(items)
        w = CW / n
        y0 = self.get_y()
        x0 = M
        for label, value, color in items:
            self._fill(*color)
            self.set_xy(x0, y0)
            self.rect(x0, y0, w - 2, 16, "F")
            self.set_xy(x0 + 1, y0 + 1)
            self.set_font("Helvetica", "B", 14)
            self.set_text_color(*WHITE)
            self.cell(w - 4, 8, value, align="C")
            self.set_xy(x0 + 1, y0 + 9)
            self.set_font("Helvetica", "", 7)
            self.cell(w - 4, 5, label, align="C")
            x0 += w
        self.set_y(y0 + 19)
        self.set_text_color(*DARK)

    def callout(self, text, color=TEAL, bg=ROW_A):
        self.ln(2)
        self._fill(*bg)
        self.set_draw_color(*color)
        self.set_line_width(1)
        y0 = self.get_y()
        self.set_x(M)
        self.multi_cell(CW, 5, text, fill=True, border=0)
        h = self.get_y() - y0
        self.line(M, y0, M, y0 + h)
        self.set_line_width(0.4)
        self.ln(2)


# ── Cover Page ────────────────────────────────────────────────────────────────
def cover(pdf):
    pdf.add_page()
    # Top navy bar
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, PW, 60, "F")

    pdf.set_xy(M, 12)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*WHITE)
    pdf.cell(CW, 12, "SecurAX", ln=True, align="L")

    pdf.set_xy(M, 26)
    pdf.set_font("Helvetica", "", 13)
    pdf.set_text_color(*TEAL_LT)
    pdf.cell(CW, 8, "Rapport Strategique 2026", ln=True)

    pdf.set_xy(M, 36)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(180, 200, 220)
    pdf.cell(CW, 6, "Plateforme SaaS de Cybersecurite — Analyse, Strategie et Roadmap", ln=True)

    pdf.set_xy(M, 48)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(160, 190, 210)
    pdf.cell(CW, 5, "Version 1.0 — Juin 2026 — Confidentiel", ln=True)

    # Teal accent bar
    pdf.set_fill_color(*TEAL)
    pdf.rect(0, 60, PW, 3, "F")

    # Philosophy box
    pdf.set_y(72)
    pdf.set_fill_color(*ROW_A)
    pdf.set_x(M)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*TEAL)
    pdf.multi_cell(CW, 6,
        "Philosophie : Critiquer honnêtement → Clarifier les limites → Proposer des améliorations concrètes.\n"
        "Ce rapport s'applique la même rigueur que SecurAX applique à ses cibles.", fill=True)

    # Summary KPI
    pdf.set_y(96)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*DARK)
    pdf.cell(CW, 6, "Vue d'ensemble", ln=True)
    pdf.hline()
    pdf.ln(3)
    pdf.kpi_row([
        ("Scanners actifs", "11", TEAL),
        ("Marché cible", "Algérie+MENA", NAVY),
        ("Objectif 12 mois", "500k DZD/m", GREEN),
        ("Statut MVP", "Operationnel", GOLD),
    ])

    # TOC preview
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*DARK)
    pdf.cell(CW, 6, "Sommaire", ln=True)
    pdf.hline()
    pdf.ln(3)

    toc = [
        ("Partie 1", "Audit Critique du Produit", "3"),
        ("Partie 2", "Analyse du Marche (Algerie, MENA, International)", "7"),
        ("Partie 3", "Analyse de la Concurrence", "11"),
        ("Partie 4", "Monetisation — Premier Client, 100€, 1000€", "14"),
        ("Partie 5", "Previsions Financieres (3 scenarios)", "18"),
        ("Partie 6", "Roadmap Produit 12 mois", "21"),
        ("Partie 7", "Ameliorations Produit Prioritaires", "24"),
        ("Partie 8", "Ressources, Outils et Acquisition", "27"),
        ("Partie 9", "Annexes — Scripts, Tarifs, KPI", "30"),
    ]
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*DARK)
    for code, title, page in toc:
        pdf.set_x(M)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*TEAL)
        pdf.cell(20, 6, code)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*DARK)
        pdf.cell(130, 6, title)
        pdf.set_text_color(*GRAY)
        pdf.cell(30, 6, f"p. {page}", align="R", ln=True)

    # Bottom
    pdf.set_y(-35)
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, pdf.get_y(), PW, 35, "F")
    pdf.set_xy(M, pdf.get_y() + 5)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(160, 190, 210)
    pdf.multi_cell(CW, 5,
        "Auteur: Équipe SecurAX | innovation.team.dz@gmail.com\n"
        "Ce document est strictement confidentiel. Toute reproduction est interdite sans autorisation.")


# ── PARTIE 1 — Audit Critique ─────────────────────────────────────────────────
def partie1(pdf):
    pdf.add_page()
    pdf.section_title("PARTIE 1", "AUDIT CRITIQUE DU PRODUIT")

    pdf.sub_title("1.1 — Description du Produit")
    pdf.body(
        "SecurAX est une plateforme web de cybersécurité développée en Python/Flask (backend) et React (frontend), "
        "avec une base de données MySQL. Elle intègre 11 scanners de sécurité couvrant les couches applicatives, "
        "réseau, infrastructure et services spécialisés. Le produit est en phase MVP opérationnel."
    )

    pdf.sub_title("1.2 — Forces Réelles")
    pdf.bullet([
        "11 scanners actifs couvrant Web, DAST, SAST, Réseau, SSL/TLS, Dépendances, Config serveur, Serveur externe, Docker, DNS/Email, WordPress.",
        "Architecture modulaire Blueprint Flask — chaque scanner est un module indépendant, extensible.",
        "Interface React moderne avec tableau de bord, historique des scans, gestion des utilisateurs (admin/user).",
        "Rapport de vulnérabilités structuré par niveau de sévérité (critique, haute, moyenne, faible).",
        "Scan en arrière-plan (background tasks) — l'utilisateur n'attend pas la fin du scan.",
        "Système d'authentification JWT avec gestion des rôles.",
        "Différenciation locale : aucun concurrent direct en Algérie proposant autant de scanners intégrés.",
        "Coût d'infrastructure potentiellement très bas (VPS Linux ~$5/mois suffit pour commencer).",
    ])

    pdf.sub_title("1.3 — Faiblesses Techniques (Honnêtes)")
    pdf.bullet([
        "Pas d'API publique documentée (Swagger/OpenAPI) — impossible d'intégrer SecurAX dans une pipeline CI/CD externe.",
        "Pas de multi-tenant : un seul espace de données partagé — impossible de vendre à plusieurs organisations simultanément de façon isolée.",
        "Pas de monitoring produit : aucune alerte si un scanner échoue silencieusement, aucune métrique d'usage.",
        "Pas de white-label : impossible de revendre la plateforme à une agence qui veut la présenter à ses clients sous son propre nom.",
        "Qualité des détections variable : certains scanners s'appuient sur des heuristiques basiques (ex. vérification de headers HTTP) plutôt que sur des CVE actualisés.",
        "Pas de tests automatisés (unit/integration) — chaque modification risque des régressions non détectées.",
        "Dépendance à PythonAnywhere pour le déploiement actuel — limite les performances et l'accès réseau (Nmap bloqué).",
        "Scanner SAST limité à Python — ne couvre pas JS, PHP, Java qui sont très répandus dans les cibles algériennes.",
        "Aucun mécanisme de mise à jour automatique des signatures/CVE.",
    ])

    pdf.sub_title("1.4 — Limites Commerciales")
    pdf.bullet([
        "Pas de page de vente ni de landing page : impossible d'acquérir un client sans appel téléphonique direct.",
        "Aucune démonstration publique disponible (démo sandbox) — frein majeur à la conversion.",
        "Pas de tarification affichée publiquement — crée une friction à l'achat.",
        "Pas de preuve sociale : 0 client payant, 0 témoignage, 0 case study — handicap pour la crédibilité.",
        "Pas de certifications (ISO 27001, OWASP Top 10 compliance) — limitant pour les grands comptes.",
        "Équipe non diversifiée : compétences techniques fortes mais pas de profil commercial/marketing dédié.",
    ])

    pdf.sub_title("1.5 — Score Réaliste du Produit")
    pdf.table(
        ["Critère", "Score /10", "Commentaire"],
        [
            ["Couverture technique (11 scanners)", "7/10", "Bonne largeur, profondeur à améliorer"],
            ["Qualité des détections", "5/10", "Heuristiques OK, CVE en temps réel manquant"],
            ["UX/Interface", "6/10", "Fonctionnel, design propre mais pas premium"],
            ["Architecture code", "6/10", "Modulaire, mais pas de tests, pas de docs API"],
            ["Readiness commerciale", "3/10", "MVP technique, mais 0 infrastructure de vente"],
            ["Différenciation marché local", "8/10", "Quasi-unique en Algérie avec cette amplitude"],
            ["Scalabilité SaaS", "4/10", "Mono-tenant actuel, refonte nécessaire pour SaaS"],
            ["Documentation", "4/10", "Interne existe, pas de docs publiques client"],
        ],
        widths=[70, 25, 87],
    )

    pdf.callout(
        "Verdict : SecurAX est un MVP technique solide avec un différenciateur local fort. "
        "L'urgence n'est PAS d'ajouter des fonctionnalités — c'est de vendre le produit existant "
        "et de collecter du feedback réel de vrais clients payants.",
        color=GOLD, bg=WARN
    )

    pdf.sub_title("1.6 — Ce Qu'Il Faut Arrêter de Faire")
    pdf.bullet([
        "Arrêter d'ajouter des scanners sans valider commercialement les existants.",
        "Arrêter de perfectionner l'UI sans avoir de premier client.",
        "Arrêter de comparer SecurAX à Nessus ou Qualys — ce n'est pas la cible à court terme.",
        "Arrêter d'attendre que le produit soit 'parfait' avant de démarcher.",
        "Arrêter de travailler sur PythonAnywhere — migrer vers un VPS dès le premier revenu.",
    ])

    pdf.sub_title("1.7 — Ce Qu'Il Faut Construire (Priorités Absolues)")
    pdf.table(
        ["Priorité", "Action", "Impact", "Délai"],
        [
            ["P1 CRITIQUE", "Landing page + formulaire de contact", "Permet d'être trouvé", "1 semaine"],
            ["P1 CRITIQUE", "Démo sandbox publique (URL fixe)", "Convertit les visiteurs", "1 semaine"],
            ["P1 CRITIQUE", "Décrocher le 1er client payant", "Valide le modèle", "30 jours"],
            ["P2 HAUTE", "API REST publique documentée (Swagger)", "Ouvre le marché dev/CI-CD", "60 jours"],
            ["P2 HAUTE", "Multi-tenant isolation", "Permet vente SaaS", "90 jours"],
            ["P3 MOYENNE", "Mise à jour CVE automatique (OSV/NVD)", "Crédibilité technique", "90 jours"],
            ["P3 MOYENNE", "Tests unitaires critiques + CI GitHub Actions", "Stabilité produit", "60 jours"],
            ["P4 LONG", "White-label / rebranding", "Partenariats agences", "6 mois"],
            ["P4 LONG", "Certifications OWASP/ISO compliance report", "Grands comptes", "12 mois"],
        ],
        widths=[30, 65, 50, 37],
    )


# ── PARTIE 2 — Marché ─────────────────────────────────────────────────────────
def partie2(pdf):
    pdf.add_page()
    pdf.section_title("PARTIE 2", "ANALYSE DU MARCHE")

    # Algérie
    pdf.sub_title("2.1 — Marché Algérien (Scénario A)")
    pdf.body(
        "L'Algérie compte plus de 200 000 PME enregistrées, dont environ 15 000 ont une présence web active "
        "significative. La cybersécurité y est sous-investie : moins de 2% des PME algériennes disposent d'un "
        "outil de scan de sécurité. Les incidents de sécurité augmentent (defacement, ransomware local, phishing). "
        "La digitalisation accélérée post-COVID crée une demande non satisfaite."
    )

    pdf.table(
        ["Segment", "Volume estimé", "Budget sécurité/an", "Potentiel SecurAX"],
        [
            ["PME (10-200 emp.)", "~15 000 actives web", "50 000 – 300 000 DZD", "FORT — cœur de cible"],
            ["Agences web locales", "~2 000 agences", "Variable (revente)", "FORT — partenariat"],
            ["Écoles / Universités", "~100 institutions", "Budget public limité", "MOYEN — institutional"],
            ["Startups Tech", "~500 startups", "Bootstrap budget", "MOYEN — early adopters"],
            ["ETI (200+ emp.)", "~1 500 entreprises", "500k – 2M DZD", "MOYEN — cycle long"],
            ["Administration publique", "Ministères, wilayas", "Budget public", "FAIBLE — bureaucratie"],
        ],
        widths=[45, 40, 50, 47],
    )

    pdf.sub_title("Tarification recommandée en DZD")
    pdf.table(
        ["Offre", "Prix mensuel", "Prix annuel (-20%)", "Inclus"],
        [
            ["Starter (PME)", "5 000 DZD", "48 000 DZD", "3 scans/mois, rapport PDF, 1 utilisateur"],
            ["Pro (PME+)", "12 000 DZD", "115 000 DZD", "10 scans/mois, tous scanners, 3 utilisateurs"],
            ["Business (ETI)", "25 000 DZD", "240 000 DZD", "Illimité, API, support prioritaire, 10 users"],
            ["Agence (revendeur)", "35 000 DZD", "336 000 DZD", "White-label, clients multiples, formation"],
            ["Audit ponctuel", "15 000 DZD/scan", "—", "Rapport signé, recommandations, SLA 48h"],
        ],
        widths=[35, 30, 35, 82],
    )

    pdf.callout(
        "Objectif Algérie 12 mois : 20 clients Starter/Pro = 240 000 DZD/mois + 5 audits ponctuels "
        "= ~315 000 DZD/mois. Atteignable en partant de zéro avec une approche B2B directe.",
        color=GREEN, bg=SUCCESS
    )

    # MENA
    pdf.add_page()
    pdf.sub_title("2.2 — Marché MENA (Scénario B)")
    pdf.body(
        "Le marché MENA de la cybersécurité est estimé à $5,4 milliards en 2025 et croît à 14% par an. "
        "Les PME MENA sont sous-équipées. Les plateformes Khamsat et Mostaql permettent une acquisition "
        "client initiale en arabe sans infrastructure commerciale locale."
    )

    pdf.table(
        ["Pays", "Opportunité", "Canal d'entrée", "Prix marché"],
        [
            ["Maroc", "Forte tech startup scene, francophone", "LinkedIn, Mostaql", "$50–150/mois"],
            ["Tunisie", "Agences web nombreuses, IT développé", "LinkedIn, partenariats", "$40–120/mois"],
            ["Égypte", "Marché le plus grand (100M hab.)", "Khamsat, Mostaql", "$30–100/mois"],
            ["Arabie Saoudite", "Vision 2030, budget cyber élevé", "B2B direct, partenaires", "$200–500/mois"],
            ["EAU", "Hub tech, standards internationaux", "Partenaires certifiés", "$300–800/mois"],
            ["Jordanie", "Écosystème tech développé", "LinkedIn, communautés", "$50–150/mois"],
        ],
        widths=[28, 55, 45, 54],
    )

    pdf.sub_title("Canaux MENA prioritaires")
    pdf.bullet([
        "Khamsat.com : marketplace arabe pour services freelance — proposer des audits sécurité comme service ponctuel.",
        "Mostaql.com : plateforme arabe B2B — créer un profil prestataire avec exemples de rapports.",
        "LinkedIn MENA : contenus en arabe et anglais sur la cybersécurité locale — génère des inbounds.",
        "Groupes WhatsApp/Telegram de CTO arabes : présence organique, partage de cas d'usage.",
        "Partenariats avec agences web au Maroc et Tunisie — ils revendent SecurAX à leurs clients.",
    ])

    pdf.sub_title("Tarification MENA (USD)")
    pdf.table(
        ["Plan", "Prix USD/mois", "Équivalent DZD", "Cible"],
        [
            ["Starter", "$49", "~6 800 DZD", "Freelances, micro-entreprises"],
            ["Pro", "$99", "~13 800 DZD", "PME, agences"],
            ["Business", "$199", "~27 700 DZD", "ETI, équipes IT"],
            ["Enterprise", "$499", "~69 400 DZD", "Grandes entreprises, API illimitée"],
            ["Audit Service", "$150/scan", "~20 800 DZD", "Audit ponctuel avec rapport"],
        ],
        widths=[30, 30, 35, 87],
    )

    # International
    pdf.add_page()
    pdf.sub_title("2.3 — Marché International (Scénario C — SaaS Global)")
    pdf.body(
        "Le marché international de la cybersécurité SaaS est saturé par des acteurs bien financés. "
        "SecurAX ne peut pas concurrencer Nessus ou Qualys de front. La stratégie internationale doit "
        "se baser sur une niche claire : 'Security Scanner for Developers — Affordable, Fast, API-First'. "
        "Product Hunt, GitHub, Hacker News et IndieHackers sont les canaux à faible coût pour tester cette thèse."
    )

    pdf.table(
        ["Canal", "Stratégie", "Investissement", "Horizon"],
        [
            ["Product Hunt", "Launch officiel avec démo", "0€ (temps uniquement)", "Mois 6–9"],
            ["GitHub", "Client CLI open source + repo actif", "0€", "Mois 3–6"],
            ["Hacker News", "Show HN avec story fondateur + démo", "0€", "Mois 6"],
            ["IndieHackers", "Documenter le parcours fondateur", "0€", "En continu"],
            ["AppSumo", "Lifetime deal pour user acquisition", "Commission 30%", "Mois 9–12"],
            ["G2 / Capterra", "Listing gratuit + reviews", "0€", "Mois 6"],
        ],
        widths=[35, 65, 45, 37],
    )

    pdf.sub_title("Prérequis pour l'international")
    pdf.bullet([
        "Interface entièrement en anglais (current: partiellement).",
        "API REST publique documentée (Swagger/OpenAPI) — obligatoire.",
        "Multi-tenant : isolation des données entre clients.",
        "Paiement Stripe/Paddle (accepte DZ via Paddle — pas de compte Stripe DZ direct).",
        "SLA et conditions de service en anglais.",
        "Hébergement EU/US avec uptime >99.5% et SSL valide.",
        "Page de statut publique (statuspage.io ou équivalent).",
    ])

    pdf.sub_title("2.4 — SWOT Global")
    pdf.table(
        ["", "Forces (S)", "Faiblesses (W)"],
        [
            ["Internes",
             "• 11 scanners intégrés\n• Architecture propre\n• Quasi-unique en Algérie\n• Coût opérationnel bas\n• Fondateurs techniques",
             "• 0 client payant\n• Pas d'API publique\n• Pas de multi-tenant\n• Pas de marketing\n• Pas de certification"],
        ],
        widths=[20, 81, 81],
    )
    pdf.table(
        ["", "Opportunités (O)", "Menaces (T)"],
        [
            ["Externes",
             "• Marché algérien non équipé\n• Digitalisation PME accélérée\n• Réglementation cyber naissante\n• MENA sous-servi\n• AppSumo pour traction rapide",
             "• Nessus Essentials gratuit\n• OpenVAS gratuit\n• Snyk freemium\n• Budget client limité DZ\n• Concurrents bien financés"],
        ],
        widths=[20, 81, 81],
    )


# ── PARTIE 3 — Concurrence ────────────────────────────────────────────────────
def partie3(pdf):
    pdf.add_page()
    pdf.section_title("PARTIE 3", "ANALYSE DE LA CONCURRENCE")

    pdf.sub_title("3.1 — Tableau Comparatif Global")
    pdf.table(
        ["Produit", "Prix", "Cible", "Scanners", "Points forts", "Faiblesse vs SecurAX"],
        [
            ["Nessus Pro", "$3 590/an", "Enterprise", "100+", "CVE en temps réel, très mature", "Trop cher pour PME algériennes, anglais uniquement"],
            ["Nessus Essentials", "Gratuit", "Personnel", "16 IP max", "Notoriété Tenable", "Très limité, non commercial"],
            ["Snyk", "Freemium/$98+/mois", "Développeurs", "Dépendances, SAST", "Intégration GitHub, IDE", "Pas de scanner réseau/web complet"],
            ["Invicti (Acunetix)", "$4 500+/an", "Enterprise", "Web, DAST", "Très précis, peu de faux positifs", "Inaccessible budget PME"],
            ["SonarQube", "Gratuit + $150+/mois", "Dev teams", "SAST uniquement", "Open source, CI/CD natif", "Pas de scanner réseau/infra"],
            ["Qualys", "$3 000+/an", "Enterprise", "Multi", "Cloud-based, compliance", "Complexe, très cher"],
            ["OpenVAS", "Gratuit", "Tech avancé", "Réseau", "Open source, complet", "Installation complexe, pas de SaaS"],
            ["SecurAX", "5 000–25 000 DZD/m", "PME/Dev", "11", "Local, français/arabe, tout-en-un", "Moins mature, moins de CVE"],
        ],
        widths=[28, 27, 22, 18, 50, 57],
    )

    pdf.sub_title("3.2 — Positionnement Stratégique de SecurAX")
    pdf.callout(
        "SecurAX n'est PAS un concurrent de Nessus. SecurAX est le 'Canva de la cybersécurité' : "
        "accessible, tout-en-un, local, sans expertise requise. La cible est la PME algérienne "
        "qui n'a PAS de RSSI et qui ne peut PAS payer $3 000/an.",
        color=TEAL, bg=ROW_A
    )

    pdf.table(
        ["Axe de positionnement", "SecurAX", "Concurrents enterprise"],
        [
            ["Prix", "5 000–25 000 DZD/mois", "$3 000–$5 000+/an"],
            ["Langue", "Français + Arabe (en cours)", "Anglais uniquement"],
            ["Complexité installation", "SaaS web — 0 installation", "Agents, licences, config"],
            ["Scanners intégrés", "11 dans une interface", "Outils séparés ou mono-scanner"],
            ["Support local", "Algérie, fuseau horaire local", "Support US/EU, tickets"],
            ["Courbe d'apprentissage", "Faible — interface intuitive", "Formation requise"],
            ["Conformité PDPO Algérie", "Connaît le contexte local", "Généralement ignoré"],
        ],
        widths=[55, 65, 62],
        header_color=TEAL,
    )

    pdf.sub_title("3.3 — Analyse par Concurrent")

    competitors = [
        {
            "name": "Nessus (Tenable)",
            "threat": "Faible à court terme",
            "reason": "Trop cher ($3 590/an), interface en anglais, complexe à configurer. "
                      "Aucune PME algérienne ne l'utilise sans RSSI dédié. SecurAX s'y prend "
                      "en prix et simplicité. Menace si Nessus sort une offre PME francophone.",
            "response": "Ne pas comparer à Nessus. Positionner SecurAX comme 'alternative accessible'."
        },
        {
            "name": "Snyk",
            "threat": "Moyenne",
            "reason": "Snyk est fort sur les dépendances et SAST pour développeurs. "
                      "Son freemium est attractif. Concurrent direct sur la partie scanner de dépendances.",
            "response": "Différencier sur la couverture globale (réseau + infra + web) que Snyk n'a pas."
        },
        {
            "name": "OpenVAS / Greenbone",
            "threat": "Moyenne (technique)",
            "reason": "Gratuit, puissant pour le réseau. Mais installation complexe, pas de SaaS, "
                      "pas de rapport client propre. Utilisé par des techniciens, pas des dirigeants PME.",
            "response": "SecurAX propose le rapport prêt à présenter au client/direction — OpenVAS ne le fait pas."
        },
        {
            "name": "SonarQube",
            "threat": "Faible",
            "reason": "SAST uniquement, orienté développeurs. Complémentaire plutôt que concurrent.",
            "response": "Intégration possible : SecurAX peut appeler SonarQube en arrière-plan (valeur ajoutée)."
        },
    ]

    for c in competitors:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*TEAL)
        pdf.cell(CW, 6, f"→ {c['name']} — Menace : {c['threat']}", ln=True)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*DARK)
        pdf.multi_cell(CW, 5, c["reason"])
        pdf.set_font("Helvetica", "I", 8.5)
        pdf.set_text_color(*GREEN)
        pdf.multi_cell(CW, 5, f"Réponse : {c['response']}")
        pdf.ln(2)


# ── PARTIE 4 — Monétisation ───────────────────────────────────────────────────
def partie4(pdf):
    pdf.add_page()
    pdf.section_title("PARTIE 4", "MONETISATION — PREMIER CLIENT, 100€, 1000€")

    pdf.sub_title("4.1 — Stratégie du Premier Client (Objectif : Semaine 1–4)")
    pdf.callout(
        "Le premier client ne viendra pas de lui-même. Il faut l'aller chercher. "
        "Votre réseau proche est la source la plus rapide et la moins coûteuse. "
        "Visez un client à 5 000–15 000 DZD pour valider le modèle, même à prix réduit.",
        color=GOLD, bg=WARN
    )

    pdf.sub_title("Plan d'action — Premier client en 30 jours")
    pdf.table(
        ["Jour", "Action concrète", "Livrable"],
        [
            ["J1–J3", "Lister 30 contacts : amis entrepreneurs, ex-collègues, famille avec business", "Liste Google Sheet"],
            ["J3–J5", "Préparer démo de 15 min + rapport d'exemple (URL fictive ou leur propre site)", "Slides + rapport PDF"],
            ["J5–J15", "Contacter 30 personnes par WhatsApp, LinkedIn, téléphone", "10 réponses minimum"],
            ["J10–J20", "Proposer audit GRATUIT pour les 2 premiers clients, payant ensuite", "2 rapports livrés"],
            ["J15–J30", "Convertir 1 des 2 en client payant mensuel (5 000 DZD min.)", "Virement reçu"],
            ["J30", "Demander 2 recommandations au premier client", "2 nouveaux contacts"],
        ],
        widths=[18, 100, 64],
    )

    pdf.sub_title("Script WhatsApp — Premier contact")
    pdf.set_fill_color(*ROW_A)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(*DARK)
    pdf.set_x(M)
    pdf.multi_cell(CW, 5,
        'Salam [Prénom],\n\n'
        'Je travaille sur SecurAX, une plateforme de cybersécurité pour PME algériennes. '
        'Je peux analyser la sécurité de ton site web gratuitement et te donner un rapport complet '
        'en 24h (failles, recommandations, score de sécurité).\n\n'
        'Ça t\'intéresse ? Donne-moi juste ton URL.',
        fill=True
    )
    pdf.ln(3)

    pdf.sub_title("4.2 — Premier 100€ (≈ 14 000 DZD)")
    pdf.body("Trois voies pour atteindre 100€ de revenu :")
    pdf.table(
        ["Voie", "Comment", "Délai réaliste"],
        [
            ["Voie A — Audit ponctuel", "1 audit à 15 000 DZD pour une PME locale", "Semaine 2–3"],
            ["Voie B — Abonnement mensuel", "2 clients Starter à 7 000 DZD chacun", "Semaine 3–4"],
            ["Voie C — Khamsat/Mostaql", "Service d'audit sur marketplace arabe à $30–50 l'unité", "Semaine 1–2"],
        ],
        widths=[35, 100, 47],
    )

    pdf.callout(
        "Recommandation : commencer par Khamsat.com en parallèle. "
        "Créez un service 'Audit sécurité site web — Rapport PDF professionnel — 48h' à 3 000 DZD ($20). "
        "Les premières ventes valident la demande et génèrent des avis.",
        color=TEAL, bg=ROW_A
    )

    pdf.sub_title("4.3 — Premier 1 000€ (≈ 140 000 DZD)")
    pdf.body("Le seuil de 1 000€ = la preuve que le modèle est reproductible. Voici comment l'atteindre :")
    pdf.table(
        ["Combinaison", "Détail", "Total"],
        [
            ["5 abonnements Pro", "5 × 12 000 DZD/mois", "60 000 DZD"],
            ["5 audits ponctuels", "5 × 15 000 DZD", "75 000 DZD"],
            ["3 agences partenaires", "3 × 8 000 DZD (commission)", "24 000 DZD"],
            ["TOTAL mois 3", "—", "159 000 DZD ≈ 1 100€"],
        ],
        widths=[50, 80, 52],
    )

    pdf.sub_title("4.4 — Modèle SaaS — Plans et Tarification Finale")
    pdf.table(
        ["Plan", "Prix/mois (DZD)", "Prix/an (DZD)", "Scans", "Users", "API", "Support"],
        [
            ["Free (démo)", "0", "—", "1 scan complet", "1", "Non", "Email 72h"],
            ["Starter", "5 000", "48 000", "5/mois", "1", "Non", "Email 48h"],
            ["Pro", "12 000", "115 000", "20/mois", "3", "Non", "Chat 24h"],
            ["Business", "25 000", "240 000", "Illimité", "10", "Oui", "Téléphone"],
            ["Agency", "40 000", "384 000", "Illimité", "Illimité", "Oui+WL", "Dédié"],
        ],
        widths=[25, 30, 28, 22, 18, 18, 41],
    )

    pdf.sub_title("4.5 — Services Complémentaires à Vendre")
    pdf.table(
        ["Service", "Prix", "Fréquence", "Description"],
        [
            ["Audit initial complet", "25 000 DZD", "Ponctuel", "Scan de toute l'infrastructure + rapport signé"],
            ["Rapport de conformité", "15 000 DZD", "Trimestriel", "Rapport OWASP Top 10 prêt pour audit"],
            ["Formation sécurité", "30 000 DZD", "Ponctuel", "Session 4h pour équipe IT ou direction"],
            ["Pentest assisté", "50 000–150 000 DZD", "Ponctuel", "Tests avancés avec intervention manuelle"],
            ["Surveillance mensuelle", "8 000 DZD/mois", "Récurrent", "Scan auto + alerte si nouvelle faille détectée"],
            ["Intégration CI/CD", "20 000 DZD", "Ponctuel", "Mise en place SecurAX dans pipeline dev"],
        ],
        widths=[40, 30, 28, 84],
    )


# ── PARTIE 5 — Prévisions Financières ─────────────────────────────────────────
def partie5(pdf):
    pdf.add_page()
    pdf.section_title("PARTIE 5", "PREVISIONS FINANCIERES — 3 SCENARIOS")

    pdf.sub_title("5.1 — Hypothèses de Base")
    pdf.table(
        ["Poste", "Coût estimé", "Notes"],
        [
            ["VPS (Hetzner/DigitalOcean)", "1 500 DZD/mois (~$10)", "Minimum viable, migrer si >50 clients"],
            ["Domaine + SSL", "500 DZD/an", "Namecheap ou DomainAlgerie"],
            ["Email pro (Zoho/Google)", "500 DZD/mois", "Professionnel obligatoire"],
            ["Passerelle paiement", "2–3% par transaction", "Chargili Pay ou CIB en Algérie"],
            ["Marketing digital initial", "5 000 DZD/mois (optionnel)", "Boost LinkedIn, flyers"],
            ["Coût variable par scan", "~0 DZD", "Infra mutualisée — scale jusqu'à 200 scans/mois"],
            ["TOTAL coût fixe mensuel", "~2 500 DZD/mois", "Sans marketing"],
        ],
        widths=[55, 40, 87],
    )

    # Scénarios
    scenarios = [
        {
            "title": "5.2 — Scénario Pessimiste",
            "color": RED,
            "bg": DANGER,
            "hypothesis": "Acquisition difficile : 1 nouveau client/mois. Churn (résiliation) 20%/mois.",
            "rows": [
                ["Mois 1", "1 client Starter", "5 000 DZD", "2 500 DZD", "2 500 DZD"],
                ["Mois 2", "2 clients", "10 000 DZD", "2 500 DZD", "7 500 DZD"],
                ["Mois 3", "2 clients (1 churn)", "10 000 DZD", "2 500 DZD", "7 500 DZD"],
                ["Mois 6", "4 clients", "25 000 DZD", "2 500 DZD", "22 500 DZD"],
                ["Mois 12", "8 clients mixtes", "70 000 DZD", "5 000 DZD", "65 000 DZD"],
            ],
            "conclusion": "Break-even à ~Mois 1. Revenu Mois 12 : 70 000 DZD. Insuffisant pour vivre, mais prouve la viabilité."
        },
        {
            "title": "5.3 — Scénario Réaliste",
            "color": GOLD,
            "bg": WARN,
            "hypothesis": "Acquisition régulière : 3–5 nouveaux clients/mois. Churn 10%. Mix audits + abonnements.",
            "rows": [
                ["Mois 1", "2 abonnements + 2 audits", "40 000 DZD", "2 500 DZD", "37 500 DZD"],
                ["Mois 2", "5 abonnements + 3 audits", "75 000 DZD", "2 500 DZD", "72 500 DZD"],
                ["Mois 3", "8 abonnements + 4 audits", "121 000 DZD", "3 000 DZD", "118 000 DZD"],
                ["Mois 6", "18 abonnements + 5 audits", "291 000 DZD", "5 000 DZD", "286 000 DZD"],
                ["Mois 12", "40 abonnements + 8 audits", "660 000 DZD", "10 000 DZD", "650 000 DZD"],
            ],
            "conclusion": "Break-even Mois 1. Objectif 500k DZD/mois atteint vers Mois 10–11. Viable pour 2 fondateurs."
        },
        {
            "title": "5.4 — Scénario Optimiste",
            "color": GREEN,
            "bg": SUCCESS,
            "hypothesis": "Partenariat agences (x5 multiplicateur), lancement MENA mois 4, AppSumo ou Product Hunt mois 6.",
            "rows": [
                ["Mois 1", "5 abonnements + 5 audits", "100 000 DZD", "2 500 DZD", "97 500 DZD"],
                ["Mois 3", "20 abonnements + 10 audits", "390 000 DZD", "5 000 DZD", "385 000 DZD"],
                ["Mois 6", "50 abonnements + 15 audits", "975 000 DZD", "15 000 DZD", "960 000 DZD"],
                ["Mois 9", "100 abonnements mixtes", "2 000 000 DZD", "30 000 DZD", "1 970 000 DZD"],
                ["Mois 12", "200 abonnements + MENA", "4 500 000 DZD", "80 000 DZD", "4 420 000 DZD"],
            ],
            "conclusion": "Seuil 500k DZD/mois atteint à Mois 4. Nécessite embauche commerciale et migration infra à Mois 5."
        },
    ]

    for s in scenarios:
        pdf.sub_title(s["title"], color=s["color"])
        pdf.callout(f"Hypothèse : {s['hypothesis']}", color=s["color"], bg=s["bg"])
        pdf.table(
            ["Période", "Situation", "Revenu brut", "Coûts", "Profit net"],
            s["rows"],
            widths=[20, 65, 33, 27, 37],
        )
        pdf.set_font("Helvetica", "I", 8.5)
        pdf.set_text_color(*s["color"])
        pdf.multi_cell(CW, 5, f"Conclusion : {s['conclusion']}")
        pdf.ln(4)
        pdf.set_text_color(*DARK)

    pdf.sub_title("5.5 — Seuil de Rentabilité")
    pdf.table(
        ["Indicateur", "Valeur"],
        [
            ["Coûts fixes mensuels (sans salaires)", "2 500 DZD"],
            ["Coûts fixes avec 1 salaire fondateur", "50 000 DZD"],
            ["Nombre de clients Starter pour couvrir coûts fixes", "1 client à 5 000 DZD"],
            ["Nombre de clients pour 1 salaire décent (50k DZD)", "~7 clients Starter OU 3 clients Pro"],
            ["Nombre de clients pour 2 salaires (100k DZD)", "~12 Starter OU 5 Pro OU mix"],
            ["Seuil SaaS viable (500k DZD/mois)", "~42 Pro OU mix 25 Pro + 15 Starter + 5 audits"],
        ],
        widths=[110, 72],
    )


# ── PARTIE 6 — Roadmap ────────────────────────────────────────────────────────
def partie6(pdf):
    pdf.add_page()
    pdf.section_title("PARTIE 6", "ROADMAP PRODUIT 12 MOIS")

    phases = [
        {
            "label": "6.1 — Phase 0 : Maintenant → 30 jours (LANCEMENT COMMERCIAL)",
            "color": RED,
            "objective": "Objectif unique : obtenir le premier paiement réel.",
            "tasks": [
                ("CRITIQUE", "Créer une landing page simple (Carrd.co ou GitHub Pages) avec formulaire contact"),
                ("CRITIQUE", "Préparer un rapport d'exemple professionnel (scan d'un site fictif ou public)"),
                ("CRITIQUE", "Contacter 30 personnes de son réseau par WhatsApp/LinkedIn"),
                ("CRITIQUE", "Proposer 2 audits gratuits pour générer des témoignages"),
                ("CRITIQUE", "Créer un profil Khamsat avec service d'audit à 2 500–5 000 DZD"),
                ("HAUTE", "Fixer les bugs critiques UX/UI remontés lors des démos"),
                ("HAUTE", "Préparer une démo vidéo de 3 minutes (Loom ou OBS)"),
                ("MOYENNE", "Créer une page LinkedIn SecurAX avec 3 posts par semaine"),
            ]
        },
        {
            "label": "6.2 — Phase 1 : Mois 1–3 (PREMIERS REVENUS)",
            "color": GOLD,
            "objective": "Objectif : 5 clients payants, 60 000 DZD/mois, feedback produit réel.",
            "tasks": [
                ("CRITIQUE", "Migrer vers VPS Hetzner/DigitalOcean (si pas encore fait)"),
                ("CRITIQUE", "Ajouter un système de facturation simple (PDF auto-généré)"),
                ("HAUTE", "Tests unitaires sur les 3 scanners les plus utilisés"),
                ("HAUTE", "Créer une page de pricing publique sur la landing page"),
                ("HAUTE", "Mettre en place un suivi CRM simple (Notion ou Google Sheet)"),
                ("HAUTE", "Lancer le programme agences partenaires (contacter 10 agences web locales)"),
                ("MOYENNE", "Implémenter le scanner SSL avec SSLyze (amélioration qualité)"),
                ("MOYENNE", "Ajouter scan différentiel (comparer 2 scans dans le temps)"),
            ]
        },
        {
            "label": "6.3 — Phase 2 : Mois 3–6 (SCALABILITE)",
            "color": TEAL,
            "objective": "Objectif : 20 clients, 250 000 DZD/mois, API disponible, expansion MENA.",
            "tasks": [
                ("CRITIQUE", "API REST publique avec clés API par utilisateur (Swagger docs)"),
                ("CRITIQUE", "Multi-tenant : isolation complète des données entre clients"),
                ("CRITIQUE", "Paiement en ligne automatisé (Chargili Pay ou CIB en ligne)"),
                ("HAUTE", "Tableau de bord client amélioré : historique, tendances, comparaisons"),
                ("HAUTE", "Mise à jour automatique CVE via OSV.dev API batch"),
                ("HAUTE", "Profils Khamsat et Mostaql actifs avec 10+ avis"),
                ("HAUTE", "Support anglais complet de l'interface"),
                ("MOYENNE", "Scan planifié récurrent (quotidien/hebdomadaire/mensuel)"),
                ("MOYENNE", "Alertes email automatiques si nouvelle faille critique détectée"),
            ]
        },
        {
            "label": "6.4 — Phase 3 : Mois 6–12 (CROISSANCE)",
            "color": GREEN,
            "objective": "Objectif : 50 clients, 500 000+ DZD/mois, présence MENA et début international.",
            "tasks": [
                ("CRITIQUE", "White-label pour agences partenaires (logo, couleurs personnalisables)"),
                ("CRITIQUE", "Launch Product Hunt + Show HN pour traction internationale"),
                ("CRITIQUE", "Embauche ou associé commercial (si revenus suffisants)"),
                ("HAUTE", "Intégration GitHub Actions / GitLab CI (scan automatique sur PR)"),
                ("HAUTE", "Compliance reports : OWASP Top 10, GDPR, ISO 27001 checklist"),
                ("HAUTE", "Agent de monitoring continu (détecte les nouvelles failles sans scan manuel)"),
                ("HAUTE", "AppSumo lifetime deal pour acquisition rapide utilisateurs internationaux"),
                ("MOYENNE", "Mobile app (React Native) pour consulter les rapports"),
                ("MOYENNE", "Intégration Slack/Teams pour notifications d'alertes"),
            ]
        },
    ]

    for phase in phases:
        pdf.sub_title(phase["label"], color=phase["color"])
        pdf.callout(phase["objective"], color=phase["color"],
                    bg=SUCCESS if phase["color"] == GREEN else
                       WARN if phase["color"] == GOLD else ROW_A)
        rows = [[p, t] for p, t in phase["tasks"]]
        pdf.table(["Priorité", "Tâche"], rows, widths=[25, 157])
        pdf.ln(2)


# ── PARTIE 7 — Améliorations Produit ─────────────────────────────────────────
def partie7(pdf):
    pdf.add_page()
    pdf.section_title("PARTIE 7", "AMELIORATIONS PRODUIT PRIORITAIRES")

    improvements = [
        {
            "title": "7.1 — API REST Publique (Impact : CRITIQUE)",
            "desc": "Sans API, SecurAX ne peut pas être intégré dans une pipeline CI/CD. "
                    "C'est la fonctionnalité la plus demandée par les développeurs.",
            "steps": [
                "Ajouter un modèle APIKey dans la base de données (clé, user_id, créée le, expire le, permissions).",
                "Créer un Blueprint Flask /api/v1/ avec authentification Bearer Token.",
                "Exposer : POST /api/v1/scan (lancer un scan), GET /api/v1/scan/{id} (statut), GET /api/v1/reports (historique).",
                "Générer la documentation Swagger avec flask-swagger-ui.",
                "Monétiser : API disponible uniquement Plans Business et Agency.",
            ]
        },
        {
            "title": "7.2 — Multi-Tenant (Impact : CRITIQUE pour SaaS)",
            "desc": "Actuellement, tous les clients partagent le même espace. "
                    "Multi-tenant = chaque client voit uniquement ses propres scans.",
            "steps": [
                "Ajouter un champ organization_id sur tous les modèles (User, Scan, Report).",
                "Filtrer TOUTES les requêtes DB par organization_id de l'utilisateur connecté.",
                "Créer un modèle Organization avec plan, quota_scans, date_expiration.",
                "Admin super-admin peut voir toutes les organisations.",
                "Migration de données : assigner les utilisateurs existants à une organisation 'default'.",
            ]
        },
        {
            "title": "7.3 — Mise à Jour CVE Automatique (Impact : HAUTE)",
            "desc": "Les CVE évoluent quotidiennement. Sans mise à jour, le scanner de dépendances devient obsolète.",
            "steps": [
                "Utiliser l'API batch OSV.dev : POST https://api.osv.dev/v1/querybatch avec 100 packages par requête.",
                "Tâche cron quotidienne (APScheduler) pour mettre à jour les CVE connues.",
                "Stocker le cache CVE en DB avec timestamp — évite de requêter OSV à chaque scan.",
                "Alerter l'administrateur si une nouvelle CVE critique (CVSS > 9) est détectée.",
            ]
        },
        {
            "title": "7.4 — Monitoring et Observabilité (Impact : HAUTE)",
            "desc": "Sans monitoring, les erreurs silencieuses passent inaperçues. "
                    "Un scan qui échoue sans alerte = client mécontent sans raison apparente.",
            "steps": [
                "Intégrer Sentry (version gratuite) pour capturer les exceptions Python en production.",
                "Ajouter des logs structurés (JSON) avec niveau ERROR/WARNING/INFO dans chaque scanner.",
                "Tableau de bord admin : taux de succès des scans, durée moyenne, erreurs fréquentes.",
                "Alertes email si un scanner échoue plus de 3 fois en 1 heure.",
            ]
        },
        {
            "title": "7.5 — SSLyze Integration (Impact : HAUTE — qualité scanner SSL)",
            "desc": "La bibliothèque ssl native Python ne détecte pas ROBOT, BEAST, POODLE, Heartbleed. "
                    "SSLyze est la référence open source pour ces tests avancés.",
            "steps": [
                "pip install sslyze",
                "Remplacer le bloc ssl.create_default_context() par SSLyze Scanner dans ssl_scanner.py.",
                "Ajouter détection : ROBOT attack, BEAST, CRIME, POODLE, Heartbleed, Certificate Transparency.",
                "Garder la détection de certificat expiré avec la lib native comme fallback.",
            ]
        },
        {
            "title": "7.6 — Scan CI/CD GitHub Actions (Impact : HAUTE — marché dev)",
            "desc": "Les équipes de développement veulent scanner automatiquement à chaque Pull Request.",
            "steps": [
                "Créer une GitHub Action officielle SecurAX (YAML disponible sur GitHub Marketplace).",
                "L'action appelle l'API SecurAX, attend le résultat, fail si CVSS critique > 7.",
                "Générer un commentaire automatique sur la PR avec le résumé du rapport.",
                "Documenter l'intégration sur la landing page — fort attrait pour développeurs.",
            ]
        },
    ]

    for imp in improvements:
        pdf.sub_title(imp["title"], color=TEAL)
        pdf.body(imp["desc"])
        pdf.bullet(imp["steps"])
        pdf.ln(1)


# ── PARTIE 8 — Ressources ─────────────────────────────────────────────────────
def partie8(pdf):
    pdf.add_page()
    pdf.section_title("PARTIE 8", "RESSOURCES, OUTILS ET ACQUISITION CLIENTS")

    pdf.sub_title("8.1 — Plateformes de Vente et Acquisition")
    pdf.table(
        ["Plateforme", "Type", "Action", "Priorité"],
        [
            ["Khamsat.com", "Marketplace arabe (services)", "Créer service audit sécurité à 2 000–5 000 DZD", "P1"],
            ["Mostaql.com", "Freelance arabe B2B", "Profil prestataire + exemples rapports", "P1"],
            ["LinkedIn", "B2B réseau pro", "3 posts/semaine, cibler DSI et dirigeants PME", "P1"],
            ["Facebook Business", "PME algériennes", "Groupe 'Sécurité web Algérie', posts éducatifs", "P2"],
            ["Product Hunt", "Tech international", "Launch produit mois 6–9", "P3"],
            ["AppSumo", "SaaS deals", "Lifetime deal pour traction rapide", "P3"],
            ["GitHub", "Développeurs", "Client CLI open source, README professionnel", "P2"],
            ["IndieHackers", "Fondateurs SaaS", "Documenter la progression mensuelle", "P2"],
            ["G2 / Capterra", "Reviews SaaS", "Créer un listing, demander des avis clients", "P2"],
        ],
        widths=[35, 35, 82, 30],
    )

    pdf.sub_title("8.2 — Outils Gratuits ou Très Bon Marché")
    pdf.table(
        ["Catégorie", "Outil", "Utilisation", "Coût"],
        [
            ["Hébergement", "Hetzner VPS CX11", "Serveur production principal", "~4€/mois"],
            ["Hébergement", "DigitalOcean Droplet", "Alternative avec $200 crédit initial", "~5$/mois"],
            ["Landing page", "Carrd.co", "Landing page simple en 1h", "19$/an"],
            ["Email pro", "Zoho Mail", "Email @securax.dz professionnel", "Gratuit (1 user)"],
            ["CRM", "Notion (template)", "Suivi prospects, clients, pipeline", "Gratuit"],
            ["Analytics", "Google Analytics 4", "Suivre les visiteurs landing page", "Gratuit"],
            ["Monitoring erreurs", "Sentry", "Capturer les erreurs Python en prod", "Gratuit (5k events)"],
            ["Status page", "UptimeRobot", "Surveiller uptime, alertes downtime", "Gratuit"],
            ["Démo vidéo", "Loom", "Enregistrer démo de 3 min pour prospects", "Gratuit"],
            ["Facturation", "Invoice Ninja", "Générer factures PDF professionnelles", "Gratuit"],
            ["Paiement DZ", "Chargili Pay", "Accepter paiement CIB/Edahabia en ligne", "2.5%/txn"],
            ["Support client", "Crisp.chat", "Chat en direct sur la landing page", "Gratuit"],
            ["Newsletter", "Mailchimp", "Newsletter sécurité mensuelle", "Gratuit (500 contacts)"],
            ["Repo code", "GitHub Private", "Versioning + CI/CD GitHub Actions", "Gratuit"],
        ],
        widths=[30, 32, 75, 45],
    )

    pdf.add_page()
    pdf.sub_title("8.3 — Partenariats Stratégiques")
    pdf.table(
        ["Type de partenaire", "Approche", "Valeur pour eux", "Valeur pour SecurAX"],
        [
            ["Agences web locales (50+)", "Proposer commission 20% sur chaque client apporté",
             "Nouveau service à vendre à leurs clients, sans investissement",
             "Canal de distribution multiplié, clients qualifiés"],
            ["Hébergeurs algériens (Amen, Ooredoo)", "Bundle sécurité inclus avec l'hébergement",
             "Valeur ajoutée différenciatrice, réduction churn clients",
             "Distribution massive, crédibilité, revenus récurrents"],
            ["Incubateurs/Startupdz", "Offrir plan gratuit aux startups incubées",
             "Service sécurité à 0 coût pour leurs incubés",
             "Notoriété, témoignages, futurs clients payants"],
            ["Écoles de développement", "Ateliers sécurité avec SecurAX (formation)",
             "Contenu pratique, outil pédagogique",
             "Notoriété, accès aux futurs clients entreprise"],
            ["ANIE / ANSSI Algérie", "Collaboration sur des rapports de cybersécurité",
             "Expertise et outils de terrain",
             "Crédibilité institutionnelle, accès marché public"],
        ],
        widths=[40, 52, 47, 43],
    )

    pdf.sub_title("8.4 — Stratégie de Contenu (0 DZD)")
    pdf.bullet([
        "LinkedIn : 1 post/semaine sur une faille de sécurité connue en Algérie (ex. sites .dz piratés). Objectif : 500 abonnés en 3 mois.",
        "Newsletter mensuelle 'SecurAX Security Digest' : top failles du mois, conseils, nouveautés produit.",
        "YouTube : tutoriels gratuits 'Comment sécuriser son site WordPress en 30 minutes'. SEO organique long terme.",
        "Medium / Dev.to : articles techniques sur la cybersécurité pour attirer les développeurs.",
        "Rapport annuel public 'État de la cybersécurité des PME algériennes' — relations presse, crédibilité.",
    ])

    pdf.sub_title("8.5 — Acquisition Payante (Si Budget Disponible)")
    pdf.table(
        ["Canal", "Budget/mois", "CPC estimé", "Leads attendus"],
        [
            ["LinkedIn Ads (DZ)", "10 000 DZD", "~500 DZD/clic", "~20 clics, 2–3 leads"],
            ["Google Ads (mots-clés sécurité)", "15 000 DZD", "~300 DZD/clic", "~50 clics, 5 leads"],
            ["Facebook Ads (PME algériennes)", "8 000 DZD", "~100 DZD/clic", "~80 clics, 4 leads"],
        ],
        widths=[45, 30, 35, 72],
    )
    pdf.callout(
        "Recommandation : Ne pas investir en publicité payante avant d'avoir 5 clients organiques. "
        "Valider d'abord le message et la conversion avec du trafic gratuit (réseau, contenu, marketplace).",
        color=GOLD, bg=WARN
    )


# ── PARTIE 9 — Annexes ────────────────────────────────────────────────────────
def partie9(pdf):
    pdf.add_page()
    pdf.section_title("PARTIE 9", "ANNEXES — SCRIPTS, TARIFS, KPI, OBJECTIFS")

    pdf.sub_title("9.1 — Script Email Commercial (Premier Contact B2B)")
    pdf.set_fill_color(*ROW_A)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(*DARK)
    pdf.set_x(M)
    pdf.multi_cell(CW, 5,
        "Objet : Votre site [nomsite.dz] — Résultat de sécurité : [SCORE]/100\n\n"
        "Bonjour [Prénom],\n\n"
        "Je me permets de vous contacter car j'ai analysé brièvement la sécurité publique de "
        "votre site [nomsite.dz] avec SecurAX, notre plateforme de cybersécurité.\n\n"
        "Résultats préliminaires :\n"
        "  • Score de sécurité : [X]/100\n"
        "  • Failles détectées : [N] (dont [M] critiques)\n"
        "  • Points sensibles : [ex. absence de HTTPS strict, headers manquants, dépendances vulnérables]\n\n"
        "Je peux vous envoyer le rapport complet gratuitement et vous proposer une solution "
        "adaptée à votre budget.\n\n"
        "Seriez-vous disponible pour un appel de 15 minutes cette semaine ?\n\n"
        "Cordialement,\n[Votre Nom] — SecurAX | innovation.team.dz@gmail.com",
        fill=True
    )
    pdf.ln(4)

    pdf.sub_title("9.2 — Script de Présentation (Appel téléphonique — 5 minutes)")
    pdf.set_fill_color(*ROW_A)
    pdf.set_x(M)
    pdf.multi_cell(CW, 5,
        "Introduction (30s) :\n"
        "'Bonjour, je suis [Nom] de SecurAX, une plateforme algérienne de cybersécurité. "
        "J'ai analysé votre site et j'ai quelques résultats à vous partager — ça prend 5 minutes.'\n\n"
        "Problème (1min) :\n"
        "'Aujourd'hui 60% des PME algériennes en ligne ont au moins une faille de sécurité critique. "
        "Un site piraté coûte en moyenne 3 semaines de chiffre d'affaires perdu + dommages réputationnels.'\n\n"
        "Solution (1min) :\n"
        "'SecurAX scanne votre site en 10 minutes, détecte les failles, et vous donne un rapport "
        "avec exactement quoi faire. C'est comme avoir un ingénieur sécurité à votre disposition.'\n\n"
        "Preuve (30s) :\n"
        "'On couvre 11 types de scans : web, réseau, SSL, dépendances, WordPress... "
        "Voici un exemple de rapport — [envoyer PDF par WhatsApp].'\n\n"
        "Appel à l'action (30s) :\n"
        "'Je vous propose un audit complet gratuit de votre infrastructure. "
        "Si vous êtes satisfait, on discute d'un abonnement mensuel à partir de 5 000 DZD. "
        "Ça vous convient ?'",
        fill=True
    )
    pdf.ln(4)

    pdf.sub_title("9.3 — KPI à Suivre Chaque Semaine")
    pdf.table(
        ["KPI", "Cible Mois 1", "Cible Mois 3", "Cible Mois 6", "Outil de mesure"],
        [
            ["Contacts démarches", "30 contacts", "100 contacts", "300 contacts", "Google Sheet CRM"],
            ["Démos réalisées", "5 démos", "20 démos", "50 démos", "Calendly / Loom"],
            ["Clients payants", "1 client", "5 clients", "20 clients", "Dashboard admin"],
            ["MRR (Revenu mensuel)", "5 000 DZD", "60 000 DZD", "250 000 DZD", "Tableau financier"],
            ["Scans réalisés/mois", "10 scans", "50 scans", "200 scans", "DB SecurAX"],
            ["Avis/témoignages", "0 → 2", "5 avis", "15 avis", "LinkedIn, Khamsat"],
            ["Uptime plateforme", ">99%", ">99.5%", ">99.9%", "UptimeRobot"],
            ["NPS (satisfaction)", "N/A", ">30", ">50", "Survey email mensuel"],
        ],
        widths=[42, 28, 28, 28, 56],
    )

    pdf.add_page()
    pdf.sub_title("9.4 — Plan 30 / 90 / 180 Jours Condensé")
    pdf.table(
        ["Horizon", "Objectif principal", "Actions clés", "Succès = ..."],
        [
            ["30 jours",
             "Premier paiement reçu",
             "Landing page, 30 contacts, 2 audits gratuits, Khamsat profile",
             "1 virement reçu (n'importe quel montant)"],
            ["90 jours",
             "5 clients payants, MRR 60k DZD",
             "API simple, pricing public, 3 agences partenaires, VPS migré",
             "5 clients actifs + 1 agence partenaire"],
            ["180 jours",
             "20 clients, MRR 250k DZD, MENA",
             "Multi-tenant, Khamsat/Mostaql actifs, LinkedIn 500+ abonnés",
             "Premier client hors Algérie payant en devise"],
        ],
        widths=[22, 42, 70, 48],
    )

    pdf.sub_title("9.5 — Risques et Mitigation")
    pdf.table(
        ["Risque", "Probabilité", "Impact", "Mitigation"],
        [
            ["Zéro client après 30 jours", "Moyenne", "Élevé", "Pivoter vers audits ponctuels Khamsat, réduire le prix"],
            ["Concurrent local lance un produit similaire", "Faible", "Moyen", "Accélérer acquisition, renforcer LTV, fidélisation"],
            ["Bug critique en production", "Haute", "Élevé", "Tests auto, Sentry monitoring, SLA de correction 24h"],
            ["Infra down (PythonAnywhere)", "Haute actuel", "Élevé", "Migrer vers VPS avant le 1er client payant"],
            ["Client insatisfait demande remboursement", "Moyenne", "Faible", "Politique de remboursement 14j, support réactif"],
            ["Fuite de données client", "Faible", "Très élevé", "Chiffrement DB, tests sécurité internes, multi-tenant"],
            ["Scalabilité insuffisante (>100 clients)", "Faible à court terme", "Moyen", "Prévoir migration vers cloud managé dès MRR 300k DZD"],
        ],
        widths=[47, 22, 18, 95],
    )

    pdf.sub_title("9.6 — Objectifs Financiers Condensés")
    pdf.kpi_row([
        ("Objectif Mois 1", "5 000 DZD", TEAL),
        ("Objectif Mois 3", "60 000 DZD", GOLD),
        ("Objectif Mois 6", "250 000 DZD", ORANGE),
        ("Objectif Mois 12", "500 000 DZD", GREEN),
    ])
    pdf.ln(4)

    pdf.sub_title("9.7 — Ressources et Liens Utiles")
    pdf.table(
        ["Ressource", "URL / Accès", "Utilisation"],
        [
            ["OSV.dev API", "api.osv.dev", "CVE open source pour scanner dépendances"],
            ["NVD NIST", "nvd.nist.gov", "Base CVE officielle américaine"],
            ["OWASP Top 10", "owasp.org/Top10", "Référence failles web — à couvrir en priorité"],
            ["Shodan API", "shodan.io/api", "Scan d'assets externes, enrichissement"],
            ["Hetzner VPS", "hetzner.com/cloud", "VPS à 4€/mois pour remplacer PythonAnywhere"],
            ["Chargili Pay", "chargili.com", "Paiement en ligne algérien (CIB, Edahabia)"],
            ["Paddle", "paddle.com", "Paiement international (accepte DZ fondateurs)"],
            ["Carrd.co", "carrd.co", "Landing page simple et rapide"],
            ["Khamsat", "khamsat.com", "Marketplace arabe pour services freelance"],
            ["Mostaql", "mostaql.com", "Plateforme B2B arabe freelance"],
            ["Sentry", "sentry.io", "Monitoring erreurs Python gratuit"],
            ["UptimeRobot", "uptimerobot.com", "Surveillance uptime 24/7 gratuit"],
            ["Swagger UI Flask", "flask-swagger-ui PyPI", "Documentation API automatique"],
            ["SSLyze", "github.com/nabla-c0d3/sslyze", "Tests SSL avancés (ROBOT, BEAST, etc.)"],
        ],
        widths=[40, 55, 87],
    )

    # Final callout
    pdf.ln(4)
    pdf.set_fill_color(*NAVY)
    pdf.rect(M, pdf.get_y(), CW, 28, "F")
    pdf.set_xy(M + 3, pdf.get_y() + 4)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*WHITE)
    pdf.cell(CW - 6, 7, "Message Final", ln=True)
    pdf.set_xy(M + 3, pdf.get_y())
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*TEAL_LT)
    pdf.multi_cell(CW - 6, 5,
        "SecurAX a tout ce qu'il faut pour réussir. Le produit existe. La technologie est là. "
        "Le marché est non saturé. Ce qui manque : vendre. Un seul client payant vaut plus "
        "que 100 fonctionnalités supplémentaires. Allez chercher ce premier client aujourd'hui.")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    pdf = PDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(M, 10, M)

    cover(pdf)
    partie1(pdf)
    partie2(pdf)
    partie3(pdf)
    partie4(pdf)
    partie5(pdf)
    partie6(pdf)
    partie7(pdf)
    partie8(pdf)
    partie9(pdf)

    out = "SecurAX_Rapport_Strategique_2026.pdf"
    pdf.output(out)
    size_kb = os.path.getsize(out) / 1024
    print(f"[OK] {out} — {pdf.page} pages — {size_kb:.1f} KB")


if __name__ == "__main__":
    main()
