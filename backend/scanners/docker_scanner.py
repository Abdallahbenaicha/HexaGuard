"""SecurAx — Docker / Container Security Scanner.

Analyzes Dockerfile and docker-compose.yml files for security misconfigurations.
No external dependencies — pure Python text analysis.

Checks performed:
  Dockerfile:
    • No USER directive (runs as root)
    • USER root explicitly set
    • Unpinned base image (:latest or no tag)
    • ADD instead of COPY
    • EXPOSE sensitive ports (22, 23, 2375, 2376, 3306, 5432, 27017, 6379)
    • Secrets / credentials in ENV directives
    • curl|bash / wget|bash supply-chain patterns
    • chmod 777 world-writable permissions
    • No HEALTHCHECK defined
  docker-compose.yml:
    • privileged: true
    • Docker socket mounted (/var/run/docker.sock)
    • network_mode: host
    • cap_add: [ALL]
    • no-new-privileges not set
    • Image :latest tags in services
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# ── Sensitive port table ───────────────────────────────────────────────────────

_SENSITIVE_PORTS: dict[str, tuple[str, str, str]] = {
    "22":    ("SSH port exposed", "high",
              "SSH inside containers is an anti-pattern. Remove EXPOSE 22 and use docker exec for debugging."),
    "23":    ("Telnet port exposed", "critical",
              "Telnet transmits data in plaintext. Remove EXPOSE 23 immediately."),
    "2375":  ("Docker daemon API port exposed (no TLS)", "critical",
              "EXPOSE 2375 grants full, unauthenticated control over the Docker host. Remove immediately."),
    "2376":  ("Docker daemon TLS API port exposed", "high",
              "EXPOSE 2376 exposes the Docker TLS API. Remove unless the service genuinely manages containers."),
    "3306":  ("MySQL port exposed", "medium",
              "Database ports should not be publicly exposed. Use internal Docker networks instead."),
    "5432":  ("PostgreSQL port exposed", "medium",
              "Database ports should not be publicly exposed. Use internal Docker networks instead."),
    "27017": ("MongoDB port exposed", "high",
              "MongoDB has no auth by default. Never expose port 27017 publicly."),
    "6379":  ("Redis port exposed", "medium",
              "Redis has no auth by default. Exposing port 6379 publicly is dangerous."),
    "9200":  ("Elasticsearch port exposed", "high",
              "Elasticsearch has no auth by default in older versions. Restrict access with network policies."),
    "5601":  ("Kibana port exposed", "medium",
              "Kibana should not be exposed publicly without authentication proxy."),
}

# ── ENV secret patterns ────────────────────────────────────────────────────────

_SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'(?i)\bpassword\b\s*[=:]\s*\S+'),          "Hardcoded PASSWORD in ENV"),
    (re.compile(r'(?i)\bsecret\b\s*[=:]\s*\S+'),            "Hardcoded SECRET in ENV"),
    (re.compile(r'(?i)\bapi[_-]?key\b\s*[=:]\s*\S+'),       "Hardcoded API KEY in ENV"),
    (re.compile(r'(?i)\btoken\b\s*[=:]\s*\S+'),             "Hardcoded TOKEN in ENV"),
    (re.compile(r'(?i)\bprivate[_-]?key\b\s*[=:]\s*\S+'),   "Hardcoded PRIVATE KEY in ENV"),
    (re.compile(r'(?i)\baws[_-]?access[_-]?key\b\s*[=:]\s*\S+'), "AWS Access Key in ENV"),
    (re.compile(r'(?i)\bdatabase[_-]?url\b\s*[=:]\s*\S+'),  "Database URL (may contain credentials) in ENV"),
    (re.compile(r'(?i)\bdb[_-]?pass(word)?\b\s*[=:]\s*\S+'),"DB Password in ENV"),
]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _vuln(title: str, severity: str, description: str,
          recommendation: str, line: int | None = None) -> dict:
    return {
        "title":          title,
        "severity":       severity,
        "description":    description,
        "recommendation": recommendation,
        "line":           line,
    }


# ── Dockerfile analysis ────────────────────────────────────────────────────────

def _scan_dockerfile(content: str) -> tuple[list, dict]:
    lines = content.splitlines()
    vulns: list[dict] = []
    meta: dict = {
        "file_type":          "Dockerfile",
        "base_image":         None,
        "has_user_directive": False,
        "has_healthcheck":    False,
        "expose_ports":       [],
        "env_secrets_found":  0,
        "total_run_layers":   0,
    }

    for i, raw in enumerate(lines, 1):
        line   = raw.strip()
        if not line or line.startswith("#"):
            continue
        upper  = line.upper()
        tokens = line.split()

        # FROM
        if upper.startswith("FROM ") and len(tokens) >= 2:
            image = tokens[1]
            meta["base_image"] = image
            if ":" not in image or image.endswith(":latest"):
                vulns.append(_vuln(
                    "Unpinned base image tag",
                    "medium",
                    f"FROM {image} uses :latest or no tag — builds are unpredictable and can pull vulnerable images.",
                    "Pin to an exact digest or version, e.g. python:3.12.3-slim-bookworm.",
                    i,
                ))

        # USER
        elif upper.startswith("USER ") and len(tokens) >= 2:
            meta["has_user_directive"] = True
            user_val = tokens[1].lower()
            if user_val in ("root", "0", "0:0", "root:root"):
                vulns.append(_vuln(
                    "Container explicitly set to run as root",
                    "high",
                    "USER root maximises the blast radius of any container escape.",
                    "Create a non-root user: RUN addgroup -S app && adduser -S app -G app  then  USER app",
                    i,
                ))

        # HEALTHCHECK
        elif upper.startswith("HEALTHCHECK"):
            meta["has_healthcheck"] = True

        # ADD vs COPY
        elif upper.startswith("ADD "):
            vulns.append(_vuln(
                "ADD used instead of COPY",
                "low",
                "ADD auto-extracts archives and fetches URLs, which can introduce unexpected files.",
                "Replace ADD with COPY for local files. Use explicit RUN curl/wget for URLs.",
                i,
            ))

        # EXPOSE sensitive ports
        elif upper.startswith("EXPOSE "):
            ports = line[7:].strip().split()
            meta["expose_ports"].extend(ports)
            for port in ports:
                port_num = port.split("/")[0]
                if port_num in _SENSITIVE_PORTS:
                    title, sev, rec = _SENSITIVE_PORTS[port_num]
                    vulns.append(_vuln(title, sev, f"Port {port} is explicitly exposed.", rec, i))

        # ENV — secret detection
        elif upper.startswith("ENV "):
            env_body = line[4:]
            for pat, label in _SECRET_PATTERNS:
                if pat.search(env_body):
                    meta["env_secrets_found"] += 1
                    vulns.append(_vuln(
                        label,
                        "critical",
                        f"Potential hardcoded credential found in ENV at line {i}.",
                        "Use Docker Secrets, build-args (--build-arg, not ENV), or inject at runtime via orchestrator.",
                        i,
                    ))

        # RUN — supply-chain + permissions
        elif upper.startswith("RUN "):
            meta["total_run_layers"] += 1
            run_body = line[4:]
            if re.search(r"(curl|wget)\s+\S+\s*\|\s*(ba)?sh", run_body, re.I):
                vulns.append(_vuln(
                    "Piped shell script from URL (supply-chain risk)",
                    "high",
                    "Piping a downloaded script directly into sh/bash is a supply-chain attack vector.",
                    "Download the script first, verify its SHA-256 checksum, then execute.",
                    i,
                ))
            if re.search(r"chmod\s+(-R\s+)?777", run_body):
                vulns.append(_vuln(
                    "World-writable file permissions (chmod 777)",
                    "medium",
                    "chmod 777 allows any process to read, write, or execute those files.",
                    "Use the minimum permissions needed: 755 for executables, 644 for data files.",
                    i,
                ))

    # Post-scan checks
    if not meta["has_user_directive"]:
        vulns.append(_vuln(
            "No USER directive — container runs as root by default",
            "critical",
            "Without a USER directive Docker runs everything as root. A container escape → full host compromise.",
            "Add before the final CMD/ENTRYPOINT:\n"
            "  RUN addgroup -S appgroup && adduser -S appuser -G appgroup\n"
            "  USER appuser",
        ))

    if not meta["has_healthcheck"]:
        vulns.append(_vuln(
            "No HEALTHCHECK defined",
            "info",
            "Without HEALTHCHECK, Docker cannot detect an unhealthy container and restart it automatically.",
            "Add: HEALTHCHECK --interval=30s --timeout=5s CMD curl -sf http://localhost/health || exit 1",
        ))

    return vulns, meta


# ── docker-compose.yml analysis ────────────────────────────────────────────────

def _scan_compose(content: str) -> tuple[list, dict]:
    lines  = content.splitlines()
    vulns: list[dict] = []
    meta: dict = {
        "file_type":         "docker-compose",
        "has_privileged":    False,
        "docker_sock_mounts": 0,
    }

    for i, raw in enumerate(lines, 1):
        line = raw.strip()

        if re.match(r"privileged\s*:\s*(true|yes)", line, re.I):
            meta["has_privileged"] = True
            vulns.append(_vuln(
                "Privileged container mode enabled",
                "critical",
                "privileged: true gives the container full access to the host kernel — equivalent to running as root on the host.",
                "Remove privileged: true. Grant only the specific capabilities required (cap_add).",
                i,
            ))

        if "/var/run/docker.sock" in line:
            meta["docker_sock_mounts"] += 1
            vulns.append(_vuln(
                "Docker socket mounted into container",
                "critical",
                "Mounting /var/run/docker.sock gives the container full control over the Docker daemon — trivial host escape.",
                "Remove the socket bind-mount. For CI use-cases consider rootless Docker or dedicated API proxies.",
                i,
            ))

        if re.match(r'network_mode\s*:\s*["\']?host["\']?', line, re.I):
            vulns.append(_vuln(
                "Host network mode disables network isolation",
                "high",
                "network_mode: host removes the container's network namespace — it shares all host interfaces.",
                "Use a custom Docker bridge network for inter-service communication.",
                i,
            ))

        if re.search(r"cap_add.*ALL", line, re.I):
            vulns.append(_vuln(
                "All Linux capabilities granted (cap_add: ALL)",
                "critical",
                "cap_add: [ALL] grants every Linux capability, effectively negating container isolation.",
                "List only the specific capabilities needed, e.g. cap_add: [NET_BIND_SERVICE].",
                i,
            ))

        # Latest tag in image: directive
        m = re.match(r"image\s*:\s*(\S+)", line, re.I)
        if m:
            img = m.group(1).strip('"\'')
            if ":" not in img or img.endswith(":latest"):
                vulns.append(_vuln(
                    "Unpinned image tag in service",
                    "medium",
                    f"Service image '{img}' uses :latest or no tag — unpredictable and potentially vulnerable.",
                    "Pin to a specific image digest or version tag.",
                    i,
                ))

    if "no-new-privileges" not in content:
        vulns.append(_vuln(
            "no-new-privileges not enforced",
            "low",
            "Without security_opt: no-new-privileges, setuid binaries inside the container can escalate privileges.",
            "Add to each service:\n  security_opt:\n    - no-new-privileges:true",
        ))

    return vulns, meta


# ── Public entry point ─────────────────────────────────────────────────────────

def run_docker_scan(content: str, filename: str = "Dockerfile") -> dict:
    """Scan a Dockerfile or docker-compose.yml and return a findings dict."""
    fname_lower = filename.lower()
    is_compose  = (
        "compose" in fname_lower
        or fname_lower.endswith(".yml")
        or fname_lower.endswith(".yaml")
    )

    if is_compose:
        vulns, meta = _scan_compose(content)
    else:
        vulns, meta = _scan_dockerfile(content)

    meta["filename"] = filename

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns.sort(key=lambda v: sev_order.get(v["severity"], 99))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        counts[v["severity"]] = counts.get(v["severity"], 0) + 1

    return {
        "scan_type":    "docker",
        "target":       filename,
        "vulnerabilities": vulns,
        "counts":       counts,
        "meta":         meta,
    }
