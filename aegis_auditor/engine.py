from __future__ import annotations

import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .models import AuditResult, Finding


class AuditEngine:
    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self.headers = {
            "User-Agent": "AegisAuthAuditor/3.0",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        }

    def run(self, target_url: str, login_url: str) -> AuditResult:
        target_url = self._normalize_url(target_url)
        login_url = self._normalize_url(login_url)
        self._validate_same_host(target_url, login_url)
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        metadata: dict[str, object] = {}

        with httpx.Client(headers=self.headers, timeout=self.timeout, follow_redirects=True, verify=True) as client:
            response, target_elapsed, target_tries = self._request_with_retry(client, target_url)
            metadata["target_status"] = response.status_code
            metadata["target_elapsed_ms"] = target_elapsed
            metadata["target_attempts"] = target_tries
            metadata["final_url"] = str(response.url)
            findings.extend(self._availability_check("target", "Disponibilidade do ambiente", response, 5))
            findings.extend(self._transport_checks(target_url, response))

            if response.status_code < 500:
                findings.extend(self._header_checks(response))
            else:
                findings.extend(self._inconclusive_header_checks())

            login_response, login_elapsed, login_tries = self._request_with_retry(client, login_url)
            metadata["login_status"] = login_response.status_code
            metadata["login_elapsed_ms"] = login_elapsed
            metadata["login_attempts"] = login_tries
            metadata["login_final_url"] = str(login_response.url)
            findings.extend(self._availability_check("login_availability", "Disponibilidade da página de login", login_response, 5))

            if login_response.status_code < 500:
                findings.extend(self._login_checks(login_url, login_response))
                findings.extend(self._cookie_checks(login_response))
                findings.extend(self._login_cache_check(login_response))
            else:
                findings.extend(self._inconclusive_login_checks())
                findings.extend([
                    self._inconclusive("cookie_secure", "Cookie Secure", "Sessão", "A resposta da página de login não permitiu avaliar cookies.", 4, "ALTA"),
                    self._inconclusive("cookie_httponly", "Cookie HttpOnly", "Sessão", "A resposta da página de login não permitiu avaliar cookies.", 4, "ALTA"),
                    self._inconclusive("cookie_samesite", "Cookie SameSite", "Sessão", "A resposta da página de login não permitiu avaliar cookies.", 4, "MÉDIA"),
                    self._inconclusive("login_cache", "Cache da página de login", "Sessão", "A resposta da página de login não permitiu avaliar a política de cache.", 4, "MÉDIA"),
                ])

        tls_metadata, tls_findings = self._tls_checks(target_url)
        metadata.update(tls_metadata)
        findings.extend(tls_findings)

        score, coverage, category_scores = self._score(findings)
        risk = "INCONCLUSIVO" if coverage < 60 else self._risk_from_score(score)
        failed = sum(1 for item in findings if item.status == "FAIL")
        warned = sum(1 for item in findings if item.status == "WARN")
        passed = sum(1 for item in findings if item.status == "PASS")
        inconclusive = sum(1 for item in findings if item.status == "INCONCLUSIVE")
        summary = f"{passed} controles aprovados, {warned} alertas, {failed} falhas e {inconclusive} inconclusivos."
        finished = datetime.now(timezone.utc)
        metadata["coverage_percent"] = coverage

        return AuditResult(
            target_url=target_url,
            login_url=login_url,
            final_url=str(metadata.get("final_url", target_url)),
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            score=score,
            risk=risk,
            coverage=coverage,
            summary=summary,
            findings=findings,
            metadata=metadata,
            category_scores=category_scores,
        )

    def _request_with_retry(self, client: httpx.Client, url: str) -> tuple[httpx.Response, int, int]:
        waits = [0.0, 2.0, 4.0, 6.0]
        last_response: httpx.Response | None = None
        last_elapsed = 0
        for index, wait in enumerate(waits, start=1):
            if wait:
                time.sleep(wait)
            started = time.perf_counter()
            response = client.get(url)
            last_elapsed = round((time.perf_counter() - started) * 1000)
            last_response = response
            if response.status_code not in {502, 503, 504}:
                return response, last_elapsed, index
        if last_response is None:
            raise RuntimeError("Não foi possível consultar o ambiente.")
        return last_response, last_elapsed, len(waits)

    def _normalize_url(self, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Informe uma URL válida.")
        if not value.startswith(("http://", "https://")):
            value = "https://" + value
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Informe uma URL HTTP ou HTTPS válida.")
        return value.rstrip("/")

    def _validate_same_host(self, target_url: str, login_url: str) -> None:
        target = urlparse(target_url)
        login = urlparse(login_url)
        if target.hostname != login.hostname:
            raise ValueError("O ambiente e a página de login devem pertencer ao mesmo host.")

    def _availability_check(self, key: str, title: str, response: httpx.Response, weight: int) -> list[Finding]:
        status = response.status_code
        if 200 <= status < 400:
            return [Finding(key, title, "Disponibilidade", "PASS", f"Resposta HTTP {status}.", "Manter monitoramento de disponibilidade.", weight, weight, "BAIXA")]
        if 400 <= status < 500:
            return [Finding(key, title, "Disponibilidade", "WARN", f"Resposta HTTP {status}.", "Confirmar se o código retornado é esperado para esta rota.", weight, max(1, weight // 2), "MÉDIA")]
        return [Finding(key, title, "Disponibilidade", "FAIL", f"Resposta HTTP {status} após novas tentativas de consulta.", "Corrigir indisponibilidade antes de interpretar controles dependentes do conteúdo.", weight, 0, "ALTA")]

    def _transport_checks(self, target_url: str, response: httpx.Response) -> list[Finding]:
        findings: list[Finding] = []
        target = urlparse(target_url)
        final = urlparse(str(response.url))
        https_ok = final.scheme == "https"
        findings.append(self._binary(
            "https",
            "HTTPS ativo",
            "Transporte",
            https_ok,
            "A conexão final utiliza HTTPS.",
            "A conexão final não utiliza HTTPS.",
            "Obrigar HTTPS em todas as páginas.",
            12,
            "CRÍTICA",
        ))

        if target.scheme == "https":
            http_url = target_url.replace("https://", "http://", 1)
            try:
                with httpx.Client(headers=self.headers, timeout=self.timeout, follow_redirects=False) as client:
                    http_response = client.get(http_url)
                location = http_response.headers.get("location", "")
                redirect_url = urljoin(http_url, location) if location else ""
                redirect_ok = http_response.status_code in {301, 302, 307, 308} and urlparse(redirect_url).scheme == "https"
                detail = f"HTTP {http_response.status_code} redireciona para HTTPS." if redirect_ok else f"HTTP retornou {http_response.status_code} sem redirecionamento HTTPS confirmado."
            except Exception as exc:
                redirect_ok = False
                detail = f"Não foi possível confirmar o redirecionamento HTTP: {exc}"
            findings.append(self._binary(
                "https_redirect",
                "Redirecionamento HTTP para HTTPS",
                "Transporte",
                redirect_ok,
                detail,
                detail,
                "Configurar redirecionamento permanente de HTTP para HTTPS.",
                5,
                "ALTA",
            ))
        return findings

    def _header_checks(self, response: httpx.Response) -> list[Finding]:
        headers = {key.lower(): value for key, value in response.headers.items()}
        findings: list[Finding] = []

        hsts = headers.get("strict-transport-security", "")
        if hsts:
            match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
            max_age = int(match.group(1)) if match else 0
            if max_age >= 15552000:
                findings.append(Finding("hsts", "Strict-Transport-Security", "Cabeçalhos", "PASS", f"HSTS presente com max-age={max_age}.", "Manter HSTS com período adequado.", 6, 6, "ALTA"))
            else:
                findings.append(Finding("hsts", "Strict-Transport-Security", "Cabeçalhos", "WARN", f"HSTS presente, porém max-age={max_age}.", "Aumentar o max-age do HSTS conforme a política da organização.", 6, 3, "MÉDIA"))
        else:
            findings.append(Finding("hsts", "Strict-Transport-Security", "Cabeçalhos", "FAIL", "HSTS não foi identificado.", "Adicionar Strict-Transport-Security com política adequada.", 6, 0, "ALTA"))

        csp = headers.get("content-security-policy", "")
        if csp:
            strong = "default-src" in csp.lower() or "script-src" in csp.lower()
            findings.append(Finding("csp", "Content-Security-Policy", "Cabeçalhos", "PASS" if strong else "WARN", "CSP identificada no cabeçalho da resposta.", "Manter uma CSP restritiva e compatível com a aplicação.", 6, 6 if strong else 3, "ALTA"))
        else:
            findings.append(Finding("csp", "Content-Security-Policy", "Cabeçalhos", "FAIL", "CSP não foi identificada.", "Definir uma Content-Security-Policy compatível com a aplicação.", 6, 0, "ALTA"))

        nosniff = headers.get("x-content-type-options", "").lower() == "nosniff"
        findings.append(self._binary("nosniff", "X-Content-Type-Options", "Cabeçalhos", nosniff, "X-Content-Type-Options está configurado como nosniff.", "X-Content-Type-Options: nosniff não foi identificado.", "Definir X-Content-Type-Options: nosniff.", 4, "MÉDIA"))

        frame_ok = "x-frame-options" in headers or "frame-ancestors" in csp.lower()
        findings.append(self._binary("frame", "Proteção contra framing", "Cabeçalhos", frame_ok, "Foi identificada proteção contra carregamento indevido em frames.", "Não foi identificada proteção explícita contra framing.", "Configurar X-Frame-Options ou frame-ancestors na CSP.", 4, "MÉDIA"))

        referrer = bool(headers.get("referrer-policy"))
        findings.append(self._binary("referrer", "Referrer-Policy", "Cabeçalhos", referrer, "Referrer-Policy está presente.", "Referrer-Policy não foi identificada.", "Definir Referrer-Policy adequada à aplicação.", 3, "BAIXA"))

        permissions = bool(headers.get("permissions-policy"))
        findings.append(self._binary("permissions", "Permissions-Policy", "Cabeçalhos", permissions, "Permissions-Policy está presente.", "Permissions-Policy não foi identificada.", "Definir Permissions-Policy para limitar recursos desnecessários.", 3, "BAIXA"))

        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        revealing = bool(powered) or any(token in server.lower() for token in ["apache/", "nginx/", "iis/", "gunicorn/", "werkzeug/"])
        detail = "Nenhuma versão detalhada de tecnologia foi observada."
        if server:
            detail = f"Cabeçalho Server informado: {server}."
        if powered:
            detail += f" X-Powered-By informado: {powered}."
        findings.append(Finding("server_disclosure", "Exposição de tecnologia do servidor", "Exposição", "WARN" if revealing else "PASS", detail, "Reduzir banners e versões de tecnologia desnecessárias." if revealing else "Manter a exposição de tecnologia minimizada.", 2, 1 if revealing else 2, "BAIXA"))
        return findings

    def _inconclusive_header_checks(self) -> list[Finding]:
        definitions = [
            ("hsts", "Strict-Transport-Security", 6, "ALTA"),
            ("csp", "Content-Security-Policy", 6, "ALTA"),
            ("nosniff", "X-Content-Type-Options", 4, "MÉDIA"),
            ("frame", "Proteção contra framing", 4, "MÉDIA"),
            ("referrer", "Referrer-Policy", 3, "BAIXA"),
            ("permissions", "Permissions-Policy", 3, "BAIXA"),
            ("server_disclosure", "Exposição de tecnologia do servidor", 2, "BAIXA"),
        ]
        return [self._inconclusive(key, title, "Cabeçalhos" if key != "server_disclosure" else "Exposição", "A resposta do ambiente não permitiu avaliar este controle.", weight, severity) for key, title, weight, severity in definitions]

    def _login_checks(self, login_url: str, response: httpx.Response) -> list[Finding]:
        findings: list[Finding] = []
        content_type = response.headers.get("content-type", "").lower()
        is_html = "html" in content_type or "<html" in response.text[:1000].lower()
        if not is_html:
            return self._inconclusive_login_checks("A rota de login não retornou conteúdo HTML analisável.")

        soup = BeautifulSoup(response.text, "html.parser")
        password = soup.find("input", attrs={"type": lambda value: value and value.lower() == "password"})
        findings.append(self._binary("password_field", "Campo de senha identificado", "Autenticação", password is not None, "A página contém campo de senha.", "Não foi identificado campo de senha no HTML retornado.", "Confirmar a rota de login e a estrutura do formulário de autenticação.", 5, "ALTA"))

        if password is None:
            findings.extend([
                self._inconclusive("login_post", "Login enviado por POST", "Autenticação", "Sem campo de senha, o método do formulário não pôde ser validado.", 6, "ALTA"),
                self._inconclusive("login_action_host", "Destino do formulário no mesmo host", "Autenticação", "Sem formulário de senha, o destino não pôde ser validado.", 5, "ALTA"),
                self._inconclusive("csrf_token", "Token anti-CSRF no formulário", "Autenticação", "Sem formulário de senha, a presença de token anti-CSRF não pôde ser validada.", 5, "ALTA"),
                self._inconclusive("password_autocomplete", "Autocomplete da senha", "Autenticação", "Sem campo de senha, a semântica de autocomplete não pôde ser validada.", 2, "BAIXA"),
                self._inconclusive("username_autocomplete", "Autocomplete do identificador", "Autenticação", "Sem formulário de senha, a semântica do identificador não pôde ser validada.", 2, "BAIXA"),
            ])
            return findings

        form = password.find_parent("form")
        if form is None:
            findings.extend([
                self._inconclusive("login_post", "Login enviado por POST", "Autenticação", "O campo de senha não pertence a um formulário HTML identificável.", 6, "ALTA"),
                self._inconclusive("login_action_host", "Destino do formulário no mesmo host", "Autenticação", "O destino do formulário não pôde ser identificado.", 5, "ALTA"),
                self._inconclusive("csrf_token", "Token anti-CSRF no formulário", "Autenticação", "O formulário não pôde ser identificado.", 5, "ALTA"),
            ])
        else:
            method = form.get("method", "get").lower()
            findings.append(self._binary("login_post", "Login enviado por POST", "Autenticação", method == "post", "O formulário de login utiliza POST.", f"O formulário utiliza método {method.upper()}.", "Enviar credenciais por POST sobre HTTPS.", 6, "ALTA"))

            action = form.get("action", "")
            action_url = urljoin(str(response.url), action) if action else str(response.url)
            same_host = urlparse(action_url).hostname == urlparse(login_url).hostname
            findings.append(self._binary("login_action_host", "Destino do formulário no mesmo host", "Autenticação", same_host, "O formulário envia dados para o mesmo host.", f"O formulário direciona dados para {urlparse(action_url).hostname or 'destino não identificado'}.", "Confirmar que credenciais sejam enviadas somente a destinos autorizados.", 5, "ALTA"))

            hidden_names = [str(item.get("name", "")).lower() for item in form.find_all("input", attrs={"type": "hidden"})]
            csrf_ok = any(any(token in name for token in ["csrf", "xsrf", "token", "authenticity"]) for name in hidden_names)
            findings.append(self._binary("csrf_token", "Token anti-CSRF no formulário", "Autenticação", csrf_ok, "Foi identificado campo oculto compatível com proteção anti-CSRF.", "Não foi identificado campo oculto compatível com token anti-CSRF.", "Aplicar proteção anti-CSRF em operações de autenticação baseadas em formulário.", 5, "ALTA"))

        password_autocomplete = str(password.get("autocomplete", "")).lower()
        password_ok = password_autocomplete in {"current-password", "new-password"}
        findings.append(Finding("password_autocomplete", "Autocomplete da senha", "Autenticação", "PASS" if password_ok else "WARN", f"autocomplete={password_autocomplete}." if password_autocomplete else "O campo de senha não informa autocomplete.", "Usar current-password em login e new-password em criação ou troca de senha.", 2, 2 if password_ok else 1, "BAIXA"))

        username = self._find_username_input(form) if form else None
        username_autocomplete = str(username.get("autocomplete", "")).lower() if username else ""
        username_ok = username_autocomplete in {"username", "email"}
        findings.append(Finding("username_autocomplete", "Autocomplete do identificador", "Autenticação", "PASS" if username_ok else "WARN", f"autocomplete={username_autocomplete}." if username_autocomplete else "O campo de identificação não informa autocomplete reconhecido.", "Usar username ou email conforme o identificador utilizado pelo login.", 2, 2 if username_ok else 1, "BAIXA"))
        return findings

    def _find_username_input(self, form):
        if form is None:
            return None
        candidates = form.find_all("input")
        scored = []
        for item in candidates:
            input_type = str(item.get("type", "text")).lower()
            name = str(item.get("name", "")).lower()
            autocomplete = str(item.get("autocomplete", "")).lower()
            if input_type not in {"text", "email", "tel", ""} or not name:
                continue
            score = 0
            if input_type == "email":
                score += 4
            if autocomplete in {"username", "email"}:
                score += 5
            if any(token in name for token in ["user", "email", "login", "account"]):
                score += 3
            scored.append((score, item))
        if not scored:
            return None
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return scored[0][1]

    def _inconclusive_login_checks(self, detail: str = "A resposta da página de login não permitiu avaliar este controle.") -> list[Finding]:
        definitions = [
            ("password_field", "Campo de senha identificado", 5, "ALTA"),
            ("login_post", "Login enviado por POST", 6, "ALTA"),
            ("login_action_host", "Destino do formulário no mesmo host", 5, "ALTA"),
            ("csrf_token", "Token anti-CSRF no formulário", 5, "ALTA"),
            ("password_autocomplete", "Autocomplete da senha", 2, "BAIXA"),
            ("username_autocomplete", "Autocomplete do identificador", 2, "BAIXA"),
        ]
        return [self._inconclusive(key, title, "Sessão" if key.startswith("cookie") else "Autenticação", detail, weight, severity) for key, title, weight, severity in definitions]

    def _cookie_checks(self, response: httpx.Response) -> list[Finding]:
        raw_cookies = response.headers.get_list("set-cookie")
        if not raw_cookies:
            return [
                self._inconclusive("cookie_secure", "Cookie Secure", "Sessão", "Nenhum cookie foi emitido na página analisada.", 4, "ALTA"),
                self._inconclusive("cookie_httponly", "Cookie HttpOnly", "Sessão", "Nenhum cookie foi emitido na página analisada.", 4, "ALTA"),
                self._inconclusive("cookie_samesite", "Cookie SameSite", "Sessão", "Nenhum cookie foi emitido na página analisada.", 4, "MÉDIA"),
            ]
        secure = all("; secure" in raw.lower() for raw in raw_cookies)
        httponly = all("; httponly" in raw.lower() for raw in raw_cookies)
        samesite = all("samesite=" in raw.lower() for raw in raw_cookies)
        return [
            self._binary("cookie_secure", "Cookie Secure", "Sessão", secure, "Os cookies emitidos utilizam Secure.", "Foi identificado cookie sem Secure.", "Marcar cookies de sessão como Secure em HTTPS.", 4, "ALTA"),
            self._binary("cookie_httponly", "Cookie HttpOnly", "Sessão", httponly, "Os cookies emitidos utilizam HttpOnly.", "Foi identificado cookie sem HttpOnly.", "Marcar cookies de sessão como HttpOnly.", 4, "ALTA"),
            self._binary("cookie_samesite", "Cookie SameSite", "Sessão", samesite, "Os cookies emitidos definem SameSite.", "Foi identificado cookie sem SameSite.", "Definir SameSite de acordo com o fluxo de autenticação.", 4, "MÉDIA"),
        ]

    def _login_cache_check(self, response: httpx.Response) -> list[Finding]:
        cache = response.headers.get("cache-control", "").lower()
        ok = "no-store" in cache or "no-cache" in cache
        return [self._binary("login_cache", "Cache da página de login", "Sessão", ok, f"Cache-Control={cache or 'não informado'}.", f"Cache-Control={cache or 'não informado'}.", "Evitar armazenamento indevido de conteúdo sensível em cache.", 4, "MÉDIA")]

    def _tls_checks(self, target_url: str) -> tuple[dict[str, object], list[Finding]]:
        parsed = urlparse(target_url)
        if parsed.scheme != "https":
            return {}, []
        host = parsed.hostname
        port = parsed.port or 443
        metadata: dict[str, object] = {}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                    cert = secure_sock.getpeercert()
                    tls_version = secure_sock.version() or ""
                    metadata["tls_version"] = tls_version
                    cipher = secure_sock.cipher()
                    metadata["cipher"] = cipher[0] if cipher else ""
                    not_after = cert.get("notAfter")
                    days_left = None
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_left = (expiry - datetime.now(timezone.utc)).days
                        metadata["certificate_days_left"] = days_left
                    cert_status = "PASS" if days_left is None or days_left >= 14 else "WARN"
                    cert_earned = 8 if cert_status == "PASS" else 4
                    cert_detail = f"Certificado validado para {host}." + (f" Restam aproximadamente {days_left} dias." if days_left is not None else "")
                    modern = tls_version in {"TLSv1.2", "TLSv1.3"}
                    return metadata, [
                        Finding("tls_certificate", "Certificado TLS válido", "Transporte", cert_status, cert_detail, "Manter renovação automática e monitoramento de validade.", 8, cert_earned, "CRÍTICA"),
                        self._binary("tls_version", "Versão TLS moderna", "Transporte", modern, f"Versão negociada: {tls_version}.", f"Versão negociada: {tls_version or 'não identificada'}.", "Permitir TLS 1.2 ou superior e desabilitar versões obsoletas.", 6, "ALTA"),
                    ]
        except Exception as exc:
            return metadata, [
                Finding("tls_certificate", "Certificado TLS válido", "Transporte", "FAIL", f"Não foi possível validar TLS: {exc}", "Corrigir certificado, cadeia de confiança e configuração TLS.", 8, 0, "CRÍTICA"),
                self._inconclusive("tls_version", "Versão TLS moderna", "Transporte", "A negociação TLS não foi concluída.", 6, "ALTA"),
            ]

    def _binary(self, key: str, title: str, category: str, ok: bool, pass_detail: str, fail_detail: str, recommendation: str, weight: int, severity: str) -> Finding:
        return Finding(key, title, category, "PASS" if ok else "FAIL", pass_detail if ok else fail_detail, recommendation, weight, weight if ok else 0, severity)

    def _inconclusive(self, key: str, title: str, category: str, detail: str, weight: int, severity: str) -> Finding:
        return Finding(key, title, category, "INCONCLUSIVE", detail, "Repetir a análise quando a rota estiver disponível e responder com conteúdo esperado.", weight, 0, severity)

    def _score(self, findings: list[Finding]) -> tuple[int, int, dict[str, int]]:
        all_weight = sum(item.weight for item in findings if item.weight > 0)
        scoreable = [item for item in findings if item.weight > 0 and item.status != "INCONCLUSIVE"]
        possible = sum(item.weight for item in scoreable)
        earned = sum(item.earned for item in scoreable)
        score = round((earned / possible) * 100) if possible else 0
        coverage = round((possible / all_weight) * 100) if all_weight else 0
        categories: dict[str, list[int]] = {}
        for item in scoreable:
            bucket = categories.setdefault(item.category, [0, 0])
            bucket[0] += item.earned
            bucket[1] += item.weight
        category_scores = {name: round((values[0] / values[1]) * 100) if values[1] else 0 for name, values in categories.items()}
        return score, coverage, category_scores

    def _risk_from_score(self, score: int) -> str:
        if score >= 90:
            return "BAIXO"
        if score >= 75:
            return "MODERADO"
        if score >= 55:
            return "ELEVADO"
        return "ALTO"
