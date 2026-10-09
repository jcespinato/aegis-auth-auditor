from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from urllib.parse import urlparse, urljoin

import httpx
from bs4 import BeautifulSoup

from .models import AuditResult, Finding


class AuditEngine:
    def __init__(self, timeout: float = 8.0) -> None:
        self.timeout = timeout
        self.headers = {
            "User-Agent": "AegisAuthAuditor/1.0",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        }

    def run(self, target_url: str, login_url: str) -> AuditResult:
        target_url = self._normalize_url(target_url)
        login_url = self._normalize_url(login_url)
        self._validate_same_host(target_url, login_url)
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []
        metadata: dict[str, object] = {}

        with httpx.Client(
            headers=self.headers,
            timeout=self.timeout,
            follow_redirects=True,
            verify=True,
        ) as client:
            response = client.get(target_url)
            metadata["target_status"] = response.status_code
            metadata["final_url"] = str(response.url)
            findings.extend(self._transport_checks(target_url, response))
            findings.extend(self._header_checks(response))

            login_response = client.get(login_url)
            metadata["login_status"] = login_response.status_code
            metadata["login_final_url"] = str(login_response.url)
            findings.extend(self._login_checks(login_url, login_response))
            findings.extend(self._cookie_checks(login_response))

        tls_metadata, tls_findings = self._tls_checks(target_url)
        metadata.update(tls_metadata)
        findings.extend(tls_findings)

        possible = sum(item.weight for item in findings if item.weight > 0)
        earned = sum(item.earned for item in findings if item.weight > 0)
        score = round((earned / possible) * 100) if possible else 0
        risk = self._risk_from_score(score)
        failed = sum(1 for item in findings if item.status == "FAIL")
        warned = sum(1 for item in findings if item.status == "WARN")
        passed = sum(1 for item in findings if item.status == "PASS")
        summary = f"{passed} controles aprovados, {warned} alertas e {failed} falhas identificadas."
        finished = datetime.now(timezone.utc)

        return AuditResult(
            target_url=target_url,
            login_url=login_url,
            final_url=str(metadata.get("final_url", target_url)),
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            score=score,
            risk=risk,
            summary=summary,
            findings=findings,
            metadata=metadata,
        )

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
            raise ValueError("O alvo e a página de login devem pertencer ao mesmo host.")

    def _transport_checks(self, target_url: str, response: httpx.Response) -> list[Finding]:
        findings: list[Finding] = []
        target = urlparse(target_url)
        final = urlparse(str(response.url))
        https_ok = final.scheme == "https"
        findings.append(
            self._finding(
                "https",
                "HTTPS ativo",
                "Transporte",
                https_ok,
                "A conexão final utiliza HTTPS." if https_ok else "A conexão final não utiliza HTTPS.",
                "Obrigar HTTPS em todas as páginas e redirecionar acessos HTTP.",
                15,
            )
        )

        if target.scheme == "https":
            http_url = target_url.replace("https://", "http://", 1)
            try:
                with httpx.Client(headers=self.headers, timeout=self.timeout, follow_redirects=False) as client:
                    http_response = client.get(http_url)
                location = http_response.headers.get("location", "")
                redirect_ok = http_response.status_code in {301, 302, 307, 308} and location.startswith("https://")
            except Exception:
                redirect_ok = False
            findings.append(
                self._finding(
                    "https_redirect",
                    "Redirecionamento HTTP para HTTPS",
                    "Transporte",
                    redirect_ok,
                    "O acesso HTTP é redirecionado para HTTPS." if redirect_ok else "Não foi confirmado redirecionamento direto de HTTP para HTTPS.",
                    "Configurar redirecionamento permanente de HTTP para HTTPS.",
                    7,
                )
            )
        return findings

    def _header_checks(self, response: httpx.Response) -> list[Finding]:
        headers = {key.lower(): value for key, value in response.headers.items()}
        checks = [
            (
                "hsts",
                "Strict-Transport-Security",
                "Cabeçalhos",
                "strict-transport-security" in headers,
                "HSTS está presente.",
                "Adicionar Strict-Transport-Security com política adequada.",
                8,
            ),
            (
                "csp",
                "Content-Security-Policy",
                "Cabeçalhos",
                "content-security-policy" in headers,
                "CSP está presente.",
                "Definir uma Content-Security-Policy compatível com a aplicação.",
                8,
            ),
            (
                "nosniff",
                "X-Content-Type-Options",
                "Cabeçalhos",
                headers.get("x-content-type-options", "").lower() == "nosniff",
                "X-Content-Type-Options está configurado como nosniff.",
                "Definir X-Content-Type-Options: nosniff.",
                5,
            ),
            (
                "frame",
                "Proteção contra framing",
                "Cabeçalhos",
                "x-frame-options" in headers or "frame-ancestors" in headers.get("content-security-policy", ""),
                "Foi identificada proteção contra carregamento indevido em frames.",
                "Configurar X-Frame-Options ou frame-ancestors na CSP.",
                5,
            ),
            (
                "referrer",
                "Referrer-Policy",
                "Cabeçalhos",
                "referrer-policy" in headers,
                "Referrer-Policy está presente.",
                "Definir Referrer-Policy adequada à aplicação.",
                4,
            ),
            (
                "permissions",
                "Permissions-Policy",
                "Cabeçalhos",
                "permissions-policy" in headers,
                "Permissions-Policy está presente.",
                "Definir Permissions-Policy para limitar recursos desnecessários.",
                4,
            ),
        ]
        findings = [self._finding(*item) for item in checks]
        server = headers.get("server", "")
        revealing = any(token in server.lower() for token in ["apache/", "nginx/", "iis/", "gunicorn/"])
        findings.append(
            Finding(
                key="server_disclosure",
                title="Exposição de tecnologia do servidor",
                category="Exposição",
                status="WARN" if revealing else "PASS",
                detail=f"Cabeçalho Server informado: {server}." if server else "Nenhuma versão detalhada de servidor foi observada.",
                recommendation="Reduzir banners e informações de versão desnecessárias." if revealing else "Manter a exposição de tecnologia minimizada.",
                weight=3,
                earned=1 if revealing else 3,
            )
        )
        return findings

    def _cookie_checks(self, response: httpx.Response) -> list[Finding]:
        raw_cookies = response.headers.get_list("set-cookie")
        if not raw_cookies:
            return [
                Finding(
                    key="cookies",
                    title="Cookies de sessão",
                    category="Sessão",
                    status="WARN",
                    detail="Nenhum cookie foi emitido na página analisada.",
                    recommendation="Executar a auditoria em uma rota que estabeleça sessão para validar atributos de cookie.",
                    weight=0,
                    earned=0,
                )
            ]
        secure = False
        httponly = False
        samesite = False
        for raw in raw_cookies:
            lower = raw.lower()
            secure = secure or "; secure" in lower
            httponly = httponly or "; httponly" in lower
            samesite = samesite or "samesite=" in lower
        return [
            self._finding(
                "cookie_secure",
                "Cookie Secure",
                "Sessão",
                secure,
                "Ao menos um cookie analisado utiliza Secure." if secure else "Não foi observado Secure nos cookies emitidos.",
                "Marcar cookies de sessão como Secure em HTTPS.",
                6,
            ),
            self._finding(
                "cookie_httponly",
                "Cookie HttpOnly",
                "Sessão",
                httponly,
                "Ao menos um cookie analisado utiliza HttpOnly." if httponly else "Não foi observado HttpOnly nos cookies emitidos.",
                "Marcar cookies de sessão como HttpOnly.",
                6,
            ),
            self._finding(
                "cookie_samesite",
                "Cookie SameSite",
                "Sessão",
                samesite,
                "Ao menos um cookie analisado define SameSite." if samesite else "Não foi observado SameSite nos cookies emitidos.",
                "Definir SameSite de acordo com o fluxo de autenticação.",
                5,
            ),
        ]

    def _login_checks(self, login_url: str, response: httpx.Response) -> list[Finding]:
        findings: list[Finding] = []
        soup = BeautifulSoup(response.text, "html.parser")
        password = soup.find("input", attrs={"type": "password"})
        findings.append(
            self._finding(
                "password_field",
                "Campo de senha identificado",
                "Autenticação",
                password is not None,
                "A página contém um campo de senha." if password else "Não foi identificado campo de senha no HTML retornado.",
                "Confirmar a rota de login e garantir formulário de autenticação adequado.",
                4,
            )
        )

        form = password.find_parent("form") if password else None
        method = (form.get("method", "get").lower() if form else "")
        post_ok = method == "post"
        findings.append(
            self._finding(
                "login_post",
                "Login enviado por POST",
                "Autenticação",
                post_ok,
                "O formulário de login utiliza POST." if post_ok else "O formulário de login não utiliza POST ou não foi identificado.",
                "Enviar credenciais por POST sobre HTTPS.",
                8,
            )
        )

        autocomplete = (password.get("autocomplete", "").lower() if password else "")
        autocomplete_ok = autocomplete in {"current-password", "new-password"}
        findings.append(
            Finding(
                key="password_autocomplete",
                title="Semântica de autocomplete da senha",
                category="Autenticação",
                status="PASS" if autocomplete_ok else "WARN",
                detail=f"autocomplete={autocomplete}." if autocomplete else "O campo de senha não informa autocomplete.",
                recommendation="Usar current-password em login e new-password em criação ou troca de senha.",
                weight=2,
                earned=2 if autocomplete_ok else 1,
            )
        )

        action = form.get("action", "") if form else ""
        action_url = urljoin(login_url + "/", action) if action else login_url
        same_host = urlparse(action_url).hostname == urlparse(login_url).hostname
        findings.append(
            self._finding(
                "login_action_host",
                "Destino do formulário no mesmo host",
                "Autenticação",
                same_host,
                "O formulário envia dados para o mesmo host." if same_host else "O formulário direciona dados para outro host.",
                "Confirmar que credenciais sejam enviadas somente a destinos autorizados.",
                5,
            )
        )
        return findings

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
                    metadata["tls_version"] = secure_sock.version()
                    cipher = secure_sock.cipher()
                    metadata["cipher"] = cipher[0] if cipher else ""
                    not_after = cert.get("notAfter")
                    days_left = None
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_left = (expiry - datetime.now(timezone.utc)).days
                        metadata["certificate_days_left"] = days_left
                    findings = [
                        Finding(
                            key="tls_certificate",
                            title="Certificado TLS válido",
                            category="Transporte",
                            status="PASS",
                            detail=f"Certificado validado para {host}." + (f" Restam aproximadamente {days_left} dias." if days_left is not None else ""),
                            recommendation="Manter renovação automática e monitoramento de validade.",
                            weight=8,
                            earned=8,
                        )
                    ]
                    return metadata, findings
        except Exception as exc:
            return metadata, [
                Finding(
                    key="tls_certificate",
                    title="Certificado TLS válido",
                    category="Transporte",
                    status="FAIL",
                    detail=f"Não foi possível validar a conexão TLS: {exc}",
                    recommendation="Corrigir certificado, cadeia de confiança e configuração TLS.",
                    weight=8,
                    earned=0,
                )
            ]

    def _finding(
        self,
        key: str,
        title: str,
        category: str,
        ok: bool,
        pass_detail: str,
        recommendation: str,
        weight: int,
    ) -> Finding:
        return Finding(
            key=key,
            title=title,
            category=category,
            status="PASS" if ok else "FAIL",
            detail=pass_detail,
            recommendation=recommendation,
            weight=weight,
            earned=weight if ok else 0,
        )

    def _risk_from_score(self, score: int) -> str:
        if score >= 90:
            return "BAIXO"
        if score >= 75:
            return "MODERADO"
        if score >= 55:
            return "ELEVADO"
        return "ALTO"
