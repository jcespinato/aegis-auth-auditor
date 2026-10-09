from __future__ import annotations

import statistics
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .models import ActiveAuthResult, AttemptRecord, Finding


class ActiveAuthEngine:
    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self.headers = {
            "User-Agent": "AegisAuthAuditor/2.0",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        }

    def run(self, login_url: str, username: str, wrong_password: str, attempts: int, interval_seconds: float) -> ActiveAuthResult:
        login_url = self._normalize_url(login_url)
        self._validate_parameters(login_url, username, wrong_password, attempts, interval_seconds)
        started = datetime.now(timezone.utc)
        records: list[AttemptRecord] = []
        block_signals = 0
        retry_after_seen = False
        server_errors = 0
        method = ""
        action_url = login_url
        username_field = ""
        password_field = ""

        with httpx.Client(headers=self.headers, timeout=self.timeout, follow_redirects=False, verify=True) as client:
            for number in range(1, attempts + 1):
                page = client.get(login_url)
                if page.status_code >= 500:
                    elapsed = 0
                    records.append(AttemptRecord(number, page.status_code, elapsed, "SERVER_ERROR", page.headers.get("retry-after", "")))
                    server_errors += 1
                    if number < attempts:
                        time.sleep(interval_seconds)
                    continue

                form_info = self._parse_form(login_url, page)
                method = form_info["method"]
                action_url = form_info["action_url"]
                username_field = form_info["username_field"]
                password_field = form_info["password_field"]
                data = dict(form_info["hidden_fields"])
                data[username_field] = username
                data[password_field] = wrong_password

                request_started = time.perf_counter()
                if method == "post":
                    response = client.post(action_url, data=data)
                else:
                    response = client.get(action_url, params=data)
                elapsed_ms = round((time.perf_counter() - request_started) * 1000)
                signal, retry_after = self._classify_response(response)
                records.append(AttemptRecord(number, response.status_code, elapsed_ms, signal, retry_after))

                if signal in {"RATE_LIMIT", "LOCKOUT", "BLOCKED"}:
                    block_signals += 1
                if retry_after:
                    retry_after_seen = True
                if signal == "SERVER_ERROR":
                    server_errors += 1

                if signal == "RATE_LIMIT":
                    break
                if block_signals >= 2:
                    break
                if number < attempts:
                    time.sleep(interval_seconds)

        timings = [record.elapsed_ms for record in records if record.elapsed_ms > 0 and record.signal != "SERVER_ERROR"]
        progressive, timing_detail = self._progressive_delay(timings)
        protection_detected = block_signals > 0
        completed = len(records)
        findings = self._build_findings(protection_detected, block_signals, retry_after_seen, progressive, timing_detail, server_errors, completed)
        score = self._score(findings)
        risk = self._risk_from_score(score)
        verdict = self._verdict(protection_detected, progressive, server_errors)
        finished = datetime.now(timezone.utc)
        summary = f"{completed} tentativas controladas concluídas; {block_signals} sinais de limitação ou bloqueio; {server_errors} erros de servidor."
        metadata = {
            "form_method": method.upper(),
            "form_action": action_url,
            "username_field": username_field,
            "password_field": password_field,
            "blocked_signals": block_signals,
            "retry_after_seen": retry_after_seen,
            "progressive_delay_detected": progressive,
            "median_latency_ms": round(statistics.median(timings)) if timings else 0,
            "max_latency_ms": max(timings) if timings else 0,
            "server_errors": server_errors,
        }
        return ActiveAuthResult(
            login_url=login_url,
            account_hint=self._mask_identifier(username),
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            attempts_requested=attempts,
            attempts_completed=completed,
            interval_seconds=interval_seconds,
            score=score,
            risk=risk,
            verdict=verdict,
            summary=summary,
            findings=findings,
            attempts=records,
            metadata=metadata,
        )

    def _normalize_url(self, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Informe a URL de login.")
        if not value.startswith(("http://", "https://")):
            value = "https://" + value
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Informe uma URL HTTP ou HTTPS válida.")
        return value

    def _validate_parameters(self, login_url: str, username: str, wrong_password: str, attempts: int, interval_seconds: float) -> None:
        parsed = urlparse(login_url)
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("O teste ativo exige HTTPS, exceto em ambiente local.")
        if not username.strip():
            raise ValueError("Informe a conta de teste.")
        if not wrong_password:
            raise ValueError("Informe uma senha propositalmente incorreta para o teste.")
        if attempts < 5 or attempts > 20:
            raise ValueError("Use entre 5 e 20 tentativas por execução.")
        if interval_seconds < 0.75 or interval_seconds > 5.0:
            raise ValueError("Use intervalo entre 0,75 e 5 segundos.")

    def _parse_form(self, login_url: str, response: httpx.Response) -> dict[str, object]:
        soup = BeautifulSoup(response.text, "html.parser")
        password = soup.find("input", attrs={"type": lambda value: value and value.lower() == "password"})
        if password is None:
            raise ValueError("Não foi identificado formulário de senha na rota informada.")
        form = password.find_parent("form")
        if form is None:
            raise ValueError("O campo de senha não pertence a um formulário HTML identificável.")
        password_field = str(password.get("name", "")).strip()
        if not password_field:
            raise ValueError("O campo de senha não possui nome de envio.")
        username = self._find_username_input(form)
        if username is None:
            raise ValueError("Não foi identificado campo de usuário ou e-mail no formulário.")
        username_field = str(username.get("name", "")).strip()
        method = str(form.get("method", "get")).lower()
        if method not in {"post", "get"}:
            raise ValueError("O método do formulário não é suportado por este módulo.")
        action = str(form.get("action", "")).strip()
        action_url = urljoin(str(response.url), action) if action else str(response.url)
        if urlparse(action_url).hostname != urlparse(login_url).hostname:
            raise ValueError("O formulário envia credenciais para outro host e o teste foi interrompido.")
        hidden_fields: dict[str, str] = {}
        for item in form.find_all("input", attrs={"type": "hidden"}):
            name = str(item.get("name", "")).strip()
            if name:
                hidden_fields[name] = str(item.get("value", ""))
        return {
            "method": method,
            "action_url": action_url,
            "username_field": username_field,
            "password_field": password_field,
            "hidden_fields": hidden_fields,
        }

    def _find_username_input(self, form):
        scored = []
        for item in form.find_all("input"):
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

    def _classify_response(self, response: httpx.Response) -> tuple[str, str]:
        retry_after = response.headers.get("retry-after", "")
        text = response.text[:250000].lower()
        rate_terms = ["too many requests", "rate limit", "muitas tentativas", "tentativas demais", "limite de tentativas"]
        lock_terms = ["account locked", "temporarily locked", "conta bloqueada", "bloqueado temporariamente", "tente novamente mais tarde", "try again later"]
        if response.status_code == 429 or retry_after or any(term in text for term in rate_terms):
            return "RATE_LIMIT", retry_after
        if any(term in text for term in lock_terms):
            return "LOCKOUT", retry_after
        if response.status_code == 403:
            return "BLOCKED", retry_after
        if response.status_code >= 500:
            return "SERVER_ERROR", retry_after
        return "NORMAL", retry_after

    def _progressive_delay(self, timings: list[int]) -> tuple[bool, str]:
        if len(timings) < 6:
            return False, "A quantidade de respostas válidas foi insuficiente para avaliar atraso progressivo."
        size = max(2, len(timings) // 3)
        first = statistics.median(timings[:size])
        last = statistics.median(timings[-size:])
        increase = last - first
        ratio = last / first if first > 0 else 1.0
        detected = increase >= 300 and ratio >= 1.5
        return detected, f"Mediana inicial {round(first)} ms; mediana final {round(last)} ms; variação {round(increase)} ms."

    def _build_findings(self, protection_detected: bool, block_signals: int, retry_after_seen: bool, progressive: bool, timing_detail: str, server_errors: int, completed: int) -> list[Finding]:
        findings: list[Finding] = []
        findings.append(Finding(
            "active_rate_limit",
            "Limitação de tentativas repetidas",
            "Resiliência",
            "PASS" if protection_detected else "FAIL",
            f"Foram detectados {block_signals} sinais de limitação ou bloqueio." if protection_detected else f"As {completed} tentativas concluídas não produziram sinal claro de limitação.",
            "Aplicar rate limiting por conta e origem, com limites adequados ao risco.",
            45,
            45 if protection_detected else 0,
            "CRÍTICA",
        ))
        if protection_detected:
            findings.append(Finding(
                "retry_after",
                "Orientação de nova tentativa",
                "Resiliência",
                "PASS" if retry_after_seen else "WARN",
                "Foi identificado Retry-After." if retry_after_seen else "A proteção foi acionada sem cabeçalho Retry-After.",
                "Quando aplicável, informar Retry-After em respostas de limitação HTTP 429.",
                10,
                10 if retry_after_seen else 5,
                "BAIXA",
            ))
        else:
            findings.append(Finding("retry_after", "Orientação de nova tentativa", "Resiliência", "INCONCLUSIVE", "Nenhuma resposta de limitação foi observada.", "Avaliar Retry-After quando houver resposta HTTP 429.", 10, 0, "BAIXA"))
        findings.append(Finding(
            "progressive_delay",
            "Atraso progressivo",
            "Resiliência",
            "PASS" if progressive else "WARN",
            timing_detail,
            "Considerar atraso progressivo como camada complementar ao rate limiting.",
            20,
            20 if progressive else 8,
            "MÉDIA",
        ))
        stable = server_errors == 0
        findings.append(Finding(
            "server_stability",
            "Estabilidade sob tentativas repetidas",
            "Disponibilidade",
            "PASS" if stable else "FAIL",
            "Nenhum erro 5xx ocorreu durante o teste." if stable else f"Foram observados {server_errors} erros HTTP 5xx durante o teste.",
            "Evitar que controles de autenticação causem indisponibilidade do serviço.",
            15,
            15 if stable else 0,
            "ALTA",
        ))
        findings.append(Finding(
            "controlled_scope",
            "Escopo controlado da execução",
            "Governança",
            "PASS",
            f"Execução limitada a {completed} tentativas, uma única conta e uma única senha incorreta.",
            "Manter limites, autorização formal e contas de teste dedicadas.",
            10,
            10,
            "MÉDIA",
        ))
        return findings

    def _score(self, findings: list[Finding]) -> int:
        scoreable = [item for item in findings if item.weight > 0 and item.status != "INCONCLUSIVE"]
        possible = sum(item.weight for item in scoreable)
        earned = sum(item.earned for item in scoreable)
        return round((earned / possible) * 100) if possible else 0

    def _risk_from_score(self, score: int) -> str:
        if score >= 90:
            return "BAIXO"
        if score >= 75:
            return "MODERADO"
        if score >= 55:
            return "ELEVADO"
        return "ALTO"

    def _verdict(self, protection_detected: bool, progressive: bool, server_errors: int) -> str:
        if server_errors:
            return "INSTABILIDADE DETECTADA"
        if protection_detected:
            return "PROTEÇÃO DETECTADA"
        if progressive:
            return "PROTEÇÃO PARCIAL"
        return "SEM LIMITAÇÃO DETECTÁVEL"

    def _mask_identifier(self, value: str) -> str:
        value = value.strip()
        if "@" in value:
            local, domain = value.split("@", 1)
            prefix = local[:2] if len(local) > 1 else local[:1]
            return f"{prefix}***@{domain}"
        prefix = value[:2] if len(value) > 1 else value[:1]
        return f"{prefix}***"
