from __future__ import annotations

import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .models import Finding, LabAttemptRecord, LabSimulationResult


class LabSimulationEngine:
    ALLOWED_HOSTS = {"aegis-auth-lab.onrender.com", "localhost", "127.0.0.1", "::1"}

    def __init__(self, timeout: float = 12.0) -> None:
        self.timeout = timeout
        self.headers = {
            "User-Agent": "AegisAuthAuditor/3.0-Lab",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        }

    def run(self, login_url: str, username: str, decoy_password: str, correct_password: str, attempts: int, correct_attempt: int, interval_seconds: float) -> LabSimulationResult:
        login_url = self._normalize_url(login_url)
        self._validate(login_url, username, decoy_password, correct_password, attempts, correct_attempt, interval_seconds)
        started = datetime.now(timezone.utc)
        records: list[LabAttemptRecord] = []
        protection_triggered = False
        success_reached = False
        protection_before_correct = False
        action_url = login_url
        method = ""
        username_field = ""
        password_field = ""

        with httpx.Client(headers=self.headers, timeout=self.timeout, follow_redirects=False, verify=True) as client:
            for number in range(1, attempts + 1):
                page = client.get(login_url)
                if page.status_code >= 500:
                    records.append(LabAttemptRecord(number, "VALID" if number == correct_attempt else "DECOY", page.status_code, 0, "SERVER_ERROR", False, page.headers.get("retry-after", "")))
                    if number < attempts:
                        time.sleep(interval_seconds)
                    continue
                form_info = self._parse_form(login_url, page)
                method = str(form_info["method"])
                action_url = str(form_info["action_url"])
                username_field = str(form_info["username_field"])
                password_field = str(form_info["password_field"])
                payload = dict(form_info["hidden_fields"])
                is_valid_attempt = number == correct_attempt
                payload[username_field] = username
                payload[password_field] = correct_password if is_valid_attempt else decoy_password
                request_started = time.perf_counter()
                response = client.post(action_url, data=payload) if method == "post" else client.get(action_url, params=payload)
                elapsed_ms = round((time.perf_counter() - request_started) * 1000)
                signal, retry_after = self._classify_response(response)
                success = self._is_success(response, login_url) if is_valid_attempt else False
                records.append(LabAttemptRecord(number, "VALID" if is_valid_attempt else "DECOY", response.status_code, elapsed_ms, signal, success, retry_after))
                if signal in {"RATE_LIMIT", "LOCKOUT", "BLOCKED"}:
                    protection_triggered = True
                    if number <= correct_attempt:
                        protection_before_correct = True
                    break
                if is_valid_attempt:
                    success_reached = success
                    break
                if number < attempts:
                    time.sleep(interval_seconds)

        findings = self._build_findings(success_reached, protection_triggered, protection_before_correct, correct_attempt, len(records))
        verdict, risk = self._verdict(success_reached, protection_before_correct)
        finished = datetime.now(timezone.utc)
        summary = self._summary(success_reached, protection_triggered, correct_attempt, len(records))
        metadata = {
            "allowlisted_host": urlparse(login_url).hostname,
            "form_method": method.upper(),
            "form_action": action_url,
            "username_field": username_field,
            "password_field": password_field,
            "credentials_stored": False,
            "known_valid_credential_required": True,
            "discovery_performed": False,
        }
        return LabSimulationResult(
            login_url=login_url,
            account_hint=self._mask_identifier(username),
            started_at=started.isoformat(),
            finished_at=finished.isoformat(),
            attempts_requested=attempts,
            attempts_completed=len(records),
            correct_attempt_number=correct_attempt,
            success_reached=success_reached,
            protection_triggered=protection_triggered,
            verdict=verdict,
            risk=risk,
            summary=summary,
            findings=findings,
            attempts=records,
            metadata=metadata,
        )

    def _normalize_url(self, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Informe a URL de login do laboratório.")
        if not value.startswith(("http://", "https://")):
            value = "https://" + value
        parsed = urlparse(value)
        if not parsed.hostname:
            raise ValueError("Informe uma URL válida.")
        return value

    def _validate(self, login_url: str, username: str, decoy_password: str, correct_password: str, attempts: int, correct_attempt: int, interval_seconds: float) -> None:
        parsed = urlparse(login_url)
        if parsed.hostname not in self.ALLOWED_HOSTS:
            raise ValueError("O modo privado desta versão é restrito ao Aegis Auth Lab e a ambientes locais.")
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("O laboratório remoto exige HTTPS.")
        if not username.strip() or not decoy_password or not correct_password:
            raise ValueError("Informe conta, senha de teste incorreta e credencial válida conhecida do laboratório.")
        if decoy_password == correct_password:
            raise ValueError("A senha incorreta de teste deve ser diferente da credencial válida conhecida.")
        if attempts < 5 or attempts > 20:
            raise ValueError("Use entre 5 e 20 tentativas.")
        if correct_attempt < 2 or correct_attempt > attempts:
            raise ValueError("A tentativa válida deve ocorrer entre a segunda e a última tentativa.")
        if interval_seconds < 1.0 or interval_seconds > 5.0:
            raise ValueError("Use intervalo entre 1 e 5 segundos.")

    def _parse_form(self, login_url: str, response: httpx.Response) -> dict[str, object]:
        soup = BeautifulSoup(response.text, "html.parser")
        password = soup.find("input", attrs={"type": lambda value: value and value.lower() == "password"})
        if password is None:
            raise ValueError("Não foi identificado campo de senha no laboratório.")
        form = password.find_parent("form")
        if form is None:
            raise ValueError("Não foi identificado formulário de autenticação.")
        password_field = str(password.get("name", "")).strip()
        username = self._find_username_input(form)
        if username is None or not password_field:
            raise ValueError("O formulário não possui campos identificáveis de usuário e senha.")
        username_field = str(username.get("name", "")).strip()
        method = str(form.get("method", "get")).lower()
        action = str(form.get("action", "")).strip()
        action_url = urljoin(str(response.url), action) if action else str(response.url)
        if urlparse(action_url).hostname != urlparse(login_url).hostname:
            raise ValueError("O formulário direciona credenciais para outro host.")
        hidden_fields: dict[str, str] = {}
        for item in form.find_all("input", attrs={"type": "hidden"}):
            name = str(item.get("name", "")).strip()
            if name:
                hidden_fields[name] = str(item.get("value", ""))
        return {"method": method, "action_url": action_url, "username_field": username_field, "password_field": password_field, "hidden_fields": hidden_fields}

    def _find_username_input(self, form):
        candidates = []
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
            candidates.append((score, item))
        if not candidates:
            return None
        candidates.sort(key=lambda pair: pair[0], reverse=True)
        return candidates[0][1]

    def _classify_response(self, response: httpx.Response) -> tuple[str, str]:
        retry_after = response.headers.get("retry-after", "")
        text = response.text[:250000].lower()
        if response.status_code == 429 or retry_after or any(term in text for term in ["too many requests", "rate limit", "muitas tentativas", "tentativas demais", "limite de tentativas"]):
            return "RATE_LIMIT", retry_after
        if any(term in text for term in ["account locked", "temporarily locked", "conta bloqueada", "bloqueado temporariamente", "tente novamente mais tarde", "try again later"]):
            return "LOCKOUT", retry_after
        if response.status_code == 403:
            return "BLOCKED", retry_after
        if response.status_code >= 500:
            return "SERVER_ERROR", retry_after
        return "NORMAL", retry_after

    def _is_success(self, response: httpx.Response, login_url: str) -> bool:
        if response.status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get("location", "")
            if location and urljoin(login_url, location).rstrip("/") != login_url.rstrip("/"):
                return True
        if 200 <= response.status_code < 300:
            soup = BeautifulSoup(response.text, "html.parser")
            password = soup.find("input", attrs={"type": lambda value: value and value.lower() == "password"})
            if password is None:
                return True
        return False

    def _build_findings(self, success_reached: bool, protection_triggered: bool, protection_before_correct: bool, correct_attempt: int, completed: int) -> list[Finding]:
        findings: list[Finding] = []
        if protection_before_correct:
            findings.append(Finding("lab_block", "Proteção antes da credencial válida", "Laboratório", "PASS", f"A proteção foi acionada antes da tentativa válida planejada na posição {correct_attempt}.", "Manter limitação de tentativas e revisar limites conforme risco e experiência do usuário.", 40, 40, "CRÍTICA"))
        elif success_reached:
            findings.append(Finding("lab_block", "Proteção antes da credencial válida", "Laboratório", "FAIL", f"Uma credencial válida conhecida foi aceita na tentativa {correct_attempt} após falhas consecutivas sem bloqueio detectável.", "Implementar rate limiting e bloqueio temporário para reduzir a janela de tentativas automatizadas.", 40, 0, "CRÍTICA"))
        else:
            findings.append(Finding("lab_block", "Proteção antes da credencial válida", "Laboratório", "INCONCLUSIVE", "A simulação terminou sem confirmação de bloqueio e sem confirmação de autenticação válida.", "Revisar a conta de laboratório e repetir o teste controlado.", 40, 0, "ALTA"))
        findings.append(Finding("known_credential", "Demonstração de impacto", "Laboratório", "FAIL" if success_reached and not protection_before_correct else "PASS" if protection_before_correct else "INCONCLUSIVE", "A credencial válida conhecida alcançou autenticação após a sequência de falhas." if success_reached else "A credencial válida conhecida não alcançou autenticação durante a sequência executada.", "Usar apenas contas dedicadas e manter a demonstração restrita ao laboratório autorizado.", 30, 0 if success_reached and not protection_before_correct else 30 if protection_before_correct else 0, "ALTA"))
        findings.append(Finding("scope", "Escopo restrito", "Governança", "PASS", f"Execução restrita a host permitido, uma conta e no máximo {completed} requisições realizadas.", "Manter o modo restrito a ambientes de laboratório e credenciais de teste conhecidas.", 20, 20, "ALTA"))
        findings.append(Finding("discovery", "Descoberta de credencial desconhecida", "Governança", "PASS", "Nenhum mecanismo de descoberta de senha desconhecida foi executado; a credencial válida é fornecida previamente pelo responsável pelo laboratório.", "Preservar a separação entre demonstração controlada e descoberta de credenciais.", 10, 10, "MÉDIA"))
        return findings

    def _verdict(self, success_reached: bool, protection_before_correct: bool) -> tuple[str, str]:
        if protection_before_correct:
            return "PROTEÇÃO INTERROMPEU A SEQUÊNCIA", "BAIXO"
        if success_reached:
            return "IMPACTO DEMONSTRADO NO LABORATÓRIO", "ALTO"
        return "RESULTADO INCONCLUSIVO", "MODERADO"

    def _summary(self, success_reached: bool, protection_triggered: bool, correct_attempt: int, completed: int) -> str:
        if success_reached:
            return f"Após tentativas incorretas controladas, a credencial válida conhecida foi aceita na tentativa {correct_attempt}; {completed} requisições foram realizadas."
        if protection_triggered:
            return f"A proteção do laboratório interrompeu a sequência antes da credencial válida planejada; {completed} requisições foram realizadas."
        return f"A sequência terminou sem confirmação de autenticação válida ou bloqueio; {completed} requisições foram realizadas."

    def _mask_identifier(self, value: str) -> str:
        value = value.strip()
        if "@" in value:
            local, domain = value.split("@", 1)
            return f"{local[:2]}***@{domain}"
        return f"{value[:2]}***"
