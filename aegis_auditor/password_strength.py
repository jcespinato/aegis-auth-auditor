from __future__ import annotations

import math
import re
import time
from datetime import datetime, timezone

from .models import Finding, PasswordAnalysisResult


COMMON_TERMS = {
    "password", "senha", "admin", "administrator", "qwerty", "abc123", "letmein", "welcome",
    "login", "user", "usuario", "teste", "test", "iloveyou", "dragon", "monkey", "football",
    "123456", "12345678", "123456789", "123123", "111111", "000000", "senha123", "password123",
}

SEQUENCES = (
    "0123456789", "9876543210", "abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqponmlkjihgfedcba",
    "qwertyuiop", "poiuytrewq", "asdfghjkl", "lkjhgfdsa", "zxcvbnm", "mnbvcxz",
)


class PasswordAnalyzer:
    def analyze(self, password: str) -> PasswordAnalysisResult:
        if not password:
            raise ValueError("Informe uma senha de laboratório para análise local.")
        if len(password) > 256:
            raise ValueError("A senha de laboratório deve ter no máximo 256 caracteres.")
        started = time.perf_counter()
        length = len(password)
        pool = self._pool_size(password)
        raw_entropy = length * math.log2(pool) if pool > 1 else 0.0
        findings = self._findings(password, raw_entropy)
        penalties = sum(max(0, item.weight - item.earned) for item in findings)
        score = max(0, min(100, round(100 - penalties)))
        if length < 8:
            score = min(score, 25)
        elif length < 12:
            score = min(score, 60)
        demo_found, demo_attempts = self._demo_search(password)
        if demo_found:
            score = min(score, 30)
        adjusted_entropy = max(1.0, raw_entropy * (0.35 + 0.65 * score / 100))
        search_space = self._format_search_space(adjusted_entropy)
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        rating = self._rating(score)
        summary = f"Robustez {rating.lower()}; {length} caracteres; estimativa relativa de espaço de busca {search_space}."
        metadata = {
            "uppercase": any(c.isupper() for c in password),
            "lowercase": any(c.islower() for c in password),
            "digits": any(c.isdigit() for c in password),
            "symbols": any(not c.isalnum() for c in password),
            "local_only": True,
            "password_stored": False,
            "demo_candidate_limit": 50000,
        }
        return PasswordAnalysisResult(
            created_at=datetime.now(timezone.utc).isoformat(),
            score=score,
            rating=rating,
            length=length,
            entropy_bits=round(adjusted_entropy, 1),
            search_space=search_space,
            demo_found=demo_found,
            demo_attempts=demo_attempts,
            demo_elapsed_ms=elapsed_ms,
            summary=summary,
            findings=findings,
            metadata=metadata,
        )

    def _pool_size(self, password: str) -> int:
        size = 0
        if any(c.islower() for c in password):
            size += 26
        if any(c.isupper() for c in password):
            size += 26
        if any(c.isdigit() for c in password):
            size += 10
        if any(not c.isalnum() for c in password):
            size += 33
        return max(size, 1)

    def _findings(self, password: str, raw_entropy: float) -> list[Finding]:
        lower = password.lower()
        findings: list[Finding] = []
        length_ok = len(password) >= 12
        findings.append(Finding("length", "Comprimento", "Senha", "PASS" if length_ok else "FAIL", f"Comprimento observado: {len(password)} caracteres.", "Preferir senhas longas e exclusivas, com pelo menos 12 caracteres quando possível.", 25, 25 if length_ok else max(0, min(20, len(password) * 2)), "ALTA"))
        diversity = sum([any(c.islower() for c in password), any(c.isupper() for c in password), any(c.isdigit() for c in password), any(not c.isalnum() for c in password)])
        findings.append(Finding("diversity", "Diversidade de caracteres", "Senha", "PASS" if diversity >= 3 else "WARN", f"Foram identificadas {diversity} de 4 categorias de caracteres.", "Evitar padrões previsíveis e priorizar comprimento, exclusividade e variedade quando isso não prejudicar a memorização.", 15, min(15, diversity * 4), "MÉDIA"))
        common = lower in COMMON_TERMS or any(term in lower for term in COMMON_TERMS if len(term) >= 6)
        findings.append(Finding("common", "Termos comuns", "Senha", "FAIL" if common else "PASS", "Foi identificado termo comum ou previsível." if common else "Não foram identificados termos comuns no conjunto local de referência.", "Evitar palavras, nomes e combinações amplamente previsíveis.", 20, 0 if common else 20, "ALTA"))
        sequence = self._has_sequence(lower)
        findings.append(Finding("sequence", "Sequências previsíveis", "Senha", "WARN" if sequence else "PASS", "Foi identificada sequência previsível." if sequence else "Não foram identificadas sequências simples de teclado, alfabeto ou números.", "Evitar sequências como 1234, qwerty e progressões alfabéticas.", 15, 5 if sequence else 15, "MÉDIA"))
        repeated = bool(re.search(r"(.)\1{2,}", lower)) or self._repeated_block(lower)
        findings.append(Finding("repeat", "Repetição", "Senha", "WARN" if repeated else "PASS", "Foram identificadas repetições que reduzem imprevisibilidade." if repeated else "Não foram identificadas repetições simples relevantes.", "Evitar caracteres ou blocos repetidos.", 10, 4 if repeated else 10, "MÉDIA"))
        personal_pattern = bool(re.search(r"(?:19|20)\d{2}$", lower)) or bool(re.search(r"\d{4,}$", lower))
        findings.append(Finding("suffix", "Sufixos previsíveis", "Senha", "WARN" if personal_pattern else "PASS", "A senha termina com padrão numérico previsível." if personal_pattern else "Não foi identificado sufixo numérico previsível.", "Evitar anos, datas e sequências numéricas como sufixo.", 10, 4 if personal_pattern else 10, "BAIXA"))
        entropy_ok = raw_entropy >= 70
        findings.append(Finding("entropy", "Imprevisibilidade estimada", "Senha", "PASS" if entropy_ok else "WARN", f"Entropia teórica bruta aproximada: {raw_entropy:.1f} bits, antes dos ajustes por padrões.", "Aumentar comprimento e reduzir padrões previsíveis para elevar a dificuldade de adivinhação.", 5, 5 if entropy_ok else 2, "MÉDIA"))
        return findings

    def _has_sequence(self, value: str) -> bool:
        if len(value) < 4:
            return False
        for seq in SEQUENCES:
            for size in range(4, min(8, len(value)) + 1):
                for index in range(0, len(value) - size + 1):
                    if value[index:index + size] in seq:
                        return True
        return False

    def _repeated_block(self, value: str) -> bool:
        for size in range(2, min(7, len(value) // 2 + 1)):
            for index in range(0, len(value) - size * 2 + 1):
                block = value[index:index + size]
                if block and block * 2 in value:
                    return True
        return False

    def _demo_search(self, password: str) -> tuple[bool, int]:
        attempts = 0
        seen: set[str] = set()
        stems = sorted(COMMON_TERMS | {"admin", "user", "usuario", "teste", "aegis", "empresa", "sistema", "acesso"})
        suffixes = ["", "1", "12", "123", "1234", "2024", "2025", "2026", "!", "@", "#", "01"]
        transforms = [lambda s: s, lambda s: s.capitalize(), lambda s: s.upper()]
        for stem in stems:
            for transform in transforms:
                base = transform(stem)
                for suffix in suffixes:
                    candidate = base + suffix
                    if candidate in seen:
                        continue
                    seen.add(candidate)
                    attempts += 1
                    if candidate == password:
                        return True, attempts
                    if attempts >= 50000:
                        return False, attempts
        for number in range(0, 10000):
            for prefix in ("", "senha", "Senha", "password", "Password", "teste", "Teste"):
                candidate = f"{prefix}{number}"
                if candidate in seen:
                    continue
                seen.add(candidate)
                attempts += 1
                if candidate == password:
                    return True, attempts
                if attempts >= 50000:
                    return False, attempts
        return False, attempts

    def _format_search_space(self, entropy_bits: float) -> str:
        log10_guesses = entropy_bits * math.log10(2)
        if log10_guesses < 3:
            return f"~10^{max(0, round(log10_guesses, 1))} candidatos"
        return f"~10^{round(log10_guesses, 1)} candidatos"

    def _rating(self, score: int) -> str:
        if score >= 90:
            return "MUITO FORTE"
        if score >= 75:
            return "FORTE"
        if score >= 55:
            return "MODERADA"
        if score >= 35:
            return "FRACA"
        return "MUITO FRACA"
