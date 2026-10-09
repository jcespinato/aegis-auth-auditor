from __future__ import annotations

import hashlib
import os
import statistics
import time
from datetime import datetime, timezone

from .models import HashBenchmarkResult


class HashBenchmark:
    PROFILES = {
        "scrypt-16384": {"kind": "scrypt", "n": 16384, "r": 8, "p": 1},
        "scrypt-32768": {"kind": "scrypt", "n": 32768, "r": 8, "p": 1},
        "pbkdf2-300k": {"kind": "pbkdf2", "iterations": 300000},
        "pbkdf2-600k": {"kind": "pbkdf2", "iterations": 600000},
    }

    def run(self, profile: str, samples: int) -> HashBenchmarkResult:
        if profile not in self.PROFILES:
            raise ValueError("Selecione um perfil de hash válido.")
        if samples < 3 or samples > 10:
            raise ValueError("Use entre 3 e 10 amostras.")
        config = self.PROFILES[profile]
        password = os.urandom(24).hex().encode("utf-8")
        salt = os.urandom(16)
        timings: list[float] = []
        for _ in range(samples):
            started = time.perf_counter()
            if config["kind"] == "scrypt":
                hashlib.scrypt(password, salt=salt, n=int(config["n"]), r=int(config["r"]), p=int(config["p"]), dklen=32, maxmem=128 * 1024 * 1024)
            else:
                hashlib.pbkdf2_hmac("sha256", password, salt, int(config["iterations"]), dklen=32)
            timings.append((time.perf_counter() - started) * 1000)
        median_ms = statistics.median(timings)
        vps = 1000 / median_ms if median_ms > 0 else 0.0
        rating = self._rating(median_ms)
        summary = f"Mediana de {median_ms:.1f} ms por derivação no computador local; classificação de custo {rating.lower()}."
        metadata = {
            "profile": profile,
            "kind": config["kind"],
            "parameters": {key: value for key, value in config.items() if key != "kind"},
            "synthetic_secret": True,
            "real_password_used": False,
        }
        return HashBenchmarkResult(
            created_at=datetime.now(timezone.utc).isoformat(),
            algorithm=profile,
            samples=samples,
            median_ms=round(median_ms, 2),
            minimum_ms=round(min(timings), 2),
            maximum_ms=round(max(timings), 2),
            verifications_per_second=round(vps, 2),
            rating=rating,
            summary=summary,
            metadata=metadata,
        )

    def _rating(self, median_ms: float) -> str:
        if median_ms >= 250:
            return "ALTO"
        if median_ms >= 100:
            return "ADEQUADO"
        if median_ms >= 40:
            return "MODERADO"
        return "BAIXO"
