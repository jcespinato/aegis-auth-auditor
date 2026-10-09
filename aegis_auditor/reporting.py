from __future__ import annotations

import csv
import json
from html import escape
from pathlib import Path
from typing import Any

from PySide6.QtCore import QMarginsF
from PySide6.QtGui import QPageLayout, QPageSize, QTextDocument
from PySide6.QtPrintSupport import QPrinter


def save_json(data: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def save_audit_csv(data: dict[str, Any], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle, delimiter=";")
        writer.writerow(["Status", "Severidade", "Categoria", "Controle", "Peso", "Pontuação", "Evidência", "Recomendação"])
        for item in data.get("findings", []):
            writer.writerow([
                item.get("status", ""),
                item.get("severity", ""),
                item.get("category", ""),
                item.get("title", ""),
                item.get("weight", 0),
                item.get("earned", 0),
                item.get("detail", ""),
                item.get("recommendation", ""),
            ])


def save_active_csv(data: dict[str, Any], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle, delimiter=";")
        writer.writerow(["Tentativa", "HTTP", "Tempo ms", "Sinal", "Retry-After"])
        for item in data.get("attempts", []):
            writer.writerow([
                item.get("number", ""),
                item.get("status_code", ""),
                item.get("elapsed_ms", ""),
                item.get("signal", ""),
                item.get("retry_after", ""),
            ])


def save_audit_pdf(data: dict[str, Any], path: Path) -> None:
    categories = "".join(
        f"<tr><td>{escape(str(name))}</td><td><b>{int(score)}/100</b></td></tr>"
        for name, score in data.get("category_scores", {}).items()
    )
    findings = "".join(_finding_block(item) for item in data.get("findings", []))
    metadata = data.get("metadata", {})
    html = _document_shell(
        "Relatório de Auditoria de Autenticação",
        f"""
        <div class="hero">
          <div class="score">{int(data.get('score', 0))}/100</div>
          <div><b>Risco:</b> {escape(str(data.get('risk', '')))}<br><b>Cobertura:</b> {int(data.get('coverage', 0))}%</div>
        </div>
        <table class="summary">
          <tr><td><b>Ambiente</b></td><td>{escape(str(data.get('target_url', '')))}</td></tr>
          <tr><td><b>Login</b></td><td>{escape(str(data.get('login_url', '')))}</td></tr>
          <tr><td><b>Status do ambiente</b></td><td>{escape(str(metadata.get('target_status', '')))}</td></tr>
          <tr><td><b>Status do login</b></td><td>{escape(str(metadata.get('login_status', '')))}</td></tr>
          <tr><td><b>TLS</b></td><td>{escape(str(metadata.get('tls_version', '')))} {escape(str(metadata.get('cipher', '')))}</td></tr>
          <tr><td><b>Resumo</b></td><td>{escape(str(data.get('summary', '')))}</td></tr>
        </table>
        <h2>Pontuação por categoria</h2>
        <table class="compact"><tr><th>Categoria</th><th>Score</th></tr>{categories}</table>
        <h2>Controles avaliados</h2>
        {findings}
        """,
    )
    _print_html(html, path)


def save_active_pdf(data: dict[str, Any], path: Path) -> None:
    metadata = data.get("metadata", {})
    findings = "".join(_finding_block(item) for item in data.get("findings", []))
    attempt_rows = "".join(
        f"<tr><td>{escape(str(item.get('number','')))}</td><td>{escape(str(item.get('status_code','')))}</td><td>{escape(str(item.get('elapsed_ms','')))}</td><td>{escape(str(item.get('signal','')))}</td><td>{escape(str(item.get('retry_after','')))}</td></tr>"
        for item in data.get("attempts", [])
    )
    html = _document_shell(
        "Relatório de Resistência da Autenticação",
        f"""
        <div class="hero">
          <div class="score">{int(data.get('score', 0))}/100</div>
          <div><b>Risco:</b> {escape(str(data.get('risk', '')))}<br><b>Resultado:</b> {escape(str(data.get('verdict', '')))}</div>
        </div>
        <table class="summary">
          <tr><td><b>Login</b></td><td>{escape(str(data.get('login_url', '')))}</td></tr>
          <tr><td><b>Conta de teste</b></td><td>{escape(str(data.get('account_hint', '')))}</td></tr>
          <tr><td><b>Tentativas</b></td><td>{escape(str(data.get('attempts_completed', '')))} de {escape(str(data.get('attempts_requested', '')))}</td></tr>
          <tr><td><b>Intervalo</b></td><td>{escape(str(data.get('interval_seconds', '')))} s</td></tr>
          <tr><td><b>Latência mediana</b></td><td>{escape(str(metadata.get('median_latency_ms', '')))} ms</td></tr>
          <tr><td><b>Resumo</b></td><td>{escape(str(data.get('summary', '')))}</td></tr>
        </table>
        <h2>Controles de resiliência</h2>
        {findings}
        <h2>Evidências de execução</h2>
        <table class="compact"><tr><th>#</th><th>HTTP</th><th>Tempo ms</th><th>Sinal</th><th>Retry-After</th></tr>{attempt_rows}</table>
        """,
    )
    _print_html(html, path)


def _finding_block(item: dict[str, Any]) -> str:
    status = escape(str(item.get("status", "")))
    category = escape(str(item.get("category", "")))
    severity = escape(str(item.get("severity", "")))
    title = escape(str(item.get("title", "")))
    detail = escape(str(item.get("detail", "")))
    recommendation = escape(str(item.get("recommendation", "")))
    earned = escape(str(item.get("earned", 0)))
    weight = escape(str(item.get("weight", 0)))
    return f"""
    <div class="finding">
      <div class="finding-head"><b>{title}</b><span>{status} · {severity} · {category} · {earned}/{weight}</span></div>
      <p><b>Evidência:</b> {detail}</p>
      <p><b>Recomendação:</b> {recommendation}</p>
    </div>
    """


def _document_shell(title: str, body: str) -> str:
    return f"""
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; color: #171917; font-size: 10pt; }}
        h1 {{ font-size: 22pt; margin: 0 0 12px 0; }}
        h2 {{ font-size: 14pt; margin: 22px 0 8px 0; }}
        .hero {{ background: #eef3e5; border: 1px solid #cbd4bf; padding: 14px; margin-bottom: 14px; }}
        .score {{ font-size: 28pt; font-weight: 700; margin-bottom: 6px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        .summary td {{ border-bottom: 1px solid #dde2d8; padding: 6px; vertical-align: top; }}
        .summary td:first-child {{ width: 28%; }}
        .compact th, .compact td {{ border: 1px solid #d7ddd2; padding: 6px; text-align: left; }}
        .compact th {{ background: #eef1eb; }}
        .finding {{ border: 1px solid #d7ddd2; margin: 0 0 10px 0; padding: 10px; page-break-inside: avoid; }}
        .finding-head {{ border-bottom: 1px solid #e2e6de; padding-bottom: 6px; margin-bottom: 6px; }}
        .finding-head span {{ float: right; font-size: 8pt; color: #5f685c; }}
        p {{ margin: 5px 0; line-height: 1.35; }}
      </style>
    </head>
    <body>
      <h1>Aegis Auth Auditor</h1>
      <div>{escape(title)}</div>
      <br>
      {body}
    </body>
    </html>
    """


def _print_html(html: str, path: Path) -> None:
    document = QTextDocument()
    document.setHtml(html)
    printer = QPrinter(QPrinter.HighResolution)
    printer.setOutputFormat(QPrinter.PdfFormat)
    printer.setOutputFileName(str(path))
    page_size = QPageSize(QPageSize.A4)
    printer.setPageSize(page_size)
    layout = QPageLayout(page_size, QPageLayout.Portrait, QMarginsF(14, 14, 14, 14), QPageLayout.Millimeter)
    printer.setPageLayout(layout)
    document.print_(printer)
