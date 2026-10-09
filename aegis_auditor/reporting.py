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
            writer.writerow([item.get("status", ""), item.get("severity", ""), item.get("category", ""), item.get("title", ""), item.get("weight", 0), item.get("earned", 0), item.get("detail", ""), item.get("recommendation", "")])


def save_active_csv(data: dict[str, Any], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle, delimiter=";")
        writer.writerow(["Tentativa", "HTTP", "Tempo ms", "Sinal", "Retry-After"])
        for item in data.get("attempts", []):
            writer.writerow([item.get("number", ""), item.get("status_code", ""), item.get("elapsed_ms", ""), item.get("signal", ""), item.get("retry_after", "")])


def save_lab_csv(data: dict[str, Any], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle, delimiter=";")
        writer.writerow(["Tentativa", "Tipo", "HTTP", "Tempo ms", "Sinal", "Sucesso", "Retry-After"])
        for item in data.get("attempts", []):
            writer.writerow([item.get("number", ""), item.get("credential_kind", ""), item.get("status_code", ""), item.get("elapsed_ms", ""), item.get("signal", ""), item.get("success", False), item.get("retry_after", "")])


def save_audit_pdf(data: dict[str, Any], path: Path) -> None:
    categories = "".join(f"<tr><td>{escape(str(name))}</td><td><b>{int(score)}/100</b></td></tr>" for name, score in data.get("category_scores", {}).items())
    findings = "".join(_finding_block(item) for item in data.get("findings", []))
    metadata = data.get("metadata", {})
    html = _document_shell("Relatório de Auditoria de Autenticação", f"""
    <div class="hero"><div class="score">{int(data.get('score', 0))}/100</div><div><b>Risco:</b> {escape(str(data.get('risk', '')))}<br><b>Cobertura:</b> {int(data.get('coverage', 0))}%</div></div>
    <table class="summary">
      <tr><td><b>Ambiente</b></td><td>{escape(str(data.get('target_url', '')))}</td></tr>
      <tr><td><b>Login</b></td><td>{escape(str(data.get('login_url', '')))}</td></tr>
      <tr><td><b>Status do ambiente</b></td><td>{escape(str(metadata.get('target_status', '')))}</td></tr>
      <tr><td><b>Status do login</b></td><td>{escape(str(metadata.get('login_status', '')))}</td></tr>
      <tr><td><b>TLS</b></td><td>{escape(str(metadata.get('tls_version', '')))} {escape(str(metadata.get('cipher', '')))}</td></tr>
      <tr><td><b>Resumo</b></td><td>{escape(str(data.get('summary', '')))}</td></tr>
    </table>
    <h2>Pontuação por categoria</h2><table class="compact"><tr><th>Categoria</th><th>Score</th></tr>{categories}</table>
    <h2>Controles avaliados</h2>{findings}
    """)
    _print_html(html, path)


def save_active_pdf(data: dict[str, Any], path: Path) -> None:
    metadata = data.get("metadata", {})
    findings = "".join(_finding_block(item) for item in data.get("findings", []))
    rows = "".join(f"<tr><td>{escape(str(item.get('number','')))}</td><td>{escape(str(item.get('status_code','')))}</td><td>{escape(str(item.get('elapsed_ms','')))}</td><td>{escape(str(item.get('signal','')))}</td><td>{escape(str(item.get('retry_after','')))}</td></tr>" for item in data.get("attempts", []))
    html = _document_shell("Relatório de Resistência da Autenticação", f"""
    <div class="hero"><div class="score">{int(data.get('score', 0))}/100</div><div><b>Risco:</b> {escape(str(data.get('risk', '')))}<br><b>Resultado:</b> {escape(str(data.get('verdict', '')))}</div></div>
    <table class="summary">
      <tr><td><b>Login</b></td><td>{escape(str(data.get('login_url', '')))}</td></tr>
      <tr><td><b>Conta de teste</b></td><td>{escape(str(data.get('account_hint', '')))}</td></tr>
      <tr><td><b>Tentativas</b></td><td>{escape(str(data.get('attempts_completed', '')))} de {escape(str(data.get('attempts_requested', '')))}</td></tr>
      <tr><td><b>Intervalo</b></td><td>{escape(str(data.get('interval_seconds', '')))} s</td></tr>
      <tr><td><b>Latência mediana</b></td><td>{escape(str(metadata.get('median_latency_ms', '')))} ms</td></tr>
      <tr><td><b>Resumo</b></td><td>{escape(str(data.get('summary', '')))}</td></tr>
    </table>
    <h2>Controles de resiliência</h2>{findings}
    <h2>Evidências de execução</h2><table class="compact"><tr><th>#</th><th>HTTP</th><th>Tempo ms</th><th>Sinal</th><th>Retry-After</th></tr>{rows}</table>
    """)
    _print_html(html, path)


def save_password_pdf(data: dict[str, Any], path: Path) -> None:
    findings = "".join(_finding_block(item) for item in data.get("findings", []))
    demo = "Encontrada no conjunto demonstrativo" if data.get("demo_found") else "Não encontrada no conjunto demonstrativo"
    html = _document_shell("Relatório Local de Robustez de Senha", f"""
    <div class="hero"><div class="score">{int(data.get('score', 0))}/100</div><div><b>Classificação:</b> {escape(str(data.get('rating', '')))}<br><b>Processamento:</b> exclusivamente local</div></div>
    <table class="summary">
      <tr><td><b>Comprimento</b></td><td>{escape(str(data.get('length', '')))} caracteres</td></tr>
      <tr><td><b>Entropia ajustada</b></td><td>{escape(str(data.get('entropy_bits', '')))} bits</td></tr>
      <tr><td><b>Espaço relativo</b></td><td>{escape(str(data.get('search_space', '')))}</td></tr>
      <tr><td><b>Demonstração local</b></td><td>{escape(demo)}; {escape(str(data.get('demo_attempts', 0)))} candidatos avaliados.</td></tr>
      <tr><td><b>Resumo</b></td><td>{escape(str(data.get('summary', '')))}</td></tr>
    </table>
    <h2>Indicadores</h2>{findings}
    """)
    _print_html(html, path)


def save_hash_pdf(data: dict[str, Any], path: Path) -> None:
    metadata = data.get("metadata", {})
    html = _document_shell("Relatório de Benchmark de Hash", f"""
    <div class="hero"><div class="score">{escape(str(data.get('median_ms', 0)))} ms</div><div><b>Perfil:</b> {escape(str(data.get('algorithm', '')))}<br><b>Custo:</b> {escape(str(data.get('rating', '')))}</div></div>
    <table class="summary">
      <tr><td><b>Amostras</b></td><td>{escape(str(data.get('samples', '')))}</td></tr>
      <tr><td><b>Mínimo</b></td><td>{escape(str(data.get('minimum_ms', '')))} ms</td></tr>
      <tr><td><b>Mediana</b></td><td>{escape(str(data.get('median_ms', '')))} ms</td></tr>
      <tr><td><b>Máximo</b></td><td>{escape(str(data.get('maximum_ms', '')))} ms</td></tr>
      <tr><td><b>Derivações por segundo</b></td><td>{escape(str(data.get('verifications_per_second', '')))}</td></tr>
      <tr><td><b>Parâmetros</b></td><td>{escape(json.dumps(metadata.get('parameters', {}), ensure_ascii=False))}</td></tr>
      <tr><td><b>Resumo</b></td><td>{escape(str(data.get('summary', '')))}</td></tr>
    </table>
    """)
    _print_html(html, path)


def save_lab_pdf(data: dict[str, Any], path: Path) -> None:
    findings = "".join(_finding_block(item) for item in data.get("findings", []))
    rows = "".join(f"<tr><td>{escape(str(item.get('number','')))}</td><td>{escape(str(item.get('credential_kind','')))}</td><td>{escape(str(item.get('status_code','')))}</td><td>{escape(str(item.get('elapsed_ms','')))}</td><td>{escape(str(item.get('signal','')))}</td><td>{'SIM' if item.get('success') else 'NÃO'}</td></tr>" for item in data.get("attempts", []))
    html = _document_shell("Relatório de Simulação Controlada em Laboratório", f"""
    <div class="hero"><div class="score">{escape(str(data.get('verdict', '')))}</div><div><b>Risco:</b> {escape(str(data.get('risk', '')))}</div></div>
    <table class="summary">
      <tr><td><b>Login</b></td><td>{escape(str(data.get('login_url', '')))}</td></tr>
      <tr><td><b>Conta</b></td><td>{escape(str(data.get('account_hint', '')))}</td></tr>
      <tr><td><b>Tentativa válida planejada</b></td><td>{escape(str(data.get('correct_attempt_number', '')))}</td></tr>
      <tr><td><b>Credencial válida alcançou autenticação</b></td><td>{'SIM' if data.get('success_reached') else 'NÃO'}</td></tr>
      <tr><td><b>Proteção acionada</b></td><td>{'SIM' if data.get('protection_triggered') else 'NÃO'}</td></tr>
      <tr><td><b>Resumo</b></td><td>{escape(str(data.get('summary', '')))}</td></tr>
    </table>
    <h2>Conclusões</h2>{findings}
    <h2>Evidências</h2><table class="compact"><tr><th>#</th><th>Tipo</th><th>HTTP</th><th>Tempo ms</th><th>Sinal</th><th>Sucesso</th></tr>{rows}</table>
    """)
    _print_html(html, path)


def save_comparison_pdf(left: dict[str, Any], right: dict[str, Any], path: Path, kind: str) -> None:
    if kind == "passive":
        left_score = left.get("score", 0)
        right_score = right.get("score", 0)
        left_label = f"{left_score}/100 · {left.get('risk','')}"
        right_label = f"{right_score}/100 · {right.get('risk','')}"
        rows = []
        left_map = {item.get("key"): item for item in left.get("findings", [])}
        right_map = {item.get("key"): item for item in right.get("findings", [])}
        for key in sorted(set(left_map) | set(right_map)):
            a = left_map.get(key, {})
            b = right_map.get(key, {})
            rows.append(f"<tr><td>{escape(str(a.get('title') or b.get('title') or key))}</td><td>{escape(str(a.get('status','—')))}</td><td>{escape(str(b.get('status','—')))}</td></tr>")
        body_rows = "".join(rows)
    else:
        left_label = f"{left.get('score',0)}/100 · {left.get('verdict','')}"
        right_label = f"{right.get('score',0)}/100 · {right.get('verdict','')}"
        body_rows = "".join([
            f"<tr><td>Score</td><td>{escape(str(left.get('score',0)))}</td><td>{escape(str(right.get('score',0)))}</td></tr>",
            f"<tr><td>Risco</td><td>{escape(str(left.get('risk','')))}</td><td>{escape(str(right.get('risk','')))}</td></tr>",
            f"<tr><td>Tentativas</td><td>{escape(str(left.get('attempts_completed',0)))}</td><td>{escape(str(right.get('attempts_completed',0)))}</td></tr>",
            f"<tr><td>Resultado</td><td>{escape(str(left.get('verdict','')))}</td><td>{escape(str(right.get('verdict','')))}</td></tr>",
        ])
    html = _document_shell("Relatório Comparativo", f"""
    <div class="hero"><b>Execução A:</b> {escape(left_label)}<br><b>Execução B:</b> {escape(right_label)}</div>
    <table class="compact"><tr><th>Indicador</th><th>Execução A</th><th>Execução B</th></tr>{body_rows}</table>
    """)
    _print_html(html, path)


def save_executive_pdf(passive: dict[str, Any] | None, active: dict[str, Any] | None, lab: dict[str, Any] | None, path: Path) -> None:
    sections = []
    if passive:
        sections.append(f"<h2>Auditoria passiva</h2><div class='hero'><b>Score:</b> {passive.get('score',0)}/100 · <b>Risco:</b> {escape(str(passive.get('risk','')))} · <b>Cobertura:</b> {passive.get('coverage',0)}%</div><p>{escape(str(passive.get('summary','')))}</p>")
    if active:
        sections.append(f"<h2>Resiliência da autenticação</h2><div class='hero'><b>Score:</b> {active.get('score',0)}/100 · <b>Risco:</b> {escape(str(active.get('risk','')))} · <b>Resultado:</b> {escape(str(active.get('verdict','')))}</div><p>{escape(str(active.get('summary','')))}</p>")
    if lab:
        sections.append(f"<h2>Simulação controlada de laboratório</h2><div class='hero'><b>Resultado:</b> {escape(str(lab.get('verdict','')))} · <b>Risco:</b> {escape(str(lab.get('risk','')))}</div><p>{escape(str(lab.get('summary','')))}</p>")
    if not sections:
        sections.append("<p>Nenhuma execução registrada.</p>")
    html = _document_shell("Relatório Executivo Consolidado", "".join(sections))
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
    return f"<div class='finding'><div class='finding-head'><b>{title}</b><span>{status} · {severity} · {category} · {earned}/{weight}</span></div><p><b>Evidência:</b> {detail}</p><p><b>Recomendação:</b> {recommendation}</p></div>"


def _document_shell(title: str, body: str) -> str:
    return f"""
    <html><head><meta charset="utf-8"><style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; color: #171917; font-size: 10pt; }}
    h1 {{ font-size: 22pt; margin: 0 0 12px 0; }} h2 {{ font-size: 14pt; margin: 22px 0 8px 0; }}
    .hero {{ background: #eef3e5; border: 1px solid #cbd4bf; padding: 14px; margin-bottom: 14px; }}
    .score {{ font-size: 28pt; font-weight: 700; margin-bottom: 6px; }} table {{ width: 100%; border-collapse: collapse; }}
    .summary td {{ border-bottom: 1px solid #dde2d8; padding: 6px; vertical-align: top; }} .summary td:first-child {{ width: 28%; }}
    .compact th, .compact td {{ border: 1px solid #d7ddd2; padding: 6px; text-align: left; }} .compact th {{ background: #eef1eb; }}
    .finding {{ border: 1px solid #d7ddd2; margin: 0 0 10px 0; padding: 10px; page-break-inside: avoid; }}
    .finding-head {{ border-bottom: 1px solid #e2e6de; padding-bottom: 6px; margin-bottom: 6px; }} .finding-head span {{ float: right; font-size: 8pt; color: #5f685c; }}
    p {{ margin: 5px 0; line-height: 1.35; }}
    </style></head><body><h1>Aegis Auth Auditor</h1><div>{escape(title)}</div><br>{body}</body></html>
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
