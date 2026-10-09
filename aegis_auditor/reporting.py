from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any

from PySide6.QtGui import QTextDocument
from PySide6.QtPrintSupport import QPrinter


def save_json(data: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def save_pdf(data: dict[str, Any], path: Path) -> None:
    findings = data.get("findings", [])
    rows = "".join(
        f"<tr><td>{escape(str(item.get('status','')))}</td><td>{escape(str(item.get('category','')))}</td><td>{escape(str(item.get('title','')))}</td><td>{escape(str(item.get('detail','')))}</td><td>{escape(str(item.get('recommendation','')))}</td></tr>"
        for item in findings
    )
    html = f"""
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{ font-family: Arial; color: #171917; }}
        h1 {{ font-size: 24px; }}
        .score {{ font-size: 32px; font-weight: 700; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 18px; }}
        th, td {{ border: 1px solid #d8ddd4; padding: 7px; font-size: 10px; vertical-align: top; }}
        th {{ background: #eef1eb; }}
      </style>
    </head>
    <body>
      <h1>Aegis Auth Auditor</h1>
      <p><b>Alvo:</b> {escape(str(data.get('target_url','')))}</p>
      <p><b>Login:</b> {escape(str(data.get('login_url','')))}</p>
      <p class="score">{data.get('score',0)}/100</p>
      <p><b>Risco:</b> {escape(str(data.get('risk','')))}</p>
      <p>{escape(str(data.get('summary','')))}</p>
      <table>
        <thead><tr><th>Status</th><th>Categoria</th><th>Controle</th><th>Evidência</th><th>Recomendação</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </body>
    </html>
    """
    document = QTextDocument()
    document.setHtml(html)
    printer = QPrinter(QPrinter.HighResolution)
    printer.setOutputFormat(QPrinter.PdfFormat)
    printer.setOutputFileName(str(path))
    document.print_(printer)
