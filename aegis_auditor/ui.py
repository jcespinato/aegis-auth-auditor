from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QThread
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QHeaderView,
    QSizePolicy,
)

from .models import AuditResult
from .reporting import save_json, save_pdf
from .storage import AuditStorage
from .worker import AuditWorker


class MetricCard(QFrame):
    def __init__(self, label: str, value: str = "—") -> None:
        super().__init__()
        self.setObjectName("metricCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 16)
        title = QLabel(label)
        title.setObjectName("metricLabel")
        self.value_label = QLabel(value)
        self.value_label.setObjectName("metricValue")
        layout.addWidget(title)
        layout.addWidget(self.value_label)

    def set_value(self, value: str) -> None:
        self.value_label.setText(value)


class MainWindow(QMainWindow):
    def __init__(self, storage: AuditStorage, assets_dir: Path) -> None:
        super().__init__()
        self.storage = storage
        self.assets_dir = assets_dir
        self.current_result: dict[str, Any] | None = None
        self.thread: QThread | None = None
        self.worker: AuditWorker | None = None
        self.setWindowTitle("Aegis Auth Auditor")
        self.resize(1320, 820)
        icon_path = assets_dir / "aegis.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        self._build_ui()
        self._load_history()

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(245)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(22, 28, 22, 24)
        brand = QLabel("AEGIS")
        brand.setObjectName("brand")
        sub = QLabel("AUTH AUDITOR")
        sub.setObjectName("brandSub")
        side.addWidget(brand)
        side.addWidget(sub)
        side.addSpacing(30)

        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.addItem(QListWidgetItem("Nova auditoria"))
        self.nav.addItem(QListWidgetItem("Histórico"))
        self.nav.setCurrentRow(0)
        self.nav.currentRowChanged.connect(self._navigate)
        side.addWidget(self.nav)
        side.addStretch(1)
        scope = QLabel("Escopo controlado\nAuditoria autorizada")
        scope.setObjectName("scope")
        side.addWidget(scope)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._audit_page())
        self.stack.addWidget(self._history_page())
        root_layout.addWidget(sidebar)
        root_layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)

    def _audit_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(34, 28, 34, 28)
        layout.setSpacing(18)

        head = QHBoxLayout()
        title_box = QVBoxLayout()
        eyebrow = QLabel("DIAGNÓSTICO DE AUTENTICAÇÃO")
        eyebrow.setObjectName("eyebrow")
        title = QLabel("Avaliação de segurança")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Analise transporte, cabeçalhos, cookies e a superfície de autenticação de um ambiente autorizado.")
        subtitle.setObjectName("pageSubtitle")
        title_box.addWidget(eyebrow)
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        head.addLayout(title_box)
        head.addStretch(1)
        layout.addLayout(head)

        config = QFrame()
        config.setObjectName("panel")
        config_layout = QVBoxLayout(config)
        config_layout.setContentsMargins(20, 18, 20, 18)
        config_layout.setSpacing(12)

        row1 = QHBoxLayout()
        target_box = QVBoxLayout()
        target_label = QLabel("URL do ambiente")
        target_label.setObjectName("fieldLabel")
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://exemplo.com")
        target_box.addWidget(target_label)
        target_box.addWidget(self.target_input)
        login_box = QVBoxLayout()
        login_label = QLabel("URL de login")
        login_label.setObjectName("fieldLabel")
        self.login_input = QLineEdit()
        self.login_input.setPlaceholderText("https://exemplo.com/login")
        login_box.addWidget(login_label)
        login_box.addWidget(self.login_input)
        row1.addLayout(target_box, 1)
        row1.addSpacing(14)
        row1.addLayout(login_box, 1)
        config_layout.addLayout(row1)

        row2 = QHBoxLayout()
        self.auth_check = QCheckBox("Confirmo que este ambiente é próprio ou que possuo autorização para avaliá-lo")
        self.auth_check.stateChanged.connect(self._update_run_state)
        row2.addWidget(self.auth_check)
        row2.addStretch(1)
        self.run_button = QPushButton("Executar auditoria")
        self.run_button.setObjectName("primaryButton")
        self.run_button.setEnabled(False)
        self.run_button.clicked.connect(self._start_audit)
        row2.addWidget(self.run_button)
        config_layout.addLayout(row2)
        layout.addWidget(config)

        metrics = QHBoxLayout()
        self.score_card = MetricCard("SCORE", "—")
        self.risk_card = MetricCard("RISCO", "—")
        self.pass_card = MetricCard("APROVADOS", "—")
        self.issue_card = MetricCard("ALERTAS + FALHAS", "—")
        for card in [self.score_card, self.risk_card, self.pass_card, self.issue_card]:
            metrics.addWidget(card)
        layout.addLayout(metrics)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.hide()
        layout.addWidget(self.progress)

        split = QSplitter(Qt.Horizontal)
        results_panel = QFrame()
        results_panel.setObjectName("panel")
        results_layout = QVBoxLayout(results_panel)
        results_layout.setContentsMargins(16, 16, 16, 16)
        result_title = QLabel("Controles avaliados")
        result_title.setObjectName("sectionTitle")
        results_layout.addWidget(result_title)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Status", "Categoria", "Controle", "Peso"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._show_selected_finding)
        results_layout.addWidget(self.table)

        detail_panel = QFrame()
        detail_panel.setObjectName("panel")
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.setContentsMargins(18, 16, 18, 16)
        detail_title = QLabel("Evidência e recomendação")
        detail_title.setObjectName("sectionTitle")
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("Selecione um controle para visualizar os detalhes.")
        detail_layout.addWidget(detail_title)
        detail_layout.addWidget(self.detail, 1)

        export_row = QHBoxLayout()
        self.export_json = QPushButton("Exportar JSON")
        self.export_pdf = QPushButton("Gerar relatório PDF")
        self.export_json.setEnabled(False)
        self.export_pdf.setEnabled(False)
        self.export_json.clicked.connect(self._export_json)
        self.export_pdf.clicked.connect(self._export_pdf)
        export_row.addWidget(self.export_json)
        export_row.addWidget(self.export_pdf)
        detail_layout.addLayout(export_row)

        split.addWidget(results_panel)
        split.addWidget(detail_panel)
        split.setSizes([760, 420])
        layout.addWidget(split, 1)
        return page

    def _history_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(34, 28, 34, 28)
        eyebrow = QLabel("HISTÓRICO LOCAL")
        eyebrow.setObjectName("eyebrow")
        title = QLabel("Auditorias executadas")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Resultados anteriores armazenados localmente neste computador.")
        subtitle.setObjectName("pageSubtitle")
        layout.addWidget(eyebrow)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(10)

        panel = QFrame()
        panel.setObjectName("panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(16, 16, 16, 16)
        self.history_table = QTableWidget(0, 5)
        self.history_table.setHorizontalHeaderLabels(["ID", "Alvo", "Score", "Risco", "Data"])
        self.history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.doubleClicked.connect(self._open_history_item)
        panel_layout.addWidget(self.history_table)
        layout.addWidget(panel, 1)
        return page

    def _navigate(self, row: int) -> None:
        self.stack.setCurrentIndex(row)
        if row == 1:
            self._load_history()

    def _update_run_state(self) -> None:
        self.run_button.setEnabled(self.auth_check.isChecked() and self.thread is None)

    def _start_audit(self) -> None:
        target = self.target_input.text().strip()
        login = self.login_input.text().strip()
        if not target or not login:
            QMessageBox.warning(self, "Campos obrigatórios", "Informe a URL do ambiente e a URL de login.")
            return
        self.run_button.setEnabled(False)
        self.progress.setRange(0, 0)
        self.progress.show()
        self.table.setRowCount(0)
        self.detail.clear()
        self.score_card.set_value("…")
        self.risk_card.set_value("…")
        self.pass_card.set_value("…")
        self.issue_card.set_value("…")

        self.thread = QThread(self)
        self.worker = AuditWorker(target, login)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self._audit_finished)
        self.worker.failed.connect(self._audit_failed)
        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self._thread_done)
        self.thread.start()

    def _audit_finished(self, result: AuditResult) -> None:
        self.storage.save(result)
        self.current_result = result.to_dict()
        self._display_result(self.current_result)
        self._load_history()

    def _audit_failed(self, message: str) -> None:
        QMessageBox.critical(self, "Falha na auditoria", message)
        self.score_card.set_value("—")
        self.risk_card.set_value("—")
        self.pass_card.set_value("—")
        self.issue_card.set_value("—")

    def _thread_done(self) -> None:
        self.progress.hide()
        self.progress.setRange(0, 100)
        self.thread = None
        self.worker = None
        self._update_run_state()

    def _display_result(self, data: dict[str, Any]) -> None:
        findings = data.get("findings", [])
        passed = sum(1 for item in findings if item.get("status") == "PASS")
        issues = sum(1 for item in findings if item.get("status") in {"WARN", "FAIL"})
        self.score_card.set_value(f"{data.get('score', 0)}/100")
        self.risk_card.set_value(str(data.get("risk", "—")))
        self.pass_card.set_value(str(passed))
        self.issue_card.set_value(str(issues))
        self.table.setRowCount(len(findings))
        for row, item in enumerate(findings):
            status_item = QTableWidgetItem(str(item.get("status", "")))
            category_item = QTableWidgetItem(str(item.get("category", "")))
            title_item = QTableWidgetItem(str(item.get("title", "")))
            weight_item = QTableWidgetItem(str(item.get("weight", 0)))
            status_item.setData(Qt.UserRole, item)
            self.table.setItem(row, 0, status_item)
            self.table.setItem(row, 1, category_item)
            self.table.setItem(row, 2, title_item)
            self.table.setItem(row, 3, weight_item)
        self.export_json.setEnabled(True)
        self.export_pdf.setEnabled(True)
        if findings:
            self.table.selectRow(0)

    def _show_selected_finding(self) -> None:
        items = self.table.selectedItems()
        if not items:
            return
        row = items[0].row()
        status_item = self.table.item(row, 0)
        data = status_item.data(Qt.UserRole) if status_item else None
        if not data:
            return
        text = (
            f"{data.get('status','')}  •  {data.get('category','')}\n\n"
            f"{data.get('title','')}\n\n"
            f"EVIDÊNCIA\n{data.get('detail','')}\n\n"
            f"RECOMENDAÇÃO\n{data.get('recommendation','')}"
        )
        self.detail.setPlainText(text)

    def _load_history(self) -> None:
        if not hasattr(self, "history_table"):
            return
        rows = self.storage.recent()
        self.history_table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            values = [
                str(row["id"]),
                row["target_url"],
                f"{row['score']}/100",
                row["risk"],
                row["started_at"][:19].replace("T", " "),
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.UserRole, row["id"])
                self.history_table.setItem(row_index, col, item)

    def _open_history_item(self) -> None:
        items = self.history_table.selectedItems()
        if not items:
            return
        audit_id = int(items[0].data(Qt.UserRole))
        data = self.storage.get(audit_id)
        if not data:
            return
        self.current_result = data
        self.target_input.setText(data.get("target_url", ""))
        self.login_input.setText(data.get("login_url", ""))
        self._display_result(data)
        self.nav.setCurrentRow(0)

    def _export_json(self) -> None:
        if not self.current_result:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exportar resultado", "aegis-audit.json", "JSON (*.json)")
        if path:
            save_json(self.current_result, Path(path))

    def _export_pdf(self) -> None:
        if not self.current_result:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Gerar relatório", "aegis-audit.pdf", "PDF (*.pdf)")
        if path:
            save_pdf(self.current_result, Path(path))


def apply_theme(app: QApplication) -> None:
    app.setFont(QFont("Segoe UI", 10))
    app.setStyleSheet(
        """
        QWidget { background: #0f120f; color: #f2f4ef; }
        #sidebar { background: #111511; border-right: 1px solid #252b25; }
        #brand { font-size: 29px; font-weight: 800; letter-spacing: 3px; color: #d4ff2f; }
        #brandSub { color: #8f998c; font-size: 10px; letter-spacing: 2px; }
        #scope { color: #6e786c; font-size: 11px; line-height: 1.5; }
        #nav { border: none; background: transparent; outline: none; }
        #nav::item { padding: 13px 12px; margin: 3px 0; border-radius: 8px; color: #aab2a7; }
        #nav::item:selected { background: #d4ff2f; color: #101310; font-weight: 700; }
        #eyebrow { color: #d4ff2f; font-size: 10px; font-weight: 700; letter-spacing: 2px; }
        #pageTitle { font-size: 31px; font-weight: 760; }
        #pageSubtitle { color: #889186; font-size: 12px; }
        #panel, #metricCard { background: #171b17; border: 1px solid #2a302a; border-radius: 12px; }
        #metricLabel { color: #747f72; font-size: 10px; letter-spacing: 1px; }
        #metricValue { font-size: 26px; font-weight: 760; color: #f4f6f1; }
        #fieldLabel { color: #9aa397; font-size: 11px; font-weight: 600; }
        #sectionTitle { font-size: 14px; font-weight: 700; color: #f4f6f1; }
        QLineEdit { background: #101410; border: 1px solid #303730; border-radius: 8px; padding: 11px 12px; color: #f1f4ee; selection-background-color: #d4ff2f; selection-color: #101310; }
        QLineEdit:focus { border: 1px solid #d4ff2f; }
        QCheckBox { color: #aab2a7; spacing: 8px; }
        QCheckBox::indicator { width: 17px; height: 17px; }
        QPushButton { background: #222822; border: 1px solid #333b33; border-radius: 8px; padding: 10px 14px; color: #e9ece6; font-weight: 600; }
        QPushButton:hover { background: #2a312a; }
        QPushButton:disabled { color: #666d65; background: #181c18; border-color: #232823; }
        #primaryButton { background: #d4ff2f; color: #111411; border: none; padding: 11px 20px; font-weight: 800; }
        #primaryButton:hover { background: #c5f020; }
        QProgressBar { border: none; background: #1a1f1a; border-radius: 3px; height: 5px; }
        QProgressBar::chunk { background: #d4ff2f; border-radius: 3px; }
        QTableWidget { background: #131713; alternate-background-color: #151a15; border: none; gridline-color: #252b25; selection-background-color: #273027; selection-color: #ffffff; }
        QHeaderView::section { background: #1c211c; color: #8f998d; border: none; border-bottom: 1px solid #303630; padding: 9px; font-size: 10px; font-weight: 700; }
        QTextEdit { background: #111511; border: 1px solid #272d27; border-radius: 9px; padding: 12px; color: #cbd1c7; }
        QSplitter::handle { background: #0f120f; width: 8px; }
        QMessageBox { background: #171b17; }
        """
    )
