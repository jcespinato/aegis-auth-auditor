from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QThread
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .models import ActiveAuthResult, AuditResult
from .reporting import save_active_csv, save_active_pdf, save_audit_csv, save_audit_pdf, save_json
from .storage import AuditStorage
from .worker import ActiveAuthWorker, AuditWorker


class MetricCard(QFrame):
    def __init__(self, label: str, value: str = "—") -> None:
        super().__init__()
        self.setObjectName("metricCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 14)
        title = QLabel(label)
        title.setObjectName("metricLabel")
        self.value_label = QLabel(value)
        self.value_label.setObjectName("metricValue")
        self.value_label.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(self.value_label)

    def set_value(self, value: str) -> None:
        self.value_label.setText(value)


class MainWindow(QMainWindow):
    def __init__(self, storage: AuditStorage, assets_dir: Path) -> None:
        super().__init__()
        self.storage = storage
        self.assets_dir = assets_dir
        self.current_audit: dict[str, Any] | None = None
        self.current_active: dict[str, Any] | None = None
        self.passive_thread: QThread | None = None
        self.passive_worker: AuditWorker | None = None
        self.active_thread: QThread | None = None
        self.active_worker: ActiveAuthWorker | None = None
        self.setWindowTitle("Aegis Auth Auditor")
        self.resize(1360, 840)
        self.setMinimumSize(1040, 680)
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
        sub = QLabel("AUTH AUDITOR  2.0")
        sub.setObjectName("brandSub")
        side.addWidget(brand)
        side.addWidget(sub)
        side.addSpacing(28)

        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.addItem(QListWidgetItem("Auditoria passiva"))
        self.nav.addItem(QListWidgetItem("Teste ativo"))
        self.nav.addItem(QListWidgetItem("Histórico"))
        self.nav.setCurrentRow(0)
        self.nav.currentRowChanged.connect(self._navigate)
        side.addWidget(self.nav)
        side.addStretch(1)
        scope = QLabel("Escopo controlado\nAmbientes autorizados")
        scope.setObjectName("scope")
        side.addWidget(scope)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._scrollable(self._audit_page()))
        self.stack.addWidget(self._scrollable(self._active_page()))
        self.stack.addWidget(self._history_page())
        root_layout.addWidget(sidebar)
        root_layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)

    def _scrollable(self, widget: QWidget) -> QScrollArea:
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.NoFrame)
        area.setWidget(widget)
        return area

    def _audit_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(34, 28, 34, 32)
        layout.setSpacing(16)

        eyebrow = QLabel("DIAGNÓSTICO PASSIVO")
        eyebrow.setObjectName("eyebrow")
        title = QLabel("Avaliação de segurança")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Analisa transporte, disponibilidade, cabeçalhos, sessão e superfície de autenticação sem enviar credenciais.")
        subtitle.setObjectName("pageSubtitle")
        layout.addWidget(eyebrow)
        layout.addWidget(title)
        layout.addWidget(subtitle)

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
        self.auth_check.stateChanged.connect(self._update_passive_state)
        self.run_button = QPushButton("Executar auditoria")
        self.run_button.setObjectName("primaryButton")
        self.run_button.setEnabled(False)
        self.run_button.clicked.connect(self._start_audit)
        row2.addWidget(self.auth_check)
        row2.addStretch(1)
        row2.addWidget(self.run_button)
        config_layout.addLayout(row2)
        layout.addWidget(config)

        metrics = QHBoxLayout()
        self.score_card = MetricCard("SCORE")
        self.risk_card = MetricCard("RISCO")
        self.coverage_card = MetricCard("COBERTURA")
        self.pass_card = MetricCard("APROVADOS")
        self.issue_card = MetricCard("ALERTAS + FALHAS")
        for card in [self.score_card, self.risk_card, self.coverage_card, self.pass_card, self.issue_card]:
            metrics.addWidget(card)
        layout.addLayout(metrics)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
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
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Status", "Severidade", "Categoria", "Controle", "Pontos"])
        for index in [0, 1, 2, 4]:
            self.table.horizontalHeader().setSectionResizeMode(index, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
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
        self.detail.setMinimumHeight(210)
        detail_layout.addWidget(detail_title)
        detail_layout.addWidget(self.detail, 1)
        export_row = QHBoxLayout()
        self.export_json = QPushButton("JSON")
        self.export_csv = QPushButton("CSV")
        self.export_pdf = QPushButton("Relatório PDF")
        for button in [self.export_json, self.export_csv, self.export_pdf]:
            button.setEnabled(False)
            export_row.addWidget(button)
        self.export_json.clicked.connect(self._export_audit_json)
        self.export_csv.clicked.connect(self._export_audit_csv)
        self.export_pdf.clicked.connect(self._export_audit_pdf)
        detail_layout.addLayout(export_row)

        split.addWidget(results_panel)
        split.addWidget(detail_panel)
        split.setSizes([780, 430])
        split.setMinimumHeight(360)
        layout.addWidget(split)
        return page

    def _active_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(34, 28, 34, 32)
        layout.setSpacing(16)

        eyebrow = QLabel("RESILIÊNCIA DA AUTENTICAÇÃO")
        eyebrow.setObjectName("eyebrow")
        title = QLabel("Teste ativo controlado")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Mede rate limiting, bloqueio, atraso progressivo e estabilidade usando uma única senha propositalmente incorreta.")
        subtitle.setObjectName("pageSubtitle")
        layout.addWidget(eyebrow)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        config = QFrame()
        config.setObjectName("panel")
        cfg = QVBoxLayout(config)
        cfg.setContentsMargins(20, 18, 20, 18)
        cfg.setSpacing(12)

        row1 = QHBoxLayout()
        login_box = QVBoxLayout()
        label = QLabel("URL de login")
        label.setObjectName("fieldLabel")
        self.active_login_input = QLineEdit()
        self.active_login_input.setPlaceholderText("https://exemplo.com/login")
        login_box.addWidget(label)
        login_box.addWidget(self.active_login_input)
        user_box = QVBoxLayout()
        user_label = QLabel("Conta de teste")
        user_label.setObjectName("fieldLabel")
        self.active_user_input = QLineEdit()
        self.active_user_input.setPlaceholderText("conta.teste")
        user_box.addWidget(user_label)
        user_box.addWidget(self.active_user_input)
        password_box = QVBoxLayout()
        password_label = QLabel("Senha incorreta de teste")
        password_label.setObjectName("fieldLabel")
        self.active_password_input = QLineEdit()
        self.active_password_input.setEchoMode(QLineEdit.Password)
        self.active_password_input.setPlaceholderText("valor propositalmente incorreto")
        password_box.addWidget(password_label)
        password_box.addWidget(self.active_password_input)
        row1.addLayout(login_box, 2)
        row1.addSpacing(12)
        row1.addLayout(user_box, 1)
        row1.addSpacing(12)
        row1.addLayout(password_box, 1)
        cfg.addLayout(row1)

        row2 = QHBoxLayout()
        attempts_box = QVBoxLayout()
        attempts_label = QLabel("Tentativas máximas")
        attempts_label.setObjectName("fieldLabel")
        self.attempts_combo = QComboBox()
        self.attempts_combo.addItems(["5", "10", "15", "20"])
        self.attempts_combo.setCurrentText("10")
        attempts_box.addWidget(attempts_label)
        attempts_box.addWidget(self.attempts_combo)
        interval_box = QVBoxLayout()
        interval_label = QLabel("Intervalo entre tentativas")
        interval_label.setObjectName("fieldLabel")
        self.interval_spin = QDoubleSpinBox()
        self.interval_spin.setRange(0.75, 5.0)
        self.interval_spin.setSingleStep(0.25)
        self.interval_spin.setDecimals(2)
        self.interval_spin.setValue(1.0)
        self.interval_spin.setSuffix(" s")
        interval_box.addWidget(interval_label)
        interval_box.addWidget(self.interval_spin)
        row2.addLayout(attempts_box)
        row2.addSpacing(12)
        row2.addLayout(interval_box)
        row2.addStretch(1)
        cfg.addLayout(row2)

        row3 = QHBoxLayout()
        self.active_auth_check = QCheckBox("Confirmo autorização e o uso de uma conta dedicada ao teste")
        self.active_auth_check.stateChanged.connect(self._update_active_state)
        self.active_run_button = QPushButton("Executar teste ativo")
        self.active_run_button.setObjectName("primaryButton")
        self.active_run_button.setEnabled(False)
        self.active_run_button.clicked.connect(self._start_active)
        row3.addWidget(self.active_auth_check)
        row3.addStretch(1)
        row3.addWidget(self.active_run_button)
        cfg.addLayout(row3)
        layout.addWidget(config)

        metrics = QHBoxLayout()
        self.active_score_card = MetricCard("SCORE")
        self.active_risk_card = MetricCard("RISCO")
        self.active_verdict_card = MetricCard("RESULTADO")
        self.active_attempt_card = MetricCard("TENTATIVAS")
        for card in [self.active_score_card, self.active_risk_card, self.active_verdict_card, self.active_attempt_card]:
            metrics.addWidget(card)
        layout.addLayout(metrics)

        self.active_progress = QProgressBar()
        self.active_progress.setRange(0, 100)
        self.active_progress.setTextVisible(False)
        self.active_progress.hide()
        layout.addWidget(self.active_progress)

        control_panel = QFrame()
        control_panel.setObjectName("panel")
        control_layout = QVBoxLayout(control_panel)
        control_layout.setContentsMargins(16, 16, 16, 16)
        control_title = QLabel("Controles de resiliência")
        control_title.setObjectName("sectionTitle")
        control_layout.addWidget(control_title)
        self.active_findings_table = QTableWidget(0, 5)
        self.active_findings_table.setHorizontalHeaderLabels(["Status", "Severidade", "Categoria", "Controle", "Pontos"])
        for index in [0, 1, 2, 4]:
            self.active_findings_table.horizontalHeader().setSectionResizeMode(index, QHeaderView.ResizeToContents)
        self.active_findings_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.active_findings_table.verticalHeader().setVisible(False)
        self.active_findings_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.active_findings_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.active_findings_table.itemSelectionChanged.connect(self._show_active_finding)
        control_layout.addWidget(self.active_findings_table)
        layout.addWidget(control_panel)

        lower = QSplitter(Qt.Horizontal)
        attempts_panel = QFrame()
        attempts_panel.setObjectName("panel")
        attempts_layout = QVBoxLayout(attempts_panel)
        attempts_layout.setContentsMargins(16, 16, 16, 16)
        attempts_title = QLabel("Evidências de execução")
        attempts_title.setObjectName("sectionTitle")
        attempts_layout.addWidget(attempts_title)
        self.attempts_table = QTableWidget(0, 5)
        self.attempts_table.setHorizontalHeaderLabels(["#", "HTTP", "Tempo", "Sinal", "Retry-After"])
        for index in [0, 1, 2, 4]:
            self.attempts_table.horizontalHeader().setSectionResizeMode(index, QHeaderView.ResizeToContents)
        self.attempts_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.attempts_table.verticalHeader().setVisible(False)
        self.attempts_table.setEditTriggers(QTableWidget.NoEditTriggers)
        attempts_layout.addWidget(self.attempts_table)

        active_detail_panel = QFrame()
        active_detail_panel.setObjectName("panel")
        active_detail_layout = QVBoxLayout(active_detail_panel)
        active_detail_layout.setContentsMargins(18, 16, 18, 16)
        active_detail_title = QLabel("Diagnóstico")
        active_detail_title.setObjectName("sectionTitle")
        self.active_detail = QTextEdit()
        self.active_detail.setReadOnly(True)
        active_detail_layout.addWidget(active_detail_title)
        active_detail_layout.addWidget(self.active_detail, 1)
        export_row = QHBoxLayout()
        self.active_export_json = QPushButton("JSON")
        self.active_export_csv = QPushButton("CSV")
        self.active_export_pdf = QPushButton("Relatório PDF")
        for button in [self.active_export_json, self.active_export_csv, self.active_export_pdf]:
            button.setEnabled(False)
            export_row.addWidget(button)
        self.active_export_json.clicked.connect(self._export_active_json)
        self.active_export_csv.clicked.connect(self._export_active_csv)
        self.active_export_pdf.clicked.connect(self._export_active_pdf)
        active_detail_layout.addLayout(export_row)

        lower.addWidget(attempts_panel)
        lower.addWidget(active_detail_panel)
        lower.setSizes([760, 430])
        lower.setMinimumHeight(300)
        layout.addWidget(lower)
        return page

    def _history_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(34, 28, 34, 28)
        eyebrow = QLabel("HISTÓRICO LOCAL")
        eyebrow.setObjectName("eyebrow")
        title = QLabel("Execuções registradas")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Auditorias e testes ativos armazenados somente neste computador.")
        subtitle.setObjectName("pageSubtitle")
        layout.addWidget(eyebrow)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(10)

        tabs = QTabWidget()
        passive_tab = QWidget()
        passive_layout = QVBoxLayout(passive_tab)
        self.history_table = QTableWidget(0, 6)
        self.history_table.setHorizontalHeaderLabels(["ID", "Alvo", "Login", "Score", "Risco", "Data"])
        self.history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        for index in [3, 4, 5]:
            self.history_table.horizontalHeader().setSectionResizeMode(index, QHeaderView.ResizeToContents)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.doubleClicked.connect(self._open_history_audit)
        passive_layout.addWidget(self.history_table)

        active_tab = QWidget()
        active_layout = QVBoxLayout(active_tab)
        self.active_history_table = QTableWidget(0, 7)
        self.active_history_table.setHorizontalHeaderLabels(["ID", "Login", "Conta", "Score", "Risco", "Resultado", "Data"])
        self.active_history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.active_history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        for index in [2, 3, 4, 5, 6]:
            self.active_history_table.horizontalHeader().setSectionResizeMode(index, QHeaderView.ResizeToContents)
        self.active_history_table.verticalHeader().setVisible(False)
        self.active_history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.active_history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.active_history_table.doubleClicked.connect(self._open_history_active)
        active_layout.addWidget(self.active_history_table)

        tabs.addTab(passive_tab, "Auditorias passivas")
        tabs.addTab(active_tab, "Testes ativos")
        layout.addWidget(tabs, 1)
        return page

    def _navigate(self, row: int) -> None:
        self.stack.setCurrentIndex(row)
        if row == 2:
            self._load_history()

    def _update_passive_state(self) -> None:
        self.run_button.setEnabled(self.auth_check.isChecked() and self.passive_thread is None)

    def _update_active_state(self) -> None:
        self.active_run_button.setEnabled(self.active_auth_check.isChecked() and self.active_thread is None)

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
        for card in [self.score_card, self.risk_card, self.coverage_card, self.pass_card, self.issue_card]:
            card.set_value("…")
        self.passive_thread = QThread(self)
        self.passive_worker = AuditWorker(target, login)
        self.passive_worker.moveToThread(self.passive_thread)
        self.passive_thread.started.connect(self.passive_worker.run)
        self.passive_worker.finished.connect(self._audit_finished)
        self.passive_worker.failed.connect(self._audit_failed)
        self.passive_worker.finished.connect(self.passive_thread.quit)
        self.passive_worker.failed.connect(self.passive_thread.quit)
        self.passive_thread.finished.connect(self._passive_thread_done)
        self.passive_thread.start()

    def _audit_finished(self, result: AuditResult) -> None:
        self.storage.save_audit(result)
        self.current_audit = result.to_dict()
        self._display_audit(self.current_audit)
        self._load_history()

    def _audit_failed(self, message: str) -> None:
        QMessageBox.critical(self, "Falha na auditoria", message)
        for card in [self.score_card, self.risk_card, self.coverage_card, self.pass_card, self.issue_card]:
            card.set_value("—")

    def _passive_thread_done(self) -> None:
        self.progress.hide()
        self.progress.setRange(0, 100)
        self.passive_thread = None
        self.passive_worker = None
        self._update_passive_state()

    def _display_audit(self, data: dict[str, Any]) -> None:
        findings = data.get("findings", [])
        passed = sum(1 for item in findings if item.get("status") == "PASS")
        issues = sum(1 for item in findings if item.get("status") in {"WARN", "FAIL"})
        self.score_card.set_value(f"{data.get('score', 0)}/100")
        self.risk_card.set_value(str(data.get("risk", "—")))
        self.coverage_card.set_value(f"{data.get('coverage', data.get('metadata', {}).get('coverage_percent', 0))}%")
        self.pass_card.set_value(str(passed))
        self.issue_card.set_value(str(issues))
        self.table.setRowCount(len(findings))
        for row, item in enumerate(findings):
            status_item = QTableWidgetItem(str(item.get("status", "")))
            status_item.setData(Qt.UserRole, item)
            values = [status_item, QTableWidgetItem(str(item.get("severity", ""))), QTableWidgetItem(str(item.get("category", ""))), QTableWidgetItem(str(item.get("title", ""))), QTableWidgetItem(f"{item.get('earned', 0)}/{item.get('weight', 0)}")]
            for col, value in enumerate(values):
                self.table.setItem(row, col, value)
        for button in [self.export_json, self.export_csv, self.export_pdf]:
            button.setEnabled(True)
        if findings:
            self.table.selectRow(0)

    def _show_selected_finding(self) -> None:
        items = self.table.selectedItems()
        if not items:
            return
        data = self.table.item(items[0].row(), 0).data(Qt.UserRole)
        if not data:
            return
        self.detail.setPlainText(
            f"{data.get('status','')}  •  {data.get('severity','')}  •  {data.get('category','')}\n\n"
            f"{data.get('title','')}\n\n"
            f"EVIDÊNCIA\n{data.get('detail','')}\n\n"
            f"RECOMENDAÇÃO\n{data.get('recommendation','')}"
        )

    def _start_active(self) -> None:
        login = self.active_login_input.text().strip()
        username = self.active_user_input.text().strip()
        wrong_password = self.active_password_input.text()
        attempts = int(self.attempts_combo.currentText())
        interval = float(self.interval_spin.value())
        if not login or not username or not wrong_password:
            QMessageBox.warning(self, "Campos obrigatórios", "Informe a URL de login, a conta de teste e uma senha incorreta de teste.")
            return
        confirmation = QMessageBox.question(self, "Confirmar teste ativo", f"Executar no máximo {attempts} tentativas controladas contra uma única conta, com intervalo de {interval:.2f} s?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if confirmation != QMessageBox.Yes:
            return
        self.active_run_button.setEnabled(False)
        self.active_progress.setRange(0, 0)
        self.active_progress.show()
        self.active_findings_table.setRowCount(0)
        self.attempts_table.setRowCount(0)
        self.active_detail.clear()
        for card in [self.active_score_card, self.active_risk_card, self.active_verdict_card, self.active_attempt_card]:
            card.set_value("…")
        self.active_thread = QThread(self)
        self.active_worker = ActiveAuthWorker(login, username, wrong_password, attempts, interval)
        self.active_worker.moveToThread(self.active_thread)
        self.active_thread.started.connect(self.active_worker.run)
        self.active_worker.finished.connect(self._active_finished)
        self.active_worker.failed.connect(self._active_failed)
        self.active_worker.finished.connect(self.active_thread.quit)
        self.active_worker.failed.connect(self.active_thread.quit)
        self.active_thread.finished.connect(self._active_thread_done)
        self.active_thread.start()

    def _active_finished(self, result: ActiveAuthResult) -> None:
        self.storage.save_active(result)
        self.current_active = result.to_dict()
        self.active_password_input.clear()
        self._display_active(self.current_active)
        self._load_history()

    def _active_failed(self, message: str) -> None:
        self.active_password_input.clear()
        QMessageBox.critical(self, "Falha no teste ativo", message)
        for card in [self.active_score_card, self.active_risk_card, self.active_verdict_card, self.active_attempt_card]:
            card.set_value("—")

    def _active_thread_done(self) -> None:
        self.active_progress.hide()
        self.active_progress.setRange(0, 100)
        self.active_thread = None
        self.active_worker = None
        self._update_active_state()

    def _display_active(self, data: dict[str, Any]) -> None:
        self.active_score_card.set_value(f"{data.get('score', 0)}/100")
        self.active_risk_card.set_value(str(data.get("risk", "—")))
        self.active_verdict_card.set_value(str(data.get("verdict", "—")))
        self.active_attempt_card.set_value(f"{data.get('attempts_completed', 0)}/{data.get('attempts_requested', 0)}")
        findings = data.get("findings", [])
        self.active_findings_table.setRowCount(len(findings))
        for row, item in enumerate(findings):
            status_item = QTableWidgetItem(str(item.get("status", "")))
            status_item.setData(Qt.UserRole, item)
            values = [status_item, QTableWidgetItem(str(item.get("severity", ""))), QTableWidgetItem(str(item.get("category", ""))), QTableWidgetItem(str(item.get("title", ""))), QTableWidgetItem(f"{item.get('earned', 0)}/{item.get('weight', 0)}")]
            for col, value in enumerate(values):
                self.active_findings_table.setItem(row, col, value)
        attempts = data.get("attempts", [])
        self.attempts_table.setRowCount(len(attempts))
        for row, item in enumerate(attempts):
            values = [str(item.get("number", "")), str(item.get("status_code", "")), f"{item.get('elapsed_ms', 0)} ms", str(item.get("signal", "")), str(item.get("retry_after", ""))]
            for col, value in enumerate(values):
                self.attempts_table.setItem(row, col, QTableWidgetItem(value))
        for button in [self.active_export_json, self.active_export_csv, self.active_export_pdf]:
            button.setEnabled(True)
        if findings:
            self.active_findings_table.selectRow(0)

    def _show_active_finding(self) -> None:
        items = self.active_findings_table.selectedItems()
        if not items:
            return
        data = self.active_findings_table.item(items[0].row(), 0).data(Qt.UserRole)
        if not data:
            return
        self.active_detail.setPlainText(
            f"{data.get('status','')}  •  {data.get('severity','')}  •  {data.get('category','')}\n\n"
            f"{data.get('title','')}\n\n"
            f"EVIDÊNCIA\n{data.get('detail','')}\n\n"
            f"RECOMENDAÇÃO\n{data.get('recommendation','')}"
        )

    def _load_history(self) -> None:
        if hasattr(self, "history_table"):
            rows = self.storage.recent_audits()
            self.history_table.setRowCount(len(rows))
            for row_index, row in enumerate(rows):
                values = [str(row["id"]), row["target_url"], row["login_url"], f"{row['score']}/100", row["risk"], row["started_at"][:19].replace("T", " ")]
                for col, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    item.setData(Qt.UserRole, row["id"])
                    self.history_table.setItem(row_index, col, item)
        if hasattr(self, "active_history_table"):
            rows = self.storage.recent_active()
            self.active_history_table.setRowCount(len(rows))
            for row_index, row in enumerate(rows):
                values = [str(row["id"]), row["login_url"], row["account_hint"], f"{row['score']}/100", row["risk"], row["verdict"], row["started_at"][:19].replace("T", " ")]
                for col, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    item.setData(Qt.UserRole, row["id"])
                    self.active_history_table.setItem(row_index, col, item)

    def _open_history_audit(self) -> None:
        items = self.history_table.selectedItems()
        if not items:
            return
        data = self.storage.get_audit(int(items[0].data(Qt.UserRole)))
        if not data:
            return
        self.current_audit = data
        self.target_input.setText(data.get("target_url", ""))
        self.login_input.setText(data.get("login_url", ""))
        self._display_audit(data)
        self.nav.setCurrentRow(0)

    def _open_history_active(self) -> None:
        items = self.active_history_table.selectedItems()
        if not items:
            return
        data = self.storage.get_active(int(items[0].data(Qt.UserRole)))
        if not data:
            return
        self.current_active = data
        self.active_login_input.setText(data.get("login_url", ""))
        self._display_active(data)
        self.nav.setCurrentRow(1)

    def _export_audit_json(self) -> None:
        if not self.current_audit:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exportar resultado", "aegis-audit.json", "JSON (*.json)")
        if path:
            save_json(self.current_audit, Path(path))

    def _export_audit_csv(self) -> None:
        if not self.current_audit:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exportar controles", "aegis-audit.csv", "CSV (*.csv)")
        if path:
            save_audit_csv(self.current_audit, Path(path))

    def _export_audit_pdf(self) -> None:
        if not self.current_audit:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Gerar relatório", "aegis-audit.pdf", "PDF (*.pdf)")
        if path:
            save_audit_pdf(self.current_audit, Path(path))

    def _export_active_json(self) -> None:
        if not self.current_active:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exportar resultado", "aegis-active-test.json", "JSON (*.json)")
        if path:
            save_json(self.current_active, Path(path))

    def _export_active_csv(self) -> None:
        if not self.current_active:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exportar evidências", "aegis-active-test.csv", "CSV (*.csv)")
        if path:
            save_active_csv(self.current_active, Path(path))

    def _export_active_pdf(self) -> None:
        if not self.current_active:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Gerar relatório", "aegis-active-test.pdf", "PDF (*.pdf)")
        if path:
            save_active_pdf(self.current_active, Path(path))


def apply_theme(app: QApplication) -> None:
    app.setFont(QFont("Segoe UI", 10))
    app.setStyleSheet(
        """
        QWidget { background: #0f120f; color: #f2f4ef; }
        QScrollArea { border: none; background: #0f120f; }
        #sidebar { background: #111511; border-right: 1px solid #252b25; }
        #brand { font-size: 29px; font-weight: 800; letter-spacing: 3px; color: #d4ff2f; }
        #brandSub { color: #8f998c; font-size: 10px; letter-spacing: 2px; }
        #scope { color: #6e786c; font-size: 11px; }
        #nav { border: none; background: transparent; outline: none; }
        #nav::item { padding: 13px 12px; margin: 3px 0; border-radius: 8px; color: #aab2a7; }
        #nav::item:selected { background: #d4ff2f; color: #101310; font-weight: 700; }
        #eyebrow { color: #d4ff2f; font-size: 10px; font-weight: 700; letter-spacing: 2px; }
        #pageTitle { font-size: 31px; font-weight: 760; }
        #pageSubtitle { color: #889186; font-size: 12px; }
        #panel, #metricCard { background: #171b17; border: 1px solid #2a302a; border-radius: 12px; }
        #metricLabel { color: #747f72; font-size: 10px; letter-spacing: 1px; }
        #metricValue { font-size: 23px; font-weight: 760; color: #f4f6f1; }
        #fieldLabel { color: #9aa397; font-size: 11px; font-weight: 600; }
        #sectionTitle { font-size: 14px; font-weight: 700; color: #f4f6f1; }
        QLineEdit, QComboBox, QDoubleSpinBox { background: #101410; border: 1px solid #303730; border-radius: 8px; padding: 10px 11px; color: #f1f4ee; selection-background-color: #d4ff2f; selection-color: #101310; }
        QLineEdit:focus, QComboBox:focus, QDoubleSpinBox:focus { border: 1px solid #d4ff2f; }
        QComboBox QAbstractItemView { background: #171b17; color: #f1f4ee; selection-background-color: #273027; }
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
        QSplitter::handle { background: #0f120f; width: 8px; height: 8px; }
        QTabWidget::pane { border: 1px solid #2a302a; border-radius: 10px; background: #171b17; }
        QTabBar::tab { background: #171b17; color: #90998e; padding: 10px 16px; border: 1px solid #2a302a; }
        QTabBar::tab:selected { color: #111411; background: #d4ff2f; font-weight: 700; }
        QMessageBox { background: #171b17; }
        """
    )
