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
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .models import ActiveAuthResult, AuditResult, HashBenchmarkResult, LabSimulationResult, PasswordAnalysisResult
from .reporting import (
    save_active_csv,
    save_active_pdf,
    save_audit_csv,
    save_audit_pdf,
    save_comparison_pdf,
    save_executive_pdf,
    save_hash_pdf,
    save_json,
    save_lab_csv,
    save_lab_pdf,
    save_password_pdf,
)
from .security import LocalAccessManager
from .storage import AuditStorage
from .worker import ActiveAuthWorker, AuditWorker, HashWorker, LabWorker, PasswordWorker


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
        self.access = LocalAccessManager(storage.db_path.parent / "private-access.json")
        self.private_unlocked = False
        self.current_audit: dict[str, Any] | None = None
        self.current_active: dict[str, Any] | None = None
        self.current_password: dict[str, Any] | None = None
        self.current_hash: dict[str, Any] | None = None
        self.current_lab: dict[str, Any] | None = None
        self.threads: dict[str, QThread | None] = {"passive": None, "active": None, "password": None, "hash": None, "lab": None}
        self.workers: dict[str, Any] = {}
        self.setWindowTitle("Aegis Auth Auditor 3.0")
        self.resize(1440, 900)
        self.setMinimumSize(1080, 700)
        icon_path = assets_dir / "aegis.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        self._build_ui()
        self._load_history()
        self._refresh_dashboard()

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(250)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(22, 28, 22, 24)
        brand = QLabel("AEGIS")
        brand.setObjectName("brand")
        sub = QLabel("AUTH AUDITOR  3.0")
        sub.setObjectName("brandSub")
        side.addWidget(brand)
        side.addWidget(sub)
        side.addSpacing(24)

        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        for title in ["Dashboard", "Auditoria passiva", "Teste ativo", "Robustez de senha", "Hash benchmark", "Laboratório privado", "Comparação", "Histórico"]:
            self.nav.addItem(QListWidgetItem(title))
        self.nav.setCurrentRow(0)
        self.nav.currentRowChanged.connect(self._navigate)
        side.addWidget(self.nav)
        side.addStretch(1)
        scope = QLabel("Escopo controlado\nAmbientes autorizados\nDados sensíveis não persistidos")
        scope.setObjectName("scope")
        side.addWidget(scope)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._scrollable(self._dashboard_page()))
        self.stack.addWidget(self._scrollable(self._audit_page()))
        self.stack.addWidget(self._scrollable(self._active_page()))
        self.stack.addWidget(self._scrollable(self._password_page()))
        self.stack.addWidget(self._scrollable(self._hash_page()))
        self.stack.addWidget(self._scrollable(self._lab_page()))
        self.stack.addWidget(self._scrollable(self._comparison_page()))
        self.stack.addWidget(self._history_page())
        root_layout.addWidget(sidebar)
        root_layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)

    def _navigate(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        if index in {0, 6, 7}:
            self._load_history()
            self._refresh_dashboard()
            self._refresh_comparison_options()

    def _scrollable(self, widget: QWidget) -> QScrollArea:
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.NoFrame)
        area.setWidget(widget)
        return area

    def _header(self, layout: QVBoxLayout, eyebrow: str, title: str, subtitle: str) -> None:
        e = QLabel(eyebrow)
        e.setObjectName("eyebrow")
        t = QLabel(title)
        t.setObjectName("pageTitle")
        s = QLabel(subtitle)
        s.setObjectName("pageSubtitle")
        s.setWordWrap(True)
        layout.addWidget(e)
        layout.addWidget(t)
        layout.addWidget(s)

    def _dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(34, 28, 34, 32)
        layout.setSpacing(18)
        self._header(layout, "CENTRO DE DIAGNÓSTICO", "Visão consolidada", "Resumo das execuções locais do Aegis Auth Auditor e acesso rápido aos relatórios consolidados.")
        row = QHBoxLayout()
        self.dash_passive = MetricCard("AUDITORIA PASSIVA")
        self.dash_active = MetricCard("RESILIÊNCIA")
        self.dash_password = MetricCard("SENHA LOCAL")
        self.dash_lab = MetricCard("LABORATÓRIO")
        for card in [self.dash_passive, self.dash_active, self.dash_password, self.dash_lab]:
            row.addWidget(card)
        layout.addLayout(row)

        panel = QFrame()
        panel.setObjectName("panel")
        p = QVBoxLayout(panel)
        p.setContentsMargins(18, 16, 18, 16)
        title = QLabel("Resumo operacional")
        title.setObjectName("sectionTitle")
        self.dashboard_text = QTextEdit()
        self.dashboard_text.setReadOnly(True)
        self.dashboard_text.setMinimumHeight(260)
        actions = QHBoxLayout()
        executive = QPushButton("Relatório executivo PDF")
        executive.setObjectName("primaryButton")
        executive.clicked.connect(self._export_executive)
        history = QPushButton("Abrir histórico")
        history.clicked.connect(lambda: self.nav.setCurrentRow(7))
        actions.addWidget(executive)
        actions.addWidget(history)
        actions.addStretch(1)
        p.addWidget(title)
        p.addWidget(self.dashboard_text)
        p.addLayout(actions)
        layout.addWidget(panel)
        return page

    def _audit_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(34, 28, 34, 32)
        layout.setSpacing(16)
        self._header(layout, "DIAGNÓSTICO PASSIVO", "Avaliação de segurança", "Analisa transporte, disponibilidade, cabeçalhos, sessão e superfície de autenticação sem enviar credenciais.")
        config = QFrame()
        config.setObjectName("panel")
        c = QVBoxLayout(config)
        c.setContentsMargins(20, 18, 20, 18)
        row = QHBoxLayout()
        self.target_input = self._field(row, "URL do ambiente", "https://exemplo.com")
        self.login_input = self._field(row, "URL de login", "https://exemplo.com/login")
        c.addLayout(row)
        actions = QHBoxLayout()
        self.auth_check = QCheckBox("Confirmo que este ambiente é próprio ou que possuo autorização para avaliá-lo")
        self.auth_check.stateChanged.connect(self._update_passive_state)
        self.run_button = QPushButton("Executar auditoria")
        self.run_button.setObjectName("primaryButton")
        self.run_button.setEnabled(False)
        self.run_button.clicked.connect(self._start_audit)
        actions.addWidget(self.auth_check)
        actions.addStretch(1)
        actions.addWidget(self.run_button)
        c.addLayout(actions)
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
        self.progress = self._progress(layout)
        self.table, self.detail = self._finding_split(layout, "Controles avaliados")
        buttons = self._export_bar(self.detail.parentWidget().layout(), [
            ("JSON", self._export_audit_json), ("CSV", self._export_audit_csv), ("Relatório PDF", self._export_audit_pdf)
        ])
        self.audit_export_buttons = buttons
        self.table.itemSelectionChanged.connect(lambda: self._show_finding(self.table, self.detail))
        return page

    def _active_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(34, 28, 34, 32)
        layout.setSpacing(16)
        self._header(layout, "RESILIÊNCIA DA AUTENTICAÇÃO", "Teste ativo controlado", "Mede rate limiting, bloqueio, atraso progressivo e estabilidade usando uma única senha propositalmente incorreta.")
        panel = QFrame()
        panel.setObjectName("panel")
        p = QVBoxLayout(panel)
        p.setContentsMargins(20, 18, 20, 18)
        row = QHBoxLayout()
        self.active_login_input = self._field(row, "URL de login", "https://exemplo.com/login")
        self.active_user_input = self._field(row, "Conta de teste", "conta.teste")
        self.active_password_input = self._field(row, "Senha incorreta de teste", "valor propositalmente incorreto", password=True)
        p.addLayout(row)
        row2 = QHBoxLayout()
        self.active_attempts = QSpinBox()
        self.active_attempts.setRange(5, 20)
        self.active_attempts.setValue(10)
        self.active_interval = QDoubleSpinBox()
        self.active_interval.setRange(0.75, 5.0)
        self.active_interval.setSingleStep(0.25)
        self.active_interval.setValue(1.0)
        self.active_interval.setSuffix(" s")
        row2.addLayout(self._labeled_widget("Tentativas máximas", self.active_attempts))
        row2.addLayout(self._labeled_widget("Intervalo entre tentativas", self.active_interval))
        row2.addStretch(1)
        p.addLayout(row2)
        actions = QHBoxLayout()
        self.active_check = QCheckBox("Confirmo autorização e o uso de uma conta dedicada ao teste")
        self.active_check.stateChanged.connect(self._update_active_state)
        self.active_run_button = QPushButton("Executar teste ativo")
        self.active_run_button.setObjectName("primaryButton")
        self.active_run_button.setEnabled(False)
        self.active_run_button.clicked.connect(self._start_active)
        actions.addWidget(self.active_check)
        actions.addStretch(1)
        actions.addWidget(self.active_run_button)
        p.addLayout(actions)
        layout.addWidget(panel)

        metrics = QHBoxLayout()
        self.active_score_card = MetricCard("SCORE")
        self.active_risk_card = MetricCard("RISCO")
        self.active_verdict_card = MetricCard("RESULTADO")
        self.active_attempt_card = MetricCard("TENTATIVAS")
        for card in [self.active_score_card, self.active_risk_card, self.active_verdict_card, self.active_attempt_card]:
            metrics.addWidget(card)
        layout.addLayout(metrics)
        self.active_progress = self._progress(layout)
        self.active_findings_table, self.active_detail = self._finding_split(layout, "Controles de resiliência", min_height=300)
        self.active_findings_table.itemSelectionChanged.connect(lambda: self._show_finding(self.active_findings_table, self.active_detail))
        attempts_panel = QFrame()
        attempts_panel.setObjectName("panel")
        ap = QVBoxLayout(attempts_panel)
        ap.setContentsMargins(16, 16, 16, 16)
        title = QLabel("Evidências de execução")
        title.setObjectName("sectionTitle")
        self.attempts_table = QTableWidget(0, 5)
        self.attempts_table.setHorizontalHeaderLabels(["#", "HTTP", "Tempo", "Sinal", "Retry-After"])
        self.attempts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.attempts_table.verticalHeader().setVisible(False)
        self.attempts_table.setEditTriggers(QTableWidget.NoEditTriggers)
        ap.addWidget(title)
        ap.addWidget(self.attempts_table)
        self.active_export_buttons = self._export_bar(ap, [("JSON", self._export_active_json), ("CSV", self._export_active_csv), ("Relatório PDF", self._export_active_pdf)])
        layout.addWidget(attempts_panel)
        return page

    def _password_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(34, 28, 34, 32)
        layout.setSpacing(16)
        self._header(layout, "ANÁLISE LOCAL", "Robustez de senha", "Avalia uma senha de laboratório localmente. O valor informado não é enviado para a rede nem armazenado no histórico.")
        panel = QFrame()
        panel.setObjectName("panel")
        p = QVBoxLayout(panel)
        p.setContentsMargins(20, 18, 20, 18)
        row = QHBoxLayout()
        self.password_input = self._field(row, "Senha de laboratório", "valor sintético para avaliação", password=True)
        self.password_show = QCheckBox("Exibir")
        self.password_show.stateChanged.connect(self._toggle_password_visibility)
        self.password_run = QPushButton("Analisar localmente")
        self.password_run.setObjectName("primaryButton")
        self.password_run.clicked.connect(self._start_password)
        row.addWidget(self.password_show)
        row.addWidget(self.password_run)
        p.addLayout(row)
        notice = QLabel("A demonstração local compara apenas padrões e um conjunto limitado de candidatos educacionais; não acessa contas nem procura credenciais desconhecidas.")
        notice.setObjectName("pageSubtitle")
        notice.setWordWrap(True)
        p.addWidget(notice)
        layout.addWidget(panel)
        metrics = QHBoxLayout()
        self.password_score = MetricCard("SCORE")
        self.password_rating = MetricCard("CLASSIFICAÇÃO")
        self.password_entropy = MetricCard("ENTROPIA AJUSTADA")
        self.password_demo = MetricCard("DEMONSTRAÇÃO LOCAL")
        for card in [self.password_score, self.password_rating, self.password_entropy, self.password_demo]:
            metrics.addWidget(card)
        layout.addLayout(metrics)
        self.password_progress = self._progress(layout)
        self.password_table, self.password_detail = self._finding_split(layout, "Indicadores de robustez")
        self.password_table.itemSelectionChanged.connect(lambda: self._show_finding(self.password_table, self.password_detail))
        self.password_export_buttons = self._export_bar(self.password_detail.parentWidget().layout(), [("JSON", self._export_password_json), ("Relatório PDF", self._export_password_pdf)])
        return page

    def _hash_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(34, 28, 34, 32)
        layout.setSpacing(16)
        self._header(layout, "BENCHMARK LOCAL", "Custo de derivação de senha", "Mede localmente o custo computacional de perfis de hash com um segredo sintético gerado em memória.")
        panel = QFrame()
        panel.setObjectName("panel")
        p = QHBoxLayout(panel)
        p.setContentsMargins(20, 18, 20, 18)
        self.hash_profile = QComboBox()
        self.hash_profile.addItems(["scrypt-16384", "scrypt-32768", "pbkdf2-300k", "pbkdf2-600k"])
        self.hash_samples = QSpinBox()
        self.hash_samples.setRange(3, 10)
        self.hash_samples.setValue(5)
        self.hash_run = QPushButton("Executar benchmark")
        self.hash_run.setObjectName("primaryButton")
        self.hash_run.clicked.connect(self._start_hash)
        p.addLayout(self._labeled_widget("Perfil", self.hash_profile))
        p.addLayout(self._labeled_widget("Amostras", self.hash_samples))
        p.addStretch(1)
        p.addWidget(self.hash_run)
        layout.addWidget(panel)
        metrics = QHBoxLayout()
        self.hash_median = MetricCard("MEDIANA")
        self.hash_rate = MetricCard("DERIVAÇÕES / S")
        self.hash_range = MetricCard("FAIXA")
        self.hash_rating = MetricCard("CUSTO")
        for card in [self.hash_median, self.hash_rate, self.hash_range, self.hash_rating]:
            metrics.addWidget(card)
        layout.addLayout(metrics)
        self.hash_progress = self._progress(layout)
        detail_panel = QFrame()
        detail_panel.setObjectName("panel")
        dp = QVBoxLayout(detail_panel)
        dp.setContentsMargins(18, 16, 18, 16)
        title = QLabel("Resultado do benchmark")
        title.setObjectName("sectionTitle")
        self.hash_detail = QTextEdit()
        self.hash_detail.setReadOnly(True)
        self.hash_detail.setMinimumHeight(280)
        dp.addWidget(title)
        dp.addWidget(self.hash_detail)
        self.hash_export_buttons = self._export_bar(dp, [("JSON", self._export_hash_json), ("Relatório PDF", self._export_hash_pdf)])
        layout.addWidget(detail_panel)
        return page

    def _lab_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(34, 28, 34, 32)
        layout.setSpacing(16)
        self._header(layout, "MODO PRIVADO", "Simulação de ataque em laboratório", "Demonstração controlada restrita ao Aegis Auth Lab e a ambientes locais, usando uma credencial válida já conhecida pelo responsável.")
        access_panel = QFrame()
        access_panel.setObjectName("panel")
        a = QHBoxLayout(access_panel)
        a.setContentsMargins(20, 16, 20, 16)
        self.lab_access_state = QLabel("BLOQUEADO")
        self.lab_access_state.setObjectName("metricValue")
        self.lab_access_button = QPushButton("Configurar acesso" if not self.access.is_configured() else "Desbloquear")
        self.lab_access_button.setObjectName("primaryButton")
        self.lab_access_button.clicked.connect(self._unlock_private)
        self.lab_change_button = QPushButton("Alterar chave local")
        self.lab_change_button.clicked.connect(self._change_private_key)
        self.lab_change_button.setEnabled(False)
        a.addWidget(self.lab_access_state)
        a.addStretch(1)
        a.addWidget(self.lab_change_button)
        a.addWidget(self.lab_access_button)
        layout.addWidget(access_panel)

        panel = QFrame()
        panel.setObjectName("panel")
        p = QVBoxLayout(panel)
        p.setContentsMargins(20, 18, 20, 18)
        row = QHBoxLayout()
        self.lab_login_input = self._field(row, "URL de login", "https://aegis-auth-lab.onrender.com/login")
        self.lab_login_input.setText("https://aegis-auth-lab.onrender.com/login")
        self.lab_user_input = self._field(row, "Conta dedicada", "conta.teste")
        p.addLayout(row)
        row2 = QHBoxLayout()
        self.lab_decoy_input = self._field(row2, "Senha incorreta de teste", "senha propositalmente incorreta", password=True)
        self.lab_correct_input = self._field(row2, "Credencial válida conhecida", "credencial da conta dedicada", password=True)
        p.addLayout(row2)
        row3 = QHBoxLayout()
        self.lab_attempts = QSpinBox()
        self.lab_attempts.setRange(5, 20)
        self.lab_attempts.setValue(10)
        self.lab_correct_at = QSpinBox()
        self.lab_correct_at.setRange(2, 10)
        self.lab_correct_at.setValue(10)
        self.lab_attempts.valueChanged.connect(lambda value: self.lab_correct_at.setMaximum(value))
        self.lab_interval = QDoubleSpinBox()
        self.lab_interval.setRange(1.0, 5.0)
        self.lab_interval.setSingleStep(0.25)
        self.lab_interval.setValue(1.0)
        self.lab_interval.setSuffix(" s")
        row3.addLayout(self._labeled_widget("Tentativas máximas", self.lab_attempts))
        row3.addLayout(self._labeled_widget("Tentativa da credencial válida", self.lab_correct_at))
        row3.addLayout(self._labeled_widget("Intervalo", self.lab_interval))
        row3.addStretch(1)
        p.addLayout(row3)
        actions = QHBoxLayout()
        self.lab_check = QCheckBox("Confirmo conta dedicada, credencial conhecida e execução exclusiva no laboratório autorizado")
        self.lab_check.stateChanged.connect(self._update_lab_state)
        self.lab_run = QPushButton("Executar simulação")
        self.lab_run.setObjectName("primaryButton")
        self.lab_run.setEnabled(False)
        self.lab_run.clicked.connect(self._start_lab)
        actions.addWidget(self.lab_check)
        actions.addStretch(1)
        actions.addWidget(self.lab_run)
        p.addLayout(actions)
        layout.addWidget(panel)

        metrics = QHBoxLayout()
        self.lab_verdict = MetricCard("RESULTADO")
        self.lab_risk = MetricCard("RISCO")
        self.lab_success = MetricCard("CREDENCIAL VÁLIDA")
        self.lab_protection = MetricCard("PROTEÇÃO")
        for card in [self.lab_verdict, self.lab_risk, self.lab_success, self.lab_protection]:
            metrics.addWidget(card)
        layout.addLayout(metrics)
        self.lab_progress = self._progress(layout)
        self.lab_findings, self.lab_detail = self._finding_split(layout, "Conclusões do laboratório", min_height=280)
        self.lab_findings.itemSelectionChanged.connect(lambda: self._show_finding(self.lab_findings, self.lab_detail))
        evidence = QFrame()
        evidence.setObjectName("panel")
        ev = QVBoxLayout(evidence)
        ev.setContentsMargins(16, 16, 16, 16)
        title = QLabel("Sequência executada")
        title.setObjectName("sectionTitle")
        self.lab_attempt_table = QTableWidget(0, 6)
        self.lab_attempt_table.setHorizontalHeaderLabels(["#", "Tipo", "HTTP", "Tempo", "Sinal", "Sucesso"])
        self.lab_attempt_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.lab_attempt_table.verticalHeader().setVisible(False)
        self.lab_attempt_table.setEditTriggers(QTableWidget.NoEditTriggers)
        ev.addWidget(title)
        ev.addWidget(self.lab_attempt_table)
        self.lab_export_buttons = self._export_bar(ev, [("JSON", self._export_lab_json), ("CSV", self._export_lab_csv), ("Relatório PDF", self._export_lab_pdf)])
        layout.addWidget(evidence)
        return page

    def _comparison_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(34, 28, 34, 32)
        layout.setSpacing(16)
        self._header(layout, "ANTES × DEPOIS", "Comparação de execuções", "Compara auditorias passivas ou testes ativos registrados no histórico para documentar a evolução das defesas.")
        tabs = QTabWidget()
        passive = QWidget()
        pv = QVBoxLayout(passive)
        choose = QHBoxLayout()
        self.compare_passive_a = QComboBox()
        self.compare_passive_b = QComboBox()
        run = QPushButton("Comparar auditorias")
        run.setObjectName("primaryButton")
        run.clicked.connect(lambda: self._compare("passive"))
        export = QPushButton("Relatório PDF")
        export.clicked.connect(lambda: self._export_comparison("passive"))
        choose.addLayout(self._labeled_widget("Execução A", self.compare_passive_a))
        choose.addLayout(self._labeled_widget("Execução B", self.compare_passive_b))
        choose.addWidget(run)
        choose.addWidget(export)
        pv.addLayout(choose)
        self.compare_passive_text = QTextEdit()
        self.compare_passive_text.setReadOnly(True)
        self.compare_passive_text.setMinimumHeight(430)
        pv.addWidget(self.compare_passive_text)
        active = QWidget()
        av = QVBoxLayout(active)
        choose2 = QHBoxLayout()
        self.compare_active_a = QComboBox()
        self.compare_active_b = QComboBox()
        run2 = QPushButton("Comparar testes")
        run2.setObjectName("primaryButton")
        run2.clicked.connect(lambda: self._compare("active"))
        export2 = QPushButton("Relatório PDF")
        export2.clicked.connect(lambda: self._export_comparison("active"))
        choose2.addLayout(self._labeled_widget("Execução A", self.compare_active_a))
        choose2.addLayout(self._labeled_widget("Execução B", self.compare_active_b))
        choose2.addWidget(run2)
        choose2.addWidget(export2)
        av.addLayout(choose2)
        self.compare_active_text = QTextEdit()
        self.compare_active_text.setReadOnly(True)
        self.compare_active_text.setMinimumHeight(430)
        av.addWidget(self.compare_active_text)
        tabs.addTab(passive, "Auditoria passiva")
        tabs.addTab(active, "Teste ativo")
        layout.addWidget(tabs)
        return page

    def _history_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(34, 28, 34, 32)
        layout.setSpacing(16)
        self._header(layout, "HISTÓRICO LOCAL", "Execuções registradas", "Auditorias e diagnósticos persistidos somente neste computador; senhas e credenciais não são armazenadas.")
        tabs = QTabWidget()
        self.history_table = self._history_table(["ID", "Alvo", "Login", "Score", "Risco", "Data"])
        self.active_history_table = self._history_table(["ID", "Login", "Conta", "Score", "Risco", "Resultado", "Data"])
        self.password_history_table = self._history_table(["ID", "Score", "Classificação", "Data"])
        self.hash_history_table = self._history_table(["ID", "Perfil", "Mediana ms", "Custo", "Data"])
        self.lab_history_table = self._history_table(["ID", "Login", "Conta", "Resultado", "Risco", "Data"])
        self.history_table.doubleClicked.connect(self._open_history_audit)
        self.active_history_table.doubleClicked.connect(self._open_history_active)
        self.password_history_table.doubleClicked.connect(self._open_history_password)
        self.hash_history_table.doubleClicked.connect(self._open_history_hash)
        self.lab_history_table.doubleClicked.connect(self._open_history_lab)
        tabs.addTab(self.history_table, "Passivas")
        tabs.addTab(self.active_history_table, "Ativos")
        tabs.addTab(self.password_history_table, "Senhas")
        tabs.addTab(self.hash_history_table, "Hashes")
        tabs.addTab(self.lab_history_table, "Laboratório")
        layout.addWidget(tabs)
        return page

    def _field(self, row: QHBoxLayout, label: str, placeholder: str, password: bool = False) -> QLineEdit:
        box = QVBoxLayout()
        lab = QLabel(label)
        lab.setObjectName("fieldLabel")
        edit = QLineEdit()
        edit.setPlaceholderText(placeholder)
        if password:
            edit.setEchoMode(QLineEdit.EchoMode.Password)
        box.addWidget(lab)
        box.addWidget(edit)
        row.addLayout(box, 1)
        return edit

    def _labeled_widget(self, label: str, widget: QWidget) -> QVBoxLayout:
        box = QVBoxLayout()
        lab = QLabel(label)
        lab.setObjectName("fieldLabel")
        box.addWidget(lab)
        box.addWidget(widget)
        return box

    def _progress(self, layout: QVBoxLayout) -> QProgressBar:
        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setTextVisible(False)
        bar.hide()
        layout.addWidget(bar)
        return bar

    def _finding_split(self, layout: QVBoxLayout, title_text: str, min_height: int = 360) -> tuple[QTableWidget, QTextEdit]:
        split = QSplitter(Qt.Horizontal)
        results_panel = QFrame()
        results_panel.setObjectName("panel")
        rp = QVBoxLayout(results_panel)
        rp.setContentsMargins(16, 16, 16, 16)
        title = QLabel(title_text)
        title.setObjectName("sectionTitle")
        table = QTableWidget(0, 5)
        table.setHorizontalHeaderLabels(["Status", "Severidade", "Categoria", "Controle", "Pontos"])
        for index in [0, 1, 2, 4]:
            table.horizontalHeader().setSectionResizeMode(index, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        rp.addWidget(title)
        rp.addWidget(table)
        detail_panel = QFrame()
        detail_panel.setObjectName("panel")
        dp = QVBoxLayout(detail_panel)
        dp.setContentsMargins(18, 16, 18, 16)
        dtitle = QLabel("Evidência e recomendação")
        dtitle.setObjectName("sectionTitle")
        detail = QTextEdit()
        detail.setReadOnly(True)
        detail.setMinimumHeight(210)
        dp.addWidget(dtitle)
        dp.addWidget(detail, 1)
        split.addWidget(results_panel)
        split.addWidget(detail_panel)
        split.setSizes([820, 430])
        split.setMinimumHeight(min_height)
        layout.addWidget(split)
        return table, detail

    def _export_bar(self, layout, definitions: list[tuple[str, Any]]) -> list[QPushButton]:
        row = QHBoxLayout()
        buttons = []
        for title, slot in definitions:
            button = QPushButton(title)
            button.setEnabled(False)
            button.clicked.connect(slot)
            row.addWidget(button)
            buttons.append(button)
        layout.addLayout(row)
        return buttons

    def _history_table(self, headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        return table

    def _update_passive_state(self) -> None:
        self.run_button.setEnabled(self.auth_check.isChecked() and self.threads["passive"] is None)

    def _update_active_state(self) -> None:
        self.active_run_button.setEnabled(self.active_check.isChecked() and self.threads["active"] is None)

    def _update_lab_state(self) -> None:
        self.lab_run.setEnabled(self.private_unlocked and self.lab_check.isChecked() and self.threads["lab"] is None)

    def _start_thread(self, key: str, worker: Any, finished_slot: Any, failed_slot: Any) -> None:
        thread = QThread(self)
        self.threads[key] = thread
        self.workers[key] = worker
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(finished_slot)
        worker.failed.connect(failed_slot)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(lambda k=key: self._thread_done(k))
        thread.start()

    def _thread_done(self, key: str) -> None:
        self.threads[key] = None
        self.workers.pop(key, None)
        if key == "passive":
            self.progress.hide()
            self.progress.setRange(0, 100)
            self._update_passive_state()
        elif key == "active":
            self.active_progress.hide()
            self.active_progress.setRange(0, 100)
            self._update_active_state()
        elif key == "password":
            self.password_progress.hide()
            self.password_progress.setRange(0, 100)
            self.password_run.setEnabled(True)
        elif key == "hash":
            self.hash_progress.hide()
            self.hash_progress.setRange(0, 100)
            self.hash_run.setEnabled(True)
        elif key == "lab":
            self.lab_progress.hide()
            self.lab_progress.setRange(0, 100)
            self._update_lab_state()

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
        self._start_thread("passive", AuditWorker(target, login), self._audit_finished, self._audit_failed)

    def _audit_finished(self, result: AuditResult) -> None:
        self.storage.save_audit(result)
        self.current_audit = result.to_dict()
        self._display_audit(self.current_audit)
        self._post_update()

    def _audit_failed(self, message: str) -> None:
        QMessageBox.critical(self, "Falha na auditoria", message)

    def _display_audit(self, data: dict[str, Any]) -> None:
        self.score_card.set_value(f"{data.get('score', 0)}/100")
        self.risk_card.set_value(str(data.get("risk", "—")))
        self.coverage_card.set_value(f"{data.get('coverage', 0)}%")
        findings = data.get("findings", [])
        passes = sum(1 for item in findings if item.get("status") == "PASS")
        issues = sum(1 for item in findings if item.get("status") in {"WARN", "FAIL"})
        self.pass_card.set_value(str(passes))
        self.issue_card.set_value(str(issues))
        self._fill_findings(self.table, findings)
        for button in self.audit_export_buttons:
            button.setEnabled(True)
        if findings:
            self.table.selectRow(0)

    def _start_active(self) -> None:
        login = self.active_login_input.text().strip()
        username = self.active_user_input.text().strip()
        wrong = self.active_password_input.text()
        if not login or not username or not wrong:
            QMessageBox.warning(self, "Campos obrigatórios", "Informe URL de login, conta de teste e senha incorreta de teste.")
            return
        attempts = self.active_attempts.value()
        interval = self.active_interval.value()
        confirm = QMessageBox.question(self, "Confirmar teste ativo", f"Executar no máximo {attempts} tentativas controladas contra uma única conta?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if confirm != QMessageBox.Yes:
            return
        self.active_run_button.setEnabled(False)
        self.active_progress.setRange(0, 0)
        self.active_progress.show()
        self.active_findings_table.setRowCount(0)
        self.attempts_table.setRowCount(0)
        self.active_detail.clear()
        for card in [self.active_score_card, self.active_risk_card, self.active_verdict_card, self.active_attempt_card]:
            card.set_value("…")
        self._start_thread("active", ActiveAuthWorker(login, username, wrong, attempts, interval), self._active_finished, self._active_failed)

    def _active_finished(self, result: ActiveAuthResult) -> None:
        self.storage.save_active(result)
        self.current_active = result.to_dict()
        self.active_password_input.clear()
        self._display_active(self.current_active)
        self._post_update()

    def _active_failed(self, message: str) -> None:
        self.active_password_input.clear()
        QMessageBox.critical(self, "Falha no teste ativo", message)

    def _display_active(self, data: dict[str, Any]) -> None:
        self.active_score_card.set_value(f"{data.get('score', 0)}/100")
        self.active_risk_card.set_value(str(data.get("risk", "—")))
        self.active_verdict_card.set_value(str(data.get("verdict", "—")))
        self.active_attempt_card.set_value(f"{data.get('attempts_completed', 0)}/{data.get('attempts_requested', 0)}")
        findings = data.get("findings", [])
        self._fill_findings(self.active_findings_table, findings)
        attempts = data.get("attempts", [])
        self.attempts_table.setRowCount(len(attempts))
        for row, item in enumerate(attempts):
            for col, value in enumerate([item.get("number", ""), item.get("status_code", ""), f"{item.get('elapsed_ms', 0)} ms", item.get("signal", ""), item.get("retry_after", "")]):
                self.attempts_table.setItem(row, col, QTableWidgetItem(str(value)))
        for button in self.active_export_buttons:
            button.setEnabled(True)
        if findings:
            self.active_findings_table.selectRow(0)

    def _toggle_password_visibility(self) -> None:
        self.password_input.setEchoMode(QLineEdit.EchoMode.Normal if self.password_show.isChecked() else QLineEdit.EchoMode.Password)

    def _start_password(self) -> None:
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Senha necessária", "Informe uma senha sintética ou de laboratório para avaliação local.")
            return
        self.password_run.setEnabled(False)
        self.password_progress.setRange(0, 0)
        self.password_progress.show()
        self.password_input.clear()
        self.password_show.setChecked(False)
        self._start_thread("password", PasswordWorker(password), self._password_finished, self._password_failed)

    def _password_finished(self, result: PasswordAnalysisResult) -> None:
        self.storage.save_password(result)
        self.current_password = result.to_dict()
        self._display_password(self.current_password)
        self._post_update()

    def _password_failed(self, message: str) -> None:
        QMessageBox.critical(self, "Falha na análise", message)

    def _display_password(self, data: dict[str, Any]) -> None:
        self.password_score.set_value(f"{data.get('score', 0)}/100")
        self.password_rating.set_value(str(data.get("rating", "—")))
        self.password_entropy.set_value(f"{data.get('entropy_bits', 0)} bits")
        demo = f"ENCONTRADA · {data.get('demo_attempts', 0)}" if data.get("demo_found") else "NÃO ENCONTRADA"
        self.password_demo.set_value(demo)
        findings = data.get("findings", [])
        self._fill_findings(self.password_table, findings)
        for button in self.password_export_buttons:
            button.setEnabled(True)
        if findings:
            self.password_table.selectRow(0)

    def _start_hash(self) -> None:
        self.hash_run.setEnabled(False)
        self.hash_progress.setRange(0, 0)
        self.hash_progress.show()
        self.hash_detail.clear()
        self._start_thread("hash", HashWorker(self.hash_profile.currentText(), self.hash_samples.value()), self._hash_finished, self._hash_failed)

    def _hash_finished(self, result: HashBenchmarkResult) -> None:
        self.storage.save_hash(result)
        self.current_hash = result.to_dict()
        self._display_hash(self.current_hash)
        self._post_update()

    def _hash_failed(self, message: str) -> None:
        QMessageBox.critical(self, "Falha no benchmark", message)

    def _display_hash(self, data: dict[str, Any]) -> None:
        self.hash_median.set_value(f"{data.get('median_ms', 0)} ms")
        self.hash_rate.set_value(str(data.get("verifications_per_second", 0)))
        self.hash_range.set_value(f"{data.get('minimum_ms', 0)}–{data.get('maximum_ms', 0)} ms")
        self.hash_rating.set_value(str(data.get("rating", "—")))
        metadata = data.get("metadata", {})
        self.hash_detail.setPlainText(f"PERFIL\n{data.get('algorithm','')}\n\nAMOSTRAS\n{data.get('samples',0)}\n\nRESUMO\n{data.get('summary','')}\n\nPARÂMETROS\n{metadata.get('parameters',{})}\n\nSEGREDO REAL UTILIZADO\nNÃO")
        for button in self.hash_export_buttons:
            button.setEnabled(True)

    def _unlock_private(self) -> None:
        if not self.access.is_configured():
            first, ok = QInputDialog.getText(self, "Configurar modo privado", "Defina uma chave local com pelo menos 8 caracteres:", QLineEdit.EchoMode.Password)
            if not ok:
                return
            second, ok2 = QInputDialog.getText(self, "Confirmar chave", "Repita a chave local:", QLineEdit.EchoMode.Password)
            if not ok2:
                return
            if first != second:
                QMessageBox.warning(self, "Chaves diferentes", "As chaves informadas não coincidem.")
                return
            try:
                self.access.configure(first)
            except Exception as exc:
                QMessageBox.warning(self, "Chave inválida", str(exc))
                return
            self.private_unlocked = True
        else:
            value, ok = QInputDialog.getText(self, "Desbloquear modo privado", "Informe a chave local:", QLineEdit.EchoMode.Password)
            if not ok:
                return
            if not self.access.verify(value):
                QMessageBox.warning(self, "Acesso negado", "Chave local inválida.")
                return
            self.private_unlocked = True
        self.lab_access_state.setText("DESBLOQUEADO")
        self.lab_access_button.setText("Desbloqueado")
        self.lab_access_button.setEnabled(False)
        self.lab_change_button.setEnabled(True)
        self._update_lab_state()

    def _change_private_key(self) -> None:
        current, ok = QInputDialog.getText(self, "Alterar chave", "Chave atual:", QLineEdit.EchoMode.Password)
        if not ok:
            return
        new, ok2 = QInputDialog.getText(self, "Alterar chave", "Nova chave local:", QLineEdit.EchoMode.Password)
        if not ok2:
            return
        try:
            if not self.access.change(current, new):
                QMessageBox.warning(self, "Acesso negado", "Chave atual inválida.")
                return
        except Exception as exc:
            QMessageBox.warning(self, "Chave inválida", str(exc))
            return
        QMessageBox.information(self, "Chave atualizada", "A chave local foi atualizada.")

    def _start_lab(self) -> None:
        if not self.private_unlocked:
            QMessageBox.warning(self, "Modo bloqueado", "Desbloqueie o laboratório privado.")
            return
        login = self.lab_login_input.text().strip()
        username = self.lab_user_input.text().strip()
        decoy = self.lab_decoy_input.text()
        correct = self.lab_correct_input.text()
        attempts = self.lab_attempts.value()
        correct_at = self.lab_correct_at.value()
        interval = self.lab_interval.value()
        if not all([login, username, decoy, correct]):
            QMessageBox.warning(self, "Campos obrigatórios", "Preencha os dados da conta dedicada de laboratório.")
            return
        confirmation = QMessageBox.question(self, "Confirmar simulação", f"Executar sequência controlada no laboratório, com credencial válida conhecida apenas na tentativa {correct_at}?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if confirmation != QMessageBox.Yes:
            return
        self.lab_run.setEnabled(False)
        self.lab_progress.setRange(0, 0)
        self.lab_progress.show()
        self.lab_findings.setRowCount(0)
        self.lab_attempt_table.setRowCount(0)
        self.lab_detail.clear()
        self._start_thread("lab", LabWorker(login, username, decoy, correct, attempts, correct_at, interval), self._lab_finished, self._lab_failed)

    def _lab_finished(self, result: LabSimulationResult) -> None:
        self.storage.save_lab(result)
        self.current_lab = result.to_dict()
        self.lab_decoy_input.clear()
        self.lab_correct_input.clear()
        self._display_lab(self.current_lab)
        self._post_update()

    def _lab_failed(self, message: str) -> None:
        self.lab_decoy_input.clear()
        self.lab_correct_input.clear()
        QMessageBox.critical(self, "Falha na simulação", message)

    def _display_lab(self, data: dict[str, Any]) -> None:
        self.lab_verdict.set_value(str(data.get("verdict", "—")))
        self.lab_risk.set_value(str(data.get("risk", "—")))
        self.lab_success.set_value("ACEITA" if data.get("success_reached") else "NÃO ACEITA")
        self.lab_protection.set_value("ACIONADA" if data.get("protection_triggered") else "NÃO DETECTADA")
        findings = data.get("findings", [])
        self._fill_findings(self.lab_findings, findings)
        attempts = data.get("attempts", [])
        self.lab_attempt_table.setRowCount(len(attempts))
        for row, item in enumerate(attempts):
            values = [item.get("number", ""), item.get("credential_kind", ""), item.get("status_code", ""), f"{item.get('elapsed_ms', 0)} ms", item.get("signal", ""), "SIM" if item.get("success") else "NÃO"]
            for col, value in enumerate(values):
                self.lab_attempt_table.setItem(row, col, QTableWidgetItem(str(value)))
        for button in self.lab_export_buttons:
            button.setEnabled(True)
        if findings:
            self.lab_findings.selectRow(0)

    def _fill_findings(self, table: QTableWidget, findings: list[dict[str, Any]]) -> None:
        table.setRowCount(len(findings))
        for row, item in enumerate(findings):
            first = QTableWidgetItem(str(item.get("status", "")))
            first.setData(Qt.UserRole, item)
            values = [first, QTableWidgetItem(str(item.get("severity", ""))), QTableWidgetItem(str(item.get("category", ""))), QTableWidgetItem(str(item.get("title", ""))), QTableWidgetItem(f"{item.get('earned',0)}/{item.get('weight',0)}")]
            for col, value in enumerate(values):
                table.setItem(row, col, value)

    def _show_finding(self, table: QTableWidget, detail: QTextEdit) -> None:
        items = table.selectedItems()
        if not items:
            return
        data = table.item(items[0].row(), 0).data(Qt.UserRole)
        if not data:
            return
        detail.setPlainText(f"{data.get('status','')}  •  {data.get('severity','')}  •  {data.get('category','')}\n\n{data.get('title','')}\n\nEVIDÊNCIA\n{data.get('detail','')}\n\nRECOMENDAÇÃO\n{data.get('recommendation','')}")

    def _post_update(self) -> None:
        self._load_history()
        self._refresh_dashboard()
        self._refresh_comparison_options()

    def _refresh_dashboard(self) -> None:
        if not hasattr(self, "dashboard_text"):
            return
        passive = self.storage.latest_audit()
        active = self.storage.latest_active()
        password = self.storage.latest_password()
        lab = self.storage.latest_lab()
        self.dash_passive.set_value(f"{passive.get('score',0)}/100 · {passive.get('risk','')}" if passive else "SEM DADOS")
        self.dash_active.set_value(f"{active.get('score',0)}/100 · {active.get('risk','')}" if active else "SEM DADOS")
        self.dash_password.set_value(f"{password.get('score',0)}/100 · {password.get('rating','')}" if password else "SEM DADOS")
        self.dash_lab.set_value(str(lab.get("verdict", "")) if lab else "SEM DADOS")
        lines = []
        if passive:
            lines.append(f"AUDITORIA PASSIVA\n{passive.get('score',0)}/100 · risco {passive.get('risk','')} · cobertura {passive.get('coverage',0)}%\n{passive.get('summary','')}")
        if active:
            lines.append(f"RESILIÊNCIA DA AUTENTICAÇÃO\n{active.get('score',0)}/100 · risco {active.get('risk','')}\n{active.get('summary','')}")
        if lab:
            lines.append(f"LABORATÓRIO PRIVADO\n{lab.get('verdict','')} · risco {lab.get('risk','')}\n{lab.get('summary','')}")
        if password:
            lines.append(f"ROBUSTEZ DE SENHA LOCAL\n{password.get('score',0)}/100 · {password.get('rating','')}\n{password.get('summary','')}")
        self.dashboard_text.setPlainText("\n\n".join(lines) if lines else "Nenhuma execução registrada.")

    def _load_history(self) -> None:
        if hasattr(self, "history_table"):
            self._populate_history(self.history_table, self.storage.recent_audits(), lambda r: [r["id"], r["target_url"], r["login_url"], f"{r['score']}/100", r["risk"], self._date(r["started_at"])])
            self._populate_history(self.active_history_table, self.storage.recent_active(), lambda r: [r["id"], r["login_url"], r["account_hint"], f"{r['score']}/100", r["risk"], r["verdict"], self._date(r["started_at"])])
            self._populate_history(self.password_history_table, self.storage.recent_passwords(), lambda r: [r["id"], f"{r['score']}/100", r["rating"], self._date(r["created_at"])])
            self._populate_history(self.hash_history_table, self.storage.recent_hashes(), lambda r: [r["id"], r["algorithm"], r["median_ms"], r["rating"], self._date(r["created_at"])])
            self._populate_history(self.lab_history_table, self.storage.recent_labs(), lambda r: [r["id"], r["login_url"], r["account_hint"], r["verdict"], r["risk"], self._date(r["started_at"])])

    def _populate_history(self, table: QTableWidget, rows: list[dict[str, Any]], transform: Any) -> None:
        table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            values = transform(row)
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setData(Qt.UserRole, row["id"])
                table.setItem(row_index, col, item)

    def _date(self, value: str) -> str:
        return str(value)[:19].replace("T", " ")

    def _open_history_audit(self) -> None:
        data = self._selected_history(self.history_table, self.storage.get_audit)
        if data:
            self.current_audit = data
            self.target_input.setText(data.get("target_url", ""))
            self.login_input.setText(data.get("login_url", ""))
            self._display_audit(data)
            self.nav.setCurrentRow(1)

    def _open_history_active(self) -> None:
        data = self._selected_history(self.active_history_table, self.storage.get_active)
        if data:
            self.current_active = data
            self.active_login_input.setText(data.get("login_url", ""))
            self._display_active(data)
            self.nav.setCurrentRow(2)

    def _open_history_password(self) -> None:
        data = self._selected_history(self.password_history_table, self.storage.get_password)
        if data:
            self.current_password = data
            self._display_password(data)
            self.nav.setCurrentRow(3)

    def _open_history_hash(self) -> None:
        data = self._selected_history(self.hash_history_table, self.storage.get_hash)
        if data:
            self.current_hash = data
            self._display_hash(data)
            self.nav.setCurrentRow(4)

    def _open_history_lab(self) -> None:
        data = self._selected_history(self.lab_history_table, self.storage.get_lab)
        if data:
            self.current_lab = data
            self._display_lab(data)
            self.nav.setCurrentRow(5)

    def _selected_history(self, table: QTableWidget, getter: Any) -> dict[str, Any] | None:
        items = table.selectedItems()
        if not items:
            return None
        return getter(int(items[0].data(Qt.UserRole)))

    def _refresh_comparison_options(self) -> None:
        if not hasattr(self, "compare_passive_a"):
            return
        self._fill_combo(self.compare_passive_a, self.storage.recent_audits(), lambda r: f"#{r['id']} · {r['score']}/100 · {self._date(r['started_at'])}")
        self._fill_combo(self.compare_passive_b, self.storage.recent_audits(), lambda r: f"#{r['id']} · {r['score']}/100 · {self._date(r['started_at'])}")
        self._fill_combo(self.compare_active_a, self.storage.recent_active(), lambda r: f"#{r['id']} · {r['score']}/100 · {self._date(r['started_at'])}")
        self._fill_combo(self.compare_active_b, self.storage.recent_active(), lambda r: f"#{r['id']} · {r['score']}/100 · {self._date(r['started_at'])}")
        if self.compare_passive_b.count() > 1:
            self.compare_passive_b.setCurrentIndex(1)
        if self.compare_active_b.count() > 1:
            self.compare_active_b.setCurrentIndex(1)

    def _fill_combo(self, combo: QComboBox, rows: list[dict[str, Any]], labeler: Any) -> None:
        current = combo.currentData()
        combo.clear()
        for row in rows:
            combo.addItem(labeler(row), row["id"])
        if current is not None:
            index = combo.findData(current)
            if index >= 0:
                combo.setCurrentIndex(index)

    def _compare(self, kind: str) -> None:
        if kind == "passive":
            a_id = self.compare_passive_a.currentData()
            b_id = self.compare_passive_b.currentData()
            if a_id is None or b_id is None:
                return
            a = self.storage.get_audit(int(a_id))
            b = self.storage.get_audit(int(b_id))
            if not a or not b:
                return
            left = {item.get("key"): item for item in a.get("findings", [])}
            right = {item.get("key"): item for item in b.get("findings", [])}
            changes = []
            for key in sorted(set(left) | set(right)):
                before = left.get(key, {}).get("status", "—")
                after = right.get(key, {}).get("status", "—")
                if before != after:
                    title = left.get(key, {}).get("title") or right.get(key, {}).get("title") or key
                    changes.append(f"{title}: {before} → {after}")
            delta = int(b.get("score", 0)) - int(a.get("score", 0))
            self.compare_passive_text.setPlainText(f"EXECUÇÃO A\nScore {a.get('score',0)}/100 · {a.get('risk','')}\n\nEXECUÇÃO B\nScore {b.get('score',0)}/100 · {b.get('risk','')}\n\nVARIAÇÃO\n{delta:+d} pontos\n\nCONTROLES ALTERADOS\n" + ("\n".join(changes) if changes else "Nenhuma alteração de status identificada."))
        else:
            a_id = self.compare_active_a.currentData()
            b_id = self.compare_active_b.currentData()
            if a_id is None or b_id is None:
                return
            a = self.storage.get_active(int(a_id))
            b = self.storage.get_active(int(b_id))
            if not a or not b:
                return
            delta = int(b.get("score", 0)) - int(a.get("score", 0))
            self.compare_active_text.setPlainText(f"EXECUÇÃO A\n{a.get('score',0)}/100 · {a.get('risk','')}\n{a.get('verdict','')}\n\nEXECUÇÃO B\n{b.get('score',0)}/100 · {b.get('risk','')}\n{b.get('verdict','')}\n\nVARIAÇÃO\n{delta:+d} pontos\n\nTENTATIVAS\nA: {a.get('attempts_completed',0)}\nB: {b.get('attempts_completed',0)}")

    def _export_comparison(self, kind: str) -> None:
        if kind == "passive":
            a_id, b_id = self.compare_passive_a.currentData(), self.compare_passive_b.currentData()
            getter = self.storage.get_audit
        else:
            a_id, b_id = self.compare_active_a.currentData(), self.compare_active_b.currentData()
            getter = self.storage.get_active
        if a_id is None or b_id is None:
            return
        a, b = getter(int(a_id)), getter(int(b_id))
        if not a or not b:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Relatório comparativo", "aegis-comparison.pdf", "PDF (*.pdf)")
        if path:
            save_comparison_pdf(a, b, Path(path), kind)

    def _export_executive(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Relatório executivo", "aegis-executive-report.pdf", "PDF (*.pdf)")
        if path:
            save_executive_pdf(self.storage.latest_audit(), self.storage.latest_active(), self.storage.latest_lab(), Path(path))

    def _save_json_dialog(self, data: dict[str, Any] | None, filename: str) -> None:
        if not data:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exportar resultado", filename, "JSON (*.json)")
        if path:
            save_json(data, Path(path))

    def _export_audit_json(self) -> None: self._save_json_dialog(self.current_audit, "aegis-audit.json")
    def _export_active_json(self) -> None: self._save_json_dialog(self.current_active, "aegis-active-test.json")
    def _export_password_json(self) -> None: self._save_json_dialog(self.current_password, "aegis-password-analysis.json")
    def _export_hash_json(self) -> None: self._save_json_dialog(self.current_hash, "aegis-hash-benchmark.json")
    def _export_lab_json(self) -> None: self._save_json_dialog(self.current_lab, "aegis-lab-simulation.json")

    def _export_audit_csv(self) -> None:
        if self.current_audit:
            path, _ = QFileDialog.getSaveFileName(self, "Exportar controles", "aegis-audit.csv", "CSV (*.csv)")
            if path: save_audit_csv(self.current_audit, Path(path))

    def _export_active_csv(self) -> None:
        if self.current_active:
            path, _ = QFileDialog.getSaveFileName(self, "Exportar evidências", "aegis-active-test.csv", "CSV (*.csv)")
            if path: save_active_csv(self.current_active, Path(path))

    def _export_lab_csv(self) -> None:
        if self.current_lab:
            path, _ = QFileDialog.getSaveFileName(self, "Exportar evidências", "aegis-lab-simulation.csv", "CSV (*.csv)")
            if path: save_lab_csv(self.current_lab, Path(path))

    def _export_audit_pdf(self) -> None:
        if self.current_audit:
            path, _ = QFileDialog.getSaveFileName(self, "Gerar relatório", "aegis-audit.pdf", "PDF (*.pdf)")
            if path: save_audit_pdf(self.current_audit, Path(path))

    def _export_active_pdf(self) -> None:
        if self.current_active:
            path, _ = QFileDialog.getSaveFileName(self, "Gerar relatório", "aegis-active-test.pdf", "PDF (*.pdf)")
            if path: save_active_pdf(self.current_active, Path(path))

    def _export_password_pdf(self) -> None:
        if self.current_password:
            path, _ = QFileDialog.getSaveFileName(self, "Gerar relatório", "aegis-password-analysis.pdf", "PDF (*.pdf)")
            if path: save_password_pdf(self.current_password, Path(path))

    def _export_hash_pdf(self) -> None:
        if self.current_hash:
            path, _ = QFileDialog.getSaveFileName(self, "Gerar relatório", "aegis-hash-benchmark.pdf", "PDF (*.pdf)")
            if path: save_hash_pdf(self.current_hash, Path(path))

    def _export_lab_pdf(self) -> None:
        if self.current_lab:
            path, _ = QFileDialog.getSaveFileName(self, "Gerar relatório", "aegis-lab-simulation.pdf", "PDF (*.pdf)")
            if path: save_lab_pdf(self.current_lab, Path(path))


def apply_theme(app: QApplication) -> None:
    app.setFont(QFont("Segoe UI", 10))
    app.setStyleSheet("""
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
    #metricValue { font-size: 21px; font-weight: 760; color: #f4f6f1; }
    #fieldLabel { color: #9aa397; font-size: 11px; font-weight: 600; }
    #sectionTitle { font-size: 14px; font-weight: 700; color: #f4f6f1; }
    QLineEdit, QComboBox, QDoubleSpinBox, QSpinBox { background: #101410; border: 1px solid #303730; border-radius: 8px; padding: 10px 11px; color: #f1f4ee; selection-background-color: #d4ff2f; selection-color: #101310; }
    QLineEdit:focus, QComboBox:focus, QDoubleSpinBox:focus, QSpinBox:focus { border: 1px solid #d4ff2f; }
    QComboBox QAbstractItemView { background: #171b17; color: #f1f4ee; selection-background-color: #273027; }
    QCheckBox { color: #aab2a7; spacing: 8px; } QCheckBox::indicator { width: 17px; height: 17px; }
    QPushButton { background: #222822; border: 1px solid #333b33; border-radius: 8px; padding: 10px 14px; color: #e9ece6; font-weight: 600; }
    QPushButton:hover { background: #2a312a; } QPushButton:disabled { color: #666d65; background: #181c18; border-color: #232823; }
    #primaryButton { background: #d4ff2f; color: #111411; border: none; padding: 11px 20px; font-weight: 800; } #primaryButton:hover { background: #c5f020; }
    QProgressBar { border: none; background: #1a1f1a; border-radius: 3px; height: 5px; } QProgressBar::chunk { background: #d4ff2f; border-radius: 3px; }
    QTableWidget { background: #131713; alternate-background-color: #151a15; border: none; gridline-color: #252b25; selection-background-color: #273027; selection-color: #ffffff; }
    QHeaderView::section { background: #1c211c; color: #8f998d; border: none; border-bottom: 1px solid #303630; padding: 9px; font-size: 10px; font-weight: 700; }
    QTextEdit { background: #111511; border: 1px solid #272d27; border-radius: 9px; padding: 12px; color: #cbd1c7; }
    QSplitter::handle { background: #0f120f; width: 8px; height: 8px; }
    QTabWidget::pane { border: 1px solid #2a302a; border-radius: 10px; background: #171b17; }
    QTabBar::tab { background: #171b17; color: #90998e; padding: 10px 16px; border: 1px solid #2a302a; }
    QTabBar::tab:selected { color: #111411; background: #d4ff2f; font-weight: 700; }
    QMessageBox { background: #171b17; }
    """)
