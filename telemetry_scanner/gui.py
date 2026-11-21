"""PySide6 dashboard for the Telemetry Injection Vulnerability Scanner."""
import threading
from datetime import datetime, timezone

from PySide6.QtCore import QObject, QThread, Signal, Qt, QTimer, QElapsedTimer
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtGui import QColor

from .active import ActiveConfig, ActiveValidator
from .models import ScanReport, Status
from .reports import export_html, export_json, export_jsonl, export_har
from .scanner import scan
from .scope import ScopeError, normalize_http_url, redact_sensitive_url


DASHBOARD_QSS = """
* { font-family: 'Share Tech Mono', 'Rajdhani', 'Inter', 'DejaVu Sans Mono', monospace; }
QMainWindow, QWidget#appRoot { background: #050508; color: #F7F5FC; }
QWidget { color: #F7F5FC; font-size: 13px; }
QLabel { background: transparent; }
QFrame#masthead { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #130B20,stop:0.58 #090914,stop:1 #071412); border: 1px solid #332342; border-radius: 13px; }
QFrame#brandMark { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #E11D8A,stop:0.48 #8B5CF6,stop:1 #00DCC0); border: 1px solid #F0ABFC; border-radius: 9px; }
QLabel#brandMarkText { color: #FFFFFF; font-family: 'DejaVu Sans Mono', monospace; font-size: 21px; font-weight: 900; }
QLabel#eyebrow { color: #00F5D4; font-size: 10px; font-weight: 900; letter-spacing: 2px; }
QLabel#appTitle { color: #FFFFFF; font-family: 'Rajdhani', 'DejaVu Sans', sans-serif; font-size: 34px; font-weight: 900; letter-spacing: 5px; }
QLabel#appSubtitle { color: #B7B1C7; font-family: 'Share Tech Mono', 'DejaVu Sans Mono', monospace; font-size: 11px; font-weight: 700; letter-spacing: 2px; }
QLabel#sectionTitle { color: #F1E8FF; font-family: 'Rajdhani', 'DejaVu Sans', sans-serif; font-size: 15px; font-weight: 900; letter-spacing: 2px; }
QLabel#helper { color: #9994A8; font-size: 11px; }
QLabel#microLabel { color: #8F899E; font-size: 9px; font-weight: 800; letter-spacing: 1px; }
QLabel#statusReady, QLabel#statusBusy { font-size: 11px; font-weight: 900; padding: 8px 13px; border-radius: 8px; }
QLabel#statusReady { color: #00F5D4; border: 1px solid #087C70; background: #071A19; }
QLabel#statusBusy { color: #F0ABFC; border: 1px solid #A855F7; background: #21102A; }
QLabel#railValue { color: #EDE8F7; font-size: 11px; font-weight: 800; }
QFrame#statusRail { background: #090914; border: 1px solid #28223B; border-left: 2px solid #A855F7; border-radius: 8px; }
QFrame#metricPanel { background: #0A0A13; border: 1px solid #28223B; border-bottom: 2px solid #8B5CF6; border-radius: 8px; }
QLabel#metricValue { color: #FFFFFF; font-family: 'Rajdhani', 'DejaVu Sans', sans-serif; font-size: 22px; font-weight: 900; }
QLabel#metricValueTeal { color: #00F5D4; font-family: 'Rajdhani', 'DejaVu Sans', sans-serif; font-size: 22px; font-weight: 900; }
QFrame#panel { background: #090914; border: 1px solid #292438; border-top: 1px solid #553478; border-radius: 10px; }
QFrame#panel:hover { border-color: #7A48A5; }
QFrame#panelAccent { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #110D1B,stop:1 #091211); border: 1px solid #7442A0; border-left: 3px solid #00DCC0; border-radius: 10px; }
QFrame#panelAccent:hover { border-color: #C026D3; border-left-color: #00F5D4; }
QFrame#headerRule { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #E11D8A,stop:0.4 #8B5CF6,stop:1 #00DCC0); border: none; max-height: 2px; }
QFrame#footerRail { background: #080810; border-top: 1px solid #39264B; }
QScrollArea#dashboardScroll { background: transparent; border: none; }
QScrollArea#dashboardScroll > QWidget > QWidget { background: transparent; }
QLineEdit, QComboBox, QTextEdit { background: #05050B; color: #F8F6FC; border: 1px solid #3A334C; border-radius: 6px; padding: 10px 12px; selection-background-color: #7C3AED; }
QLineEdit:focus, QComboBox:focus, QTextEdit:focus { border: 1px solid #C026D3; background: #090711; }
QComboBox:hover { border-color: #00BFA8; }
QLineEdit::placeholder { color: #777285; }
QComboBox::drop-down { border: none; width: 26px; }
QComboBox QAbstractItemView { background: #090914; color: #F7F5FC; selection-background-color: #42205A; border: 1px solid #A855F7; }
QCheckBox { color: #E4DFED; spacing: 10px; font-size: 12px; }
QCheckBox::indicator { width: 17px; height: 17px; border: 1px solid #746887; border-radius: 3px; background: #05050B; }
QCheckBox::indicator:checked { background: #00BFA8; border-color: #00F5D4; }
QPushButton { min-height: 38px; border-radius: 5px; padding: 0 18px; font-weight: 900; letter-spacing: 1px; }
QPushButton#startButton { color: #FFFFFF; border: 1px solid #D8B4FE; background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #A855F7,stop:0.62 #7C3AED,stop:1 #5B21B6); }
QPushButton#startButton:hover { color: #FFFFFF; border-color: #00F5D4; background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #C026D3,stop:1 #7C3AED); }
QPushButton#startButton:pressed { background: #4C1D95; border-color: #00F5D4; }
QPushButton#startButton:disabled { color: #777181; border-color: #393344; background: #1B1923; }
QPushButton#stopButton { color: #FF9BAA; border: 1px solid #87344D; background: #1D0D16; }
QPushButton#stopButton:hover { color: #FFFFFF; border-color: #FF466D; background: #4A1428; }
QPushButton#stopButton:pressed { background: #3B151E; border-color: #FF7183; }
QPushButton#stopButton:disabled { color: #65545A; border-color: #35262B; background: #151116; }
QPushButton#exportButton { color: #B8FFF5; border: 1px solid #087C70; background: #071715; }
QPushButton#exportButton:hover { color: #FFFFFF; border-color: #00F5D4; background: #0E302B; }
QPushButton#exportButton:pressed { background: #0B2927; border-color: #C026D3; }
QProgressBar { color: #C9FFF7; background: #05050B; border: 1px solid #49325E; border-radius: 4px; text-align: center; min-height: 18px; max-height: 18px; font-size: 10px; font-weight: 900; }
QProgressBar::chunk { border-radius: 3px; background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #E11D8A,stop:0.52 #8B5CF6,stop:1 #00F5D4); }
QTableWidget { background: #06060D; alternate-background-color: #0B0A13; color: #ECE8F4; border: 1px solid #332B45; border-radius: 6px; gridline-color: #211C2E; selection-background-color: #352042; selection-color: #FFFFFF; }
QHeaderView::section { background: #100D19; color: #C8B8DC; border: none; border-bottom: 1px solid #7A3AA0; padding: 11px 8px; font-size: 10px; font-weight: 900; letter-spacing: 1.2px; }
QTableWidget::item { padding: 8px; }
QTableWidget::item:hover { background: #21172E; }
QScrollBar:vertical { background: #080810; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #4A3561; border-radius: 4px; min-height: 22px; }
QScrollBar::handle:vertical:hover { background: #A855F7; }
QSplitter::handle { background: #382747; width: 3px; }
QLabel#credit { color: #F0ABFC; font-family: 'Rajdhani', 'DejaVu Sans', sans-serif; font-size: 12px; font-weight: 900; letter-spacing: 1.3px; }
QLabel#footerNote { color: #777285; font-size: 9px; letter-spacing: 1px; }
"""


class Worker(QObject):
    # total=0 means the crawler is still discovering its dynamic workload.
    progress = Signal(int, int, str, int, int)
    done = Signal(object)

    def __init__(self, target, stop, active=False, approved=None, authorized=False):
        super().__init__()
        self.target = target
        self.stop = stop
        self.active = active
        self.approved = approved or []
        self.authorized = authorized
        self._phase = "INITIALIZING SCANNER"
        self._work_completed = 0
        self._work_total = 0
        self._resources_completed = 0
        self._resources_total = 0
        self._finished = False

    def _emit_status(self, phase):
        if self._finished:
            return
        self._phase = phase
        self.progress.emit(
            self._work_completed, self._work_total, self._phase,
            self._resources_completed, self._resources_total,
        )

    def _emit_work_progress(self, current, total):
        if self._finished:
            return
        self._work_completed = max(self._work_completed, int(current))
        self._work_total = max(0, int(total))
        self.progress.emit(
            self._work_completed, self._work_total, self._phase,
            self._resources_completed, self._resources_total,
        )

    def _on_scan_progress(self, current, total):
        if self._finished:
            return
        self._resources_completed = max(self._resources_completed, int(current))
        if total > 0:
            self._resources_total = int(total)
        self._work_completed = self._resources_completed
        self._work_total = max(0, int(total))
        if total > 0:
            # The crawl has settled, but active-validation work (if selected)
            # must be added to the final denominator before displaying a ratio.
            return
        self.progress.emit(
            self._work_completed, self._work_total, self._phase,
            self._resources_completed, self._resources_total,
        )

    def run(self):
        started = datetime.now(timezone.utc).isoformat()
        mode = "Active validation" if self.active else "Discovery"
        report = None
        try:
            report = scan(
                self.target,
                self._on_scan_progress,
                self.stop.is_set,
                status=self._emit_status,
            )
            report.mode = mode
            if self.active and not self.stop.is_set():
                if not self.authorized:
                    for endpoint in report.endpoints:
                        if endpoint.url in self.approved:
                            endpoint.limitations.append(
                                "Active test skipped: explicit operator authorization was not confirmed."
                            )
                        else:
                            endpoint.limitations.append(
                                "Active test skipped: discovered endpoint is not explicitly allowlisted."
                            )
                else:
                    eligible = [endpoint for endpoint in report.endpoints if endpoint.url in self.approved]
                    resource_count = self._resources_completed
                    total_work = resource_count + len(eligible)
                    self._emit_work_progress(resource_count, total_work)
                    self._emit_status("VALIDATING ALLOWLISTED ENDPOINTS")
                    validator = ActiveValidator(ActiveConfig(self.approved, timeout=5.0, min_interval=2.0))
                    try:
                        for endpoint in eligible:
                            if self.stop.is_set():
                                break
                            validator.submit(endpoint, True)
                            if endpoint.auth_evidence.startswith("Request failed:"):
                                report.errors.append(
                                    f"{redact_sensitive_url(endpoint.url)}: authorized validation {endpoint.auth_evidence}"
                                )
                            self._emit_work_progress(self._work_completed + 1, total_work)
                    finally:
                        validator.close()
                    for endpoint in report.endpoints:
                        if endpoint.url not in self.approved:
                            endpoint.limitations.append(
                                "Active test skipped: discovered endpoint is not explicitly allowlisted."
                            )
            elif not self.active:
                self._emit_work_progress(self._resources_completed, self._resources_total)
        except Exception as exc:
            # Always signal completion so the GUI can recover its controls and thread.
            if report is None:
                report = ScanReport(
                    target=self.target,
                    started_at=started,
                    finished_at=datetime.now(timezone.utc).isoformat(),
                    mode=mode,
                )
            report.errors.append(f"Unexpected worker failure: {type(exc).__name__}")
            report.finished_at = datetime.now(timezone.utc).isoformat()
        # Completion is the final worker event. No progress can be emitted
        # after this point, even if a callback is retained accidentally.
        self._finished = True
        self.done.emit(report)


def make_panel(title, accent=False, helper=None):
    """Build a reusable dark-glass card with a consistent heading."""
    frame = QFrame()
    frame.setObjectName("panelAccent" if accent else "panel")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(18, 15, 18, 16)
    layout.setSpacing(10)
    heading = QLabel(title)
    heading.setObjectName("sectionTitle")
    layout.addWidget(heading)
    if helper:
        note = QLabel(helper)
        note.setObjectName("helper")
        note.setWordWrap(True)
        layout.addWidget(note)
    return frame, layout


def make_metric_card(label, value, teal=False):
    """Create a compact dashboard metric with reusable label/value styling."""
    frame = QFrame()
    frame.setObjectName("metricPanel")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(14, 8, 14, 8)
    layout.setSpacing(2)
    caption = QLabel(label)
    caption.setObjectName("microLabel")
    number = QLabel(value)
    number.setObjectName("metricValueTeal" if teal else "metricValue")
    layout.addWidget(caption)
    layout.addWidget(number)
    return frame, number


ASSESSMENT_STYLES = {
    Status.DISCOVERED: ("OBSERVED", "#00F5D4"),
    Status.AUTH_REQUIRED: ("AUTH GATE", "#C4B5FD"),
    Status.POTENTIAL: ("REVIEW", "#F0ABFC"),
    Status.INGESTED: ("INGESTED", "#5EEAD4"),
    Status.FINDING: ("FINDING", "#FF5577"),
    Status.INCONCLUSIVE: ("UNVERIFIED", "#B3A9C7"),
}


def make_assessment_item(status):
    """Create a high-contrast class marker while preserving the underlying status."""
    label, color = ASSESSMENT_STYLES.get(status, ("UNKNOWN", "#B3A9C7"))
    item = QTableWidgetItem(label)
    item.setForeground(QColor(color))
    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    item.setToolTip(str(status))
    return item


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Telemetry Injection Vulnerability Scanner")
        self.resize(1440, 960)
        self.setMinimumSize(1020, 740)
        self.report = None
        self.stop_event = threading.Event()
        self.worker_thread = None
        self._close_when_idle = False
        self._progress_finished = True
        self._resource_current = 0
        self._resource_total = 0
        self._work_completed = 0
        self._work_total = 0
        self.elapsed_clock = QElapsedTimer()
        self.elapsed_timer = QTimer(self)
        self.elapsed_timer.setInterval(1000)
        self.elapsed_timer.timeout.connect(self._update_elapsed)

        root = QWidget()
        root.setObjectName("appRoot")
        outer = QVBoxLayout(root)
        outer.setContentsMargins(24, 18, 24, 14)
        outer.setSpacing(11)

        # High-contrast console masthead.
        masthead = QFrame()
        masthead.setObjectName("masthead")
        masthead_layout = QHBoxLayout(masthead)
        masthead_layout.setContentsMargins(18, 14, 18, 14)
        masthead_layout.setSpacing(17)
        brand_mark = QFrame()
        brand_mark.setObjectName("brandMark")
        brand_mark.setFixedSize(62, 62)
        mark_layout = QVBoxLayout(brand_mark)
        mark_layout.setContentsMargins(2, 2, 2, 2)
        mark_text = QLabel("TS//")
        mark_text.setObjectName("brandMarkText")
        mark_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark_layout.addWidget(mark_text)
        masthead_layout.addWidget(brand_mark)

        brand = QVBoxLayout()
        brand.setSpacing(3)
        eyebrow = QLabel("NIGHTWATCH  /  TELEMETRY INTELLIGENCE DIVISION")
        eyebrow.setObjectName("eyebrow")
        title = QLabel("TELEMETRY//SCANNER")
        title.setObjectName("appTitle")
        subtitle = QLabel("INJECTION SURFACE ANALYSIS  •  FIELD OPERATIONS CONSOLE")
        subtitle.setObjectName("appSubtitle")
        brand.addWidget(eyebrow)
        brand.addWidget(title)
        brand.addWidget(subtitle)
        masthead_layout.addLayout(brand)
        masthead_layout.addStretch(1)

        node_meta = QVBoxLayout()
        node_meta.setSpacing(5)
        node_label = QLabel("NODE 07  /  LOCAL ANALYSIS")
        node_label.setObjectName("microLabel")
        self.status_indicator = QLabel("●  PASSIVE MODE / READY")
        self.status_indicator.setObjectName("statusReady")
        self.status_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        node_meta.addWidget(node_label, 0, Qt.AlignmentFlag.AlignRight)
        node_meta.addWidget(self.status_indicator, 0, Qt.AlignmentFlag.AlignRight)
        masthead_layout.addLayout(node_meta)
        outer.addWidget(masthead)

        laser_rule = QFrame()
        laser_rule.setObjectName("headerRule")
        outer.addWidget(laser_rule)

        # Compact operational telemetry rail.
        status_rail = QFrame()
        status_rail.setObjectName("statusRail")
        rail = QHBoxLayout(status_rail)
        rail.setContentsMargins(12, 7, 12, 7)
        rail.setSpacing(12)
        rail_label = QLabel("SYS.STATUS")
        rail_label.setObjectName("eyebrow")
        self.scope_state = QLabel("SAME-ORIGIN DISCOVERY")
        self.scope_state.setObjectName("railValue")
        rail.addWidget(rail_label)
        rail.addWidget(self.scope_state)
        rail.addStretch(1)
        self.run_state = QLabel("READY  /  NO SCAN RUNNING")
        self.run_state.setObjectName("railValue")
        rail.addWidget(self.run_state)
        outer.addWidget(status_rail)

        # Keep the ops header and export dock fixed while the dashboard body scrolls on short screens.
        dashboard_scroll = QScrollArea()
        dashboard_scroll.setObjectName("dashboardScroll")
        dashboard_scroll.setWidgetResizable(True)
        dashboard_scroll.setFrameShape(QFrame.Shape.NoFrame)
        dashboard_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        dashboard_content = QWidget()
        dashboard_layout = QVBoxLayout(dashboard_content)
        dashboard_layout.setContentsMargins(0, 4, 0, 4)
        dashboard_layout.setSpacing(11)
        dashboard_scroll.setWidget(dashboard_content)
        outer.addWidget(dashboard_scroll, 1)

        # High-level result counters stay visible above the controls.
        metric_row = QHBoxLayout()
        metric_row.setSpacing(10)
        metric, self.metric_endpoints = make_metric_card("ENDPOINTS OBSERVED", "00", teal=True)
        metric_row.addWidget(metric)
        metric, self.metric_confirmed = make_metric_card("CONFIRMED FINDINGS", "00")
        metric_row.addWidget(metric)
        metric, self.metric_mode = make_metric_card("ACTIVE TESTING", "LOCKED / OPT-IN")
        metric_row.addWidget(metric)
        dashboard_layout.addLayout(metric_row)

        # Target and analysis mode cards.
        top_grid = QGridLayout()
        top_grid.setHorizontalSpacing(11)
        target_card, target_layout = make_panel(
            "01  /  TARGET UPLINK",
            helper="Authorized application origin. Passive discovery stays within the same origin and a 25-resource cap.",
        )
        self.target = QLineEdit()
        self.target.setPlaceholderText("https://authorized-app.example  |  http://127.0.0.1:8000/")
        self.target.setMinimumHeight(42)
        target_layout.addWidget(self.target)
        top_grid.addWidget(target_card, 0, 0, 3, 5)

        mode_card, mode_layout = make_panel(
            "02  /  SCAN PROFILE",
            accent=True,
            helper="Active validation remains opt-in and endpoint-allowlisted.",
        )
        self.mode = QComboBox()
        self.mode.addItems(["DISCOVERY  /  PASSIVE", "ACTIVE VALIDATION  /  AUTHORIZED ONLY"])
        self.mode.setMinimumHeight(42)
        mode_layout.addWidget(self.mode)
        top_grid.addWidget(mode_card, 0, 5, 3, 4)
        dashboard_layout.addLayout(top_grid)

        authorization_card, authorization_layout = make_panel(
            "03  /  AUTHORIZATION FIREWALL",
            accent=True,
            helper="Only an exact discovered endpoint in this allowlist can receive a single synthetic event. Third-party discoveries are never tested by appearance alone.",
        )
        self.allowlist = QLineEdit()
        self.allowlist.setPlaceholderText("Exact authorized endpoint URLs  •  comma separated")
        self.allowlist.setMinimumHeight(40)
        authorization_layout.addWidget(self.allowlist)
        self.authorized = QCheckBox("I OWN OR AM EXPLICITLY AUTHORIZED TO TEST EVERY ENDPOINT LISTED ABOVE")
        authorization_layout.addWidget(self.authorized)
        dashboard_layout.addWidget(authorization_card)

        # Prominent control deck.
        action_row = QHBoxLayout()
        action_row.setSpacing(10)
        self.scan_btn = QPushButton("▶   INITIALIZE SCAN")
        self.scan_btn.setObjectName("startButton")
        self.scan_btn.setMinimumHeight(48)
        self.stop_btn = QPushButton("■   ABORT / STOP")
        self.stop_btn.setObjectName("stopButton")
        self.stop_btn.setMinimumHeight(48)
        self.stop_btn.setEnabled(False)
        action_row.addWidget(self.scan_btn, 3)
        action_row.addWidget(self.stop_btn, 1)
        action_row.addStretch(1)
        self.progress_state = QLabel("AWAITING INPUT")
        self.progress_state.setObjectName("eyebrow")
        action_row.addWidget(self.progress_state)
        dashboard_layout.addLayout(action_row)

        progress_card, progress_layout = make_panel("04  /  SCAN TELEMETRY")
        progress_meta = QHBoxLayout()
        self.progress_counts = QLabel("RESOURCES: 0 / —")
        self.progress_counts.setObjectName("railValue")
        self.work_counts = QLabel("WORK UNITS: 0 / —")
        self.work_counts.setObjectName("railValue")
        self.elapsed_label = QLabel("ELAPSED: 00:00:00")
        self.elapsed_label.setObjectName("railValue")
        progress_meta.addWidget(self.progress_counts)
        progress_meta.addSpacing(16)
        progress_meta.addWidget(self.work_counts)
        progress_meta.addStretch(1)
        progress_meta.addWidget(self.elapsed_label)
        progress_layout.addLayout(progress_meta)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFormat("IDLE  •  %p%")
        progress_layout.addWidget(self.progress)
        dashboard_layout.addWidget(progress_card)

        # Threat-analysis table and evidence inspector.
        results_card, results_layout = make_panel(
            "05  /  THREAT ANALYSIS MATRIX",
            helper="Color-coded signal classes describe assessment state; accepted telemetry alone is not a confirmed security finding.",
        )
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["SIGNAL", "SERVICE", "ENDPOINT", "STATUS", "AUTH TRACE"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(36)
        self.table.setMinimumHeight(230)

        detail_wrap = QWidget()
        detail_layout = QVBoxLayout(detail_wrap)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_title = QLabel("EVIDENCE / ANALYST VIEW")
        detail_title.setObjectName("eyebrow")
        detail_layout.addWidget(detail_title)
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a signal to inspect source evidence, test conditions, limitations, and remediation.")
        detail_layout.addWidget(self.details)
        splitter.addWidget(self.table)
        splitter.addWidget(detail_wrap)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        results_layout.addWidget(splitter)
        dashboard_layout.addWidget(results_card, 1)

        # Distinct export dock and visible author credit.
        footer = QFrame()
        footer.setObjectName("footerRail")
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(2, 8, 2, 0)
        footer_layout.setSpacing(10)
        self.credit_label = QLabel("DESIGNED & ENHANCED BY Ph15h3r")
        self.credit_label.setObjectName("credit")
        footer_note = QLabel("LOCAL SCOPE  •  PASSIVE BY DEFAULT  •  AUTHORIZATION REQUIRED FOR ACTIVE TESTS")
        footer_note.setObjectName("footerNote")
        footer_layout.addWidget(self.credit_label)
        footer_layout.addSpacing(10)
        footer_layout.addWidget(footer_note)
        footer_layout.addStretch(1)
        self.export_btn = QPushButton("EXPORT  /  JSON")
        self.export_btn.setObjectName("exportButton")
        self.html_export_btn = QPushButton("EXPORT  /  HTML")
        self.html_export_btn.setObjectName("exportButton")
        self.jsonl_export_btn = QPushButton("EXPORT  /  JSONL")
        self.jsonl_export_btn.setObjectName("exportButton")
        self.har_export_btn = QPushButton("EXPORT  /  HAR")
        self.har_export_btn.setObjectName("exportButton")
        footer_layout.addWidget(self.export_btn)
        footer_layout.addWidget(self.html_export_btn)
        footer_layout.addWidget(self.jsonl_export_btn)
        footer_layout.addWidget(self.har_export_btn)
        outer.addWidget(footer)

        self.setCentralWidget(root)
        self.setStyleSheet(DASHBOARD_QSS)
        self.scan_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.export_btn.clicked.connect(lambda: self.export("json"))
        self.html_export_btn.clicked.connect(lambda: self.export("html"))
        self.jsonl_export_btn.clicked.connect(lambda: self.export("jsonl"))
        self.har_export_btn.clicked.connect(lambda: self.export("har"))
        self.table.itemSelectionChanged.connect(self.show_details)
        self.mode.currentIndexChanged.connect(self.update_mode_state)
        self.update_mode_state()

    def _update_elapsed(self):
        seconds = self.elapsed_clock.elapsed() // 1000
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        self.elapsed_label.setText(f"ELAPSED: {hours:02d}:{minutes:02d}:{seconds:02d}")
    def update_mode_state(self):
        active = self.mode.currentIndex() == 1
        self.allowlist.setEnabled(active)
        self.authorized.setEnabled(active)
        if active:
            self.status_indicator.setText("●  ACTIVE MODE / AUTH GATED")
            self.status_indicator.setObjectName("statusBusy")
            self.scope_state.setText("EXPLICIT ALLOWLIST REQUIRED")
            self.metric_mode.setText("ACTIVE / GATED")
        else:
            self.status_indicator.setText("●  PASSIVE MODE / READY")
            self.status_indicator.setObjectName("statusReady")
            self.scope_state.setText("SAME-ORIGIN DISCOVERY")
            self.metric_mode.setText("LOCKED / OPT-IN")
        self.status_indicator.style().unpolish(self.status_indicator)
        self.status_indicator.style().polish(self.status_indicator)

    def start_scan(self):
        try:
            target = normalize_http_url(self.target.text())
        except ScopeError as exc:
            QMessageBox.warning(self, "Invalid target", str(exc))
            return
        active = self.mode.currentIndex() == 1
        approved = []
        if active:
            try:
                approved = [normalize_http_url(item) for item in self.allowlist.text().split(",") if item.strip()]
                if not approved or not self.authorized.isChecked():
                    raise ScopeError(
                        "Active validation requires an explicit endpoint allowlist and authorization confirmation."
                    )
            except ScopeError as exc:
                QMessageBox.warning(self, "Active validation blocked", str(exc))
                return

        self.stop_event.clear()
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_indicator.setText("●  ANALYSIS IN PROGRESS")
        self.status_indicator.setObjectName("statusBusy")
        self.status_indicator.style().unpolish(self.status_indicator)
        self.status_indicator.style().polish(self.status_indicator)
        self.status_indicator.setText("●  SCAN IN PROGRESS")
        self.run_state.setText("RUNNING  /  SAME-ORIGIN CAP: 25")
        self.progress_state.setText("CRAWLING IN-SCOPE RESOURCES")
        self._progress_finished = False
        self._resource_current = 0
        self._resource_total = 0
        self._work_completed = 0
        self._work_total = 0
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFormat("INITIALIZING  •  0%")
        self.progress_counts.setText("RESOURCES: 0 / DISCOVERING")
        self.work_counts.setText("WORK UNITS: 0 / DISCOVERING")
        self.elapsed_clock.start()
        self.elapsed_label.setText("ELAPSED: 00:00:00")
        self.elapsed_timer.start()

        self.worker_thread = QThread(self)
        self.worker = Worker(
            target,
            self.stop_event,
            active,
            approved,
            authorized=self.authorized.isChecked(),
        )
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._set_progress, Qt.ConnectionType.QueuedConnection)
        self.worker.done.connect(self.finish, Qt.ConnectionType.QueuedConnection)
        self.worker.done.connect(self.worker_thread.quit)
        self.worker_thread.finished.connect(self.worker.deleteLater)
        self.worker_thread.finished.connect(self._thread_finished)
        self.worker_thread.start()

    def _set_progress(self, current, total, phase, resources_completed, resources_total):
        if self._progress_finished:
            return
        self._resource_current = max(self._resource_current, resources_completed)
        self._resource_total = resources_total
        self._work_completed = current
        self._work_total = total
        self.progress_state.setText(phase)
        if total <= 0:
            # The crawl may still add more same-origin resources. An
            # indeterminate bar is truthful until that moving workload settles.
            self.progress.setRange(0, 0)
            self.progress.setFormat("DISCOVERY IN PROGRESS")
            self.progress_counts.setText(f"RESOURCES: {self._resource_current} / DISCOVERING")
            self.work_counts.setText(f"WORK UNITS: {current} / DISCOVERING")
            return
        self.progress.setRange(0, 100)
        # 100 is reserved for the successful terminal signal in finish().
        percent = min(99, int((current * 100) / max(total, 1)))
        self.progress.setValue(max(self.progress.value(), percent))
        self.progress.setFormat(f"WORK COMPLETE  •  {self.progress.value()}%")
        self.progress_counts.setText(
            f"RESOURCES: {self._resource_current} / {self._resource_total or self._resource_current}"
        )
        self.work_counts.setText(f"WORK UNITS: {current} / {total}")

    def finish(self, report):
        if self._progress_finished:
            return
        self._progress_finished = True
        self.elapsed_timer.stop()
        self._update_elapsed()
        self.report = report
        self.table.setRowCount(len(report.endpoints))
        confirmed = sum(endpoint.status == Status.FINDING for endpoint in report.endpoints)
        self.metric_endpoints.setText(f"{len(report.endpoints):02d}")
        self.metric_confirmed.setText(f"{confirmed:02d}")
        self.scope_state.setText("ACTIVE / ALLOWLISTED" if report.mode == "Active validation" else "SAME-ORIGIN COMPLETE")
        for row, endpoint in enumerate(report.endpoints):
            values = (endpoint.service, redact_sensitive_url(endpoint.url), str(endpoint.status), endpoint.auth_evidence)
            self.table.setItem(row, 0, make_assessment_item(endpoint.status))
            for column, value in enumerate(values, start=1):
                self.table.setItem(row, column, QTableWidgetItem(value))
        self.details.setPlainText(
            "\n".join(report.errors) if report.errors else "Analysis complete. Select a signal for analyst details."
        )
        stopped = self.stop_event.is_set()
        failed = bool(report.errors) and not stopped
        if stopped:
            self.run_state.setText("STOPPED  /  PARTIAL RESULTS")
            self.progress_state.setText("SCAN CANCELLED")
            self.progress.setRange(0, 100)
            self.progress.setFormat("CANCELLED  •  PARTIAL RESULTS")
        elif failed:
            self.run_state.setText("FAILED  /  PARTIAL RESULTS")
            self.progress_state.setText("SCAN ERROR")
            self.progress.setRange(0, 100)
            self.progress.setFormat("FAILED  •  REVIEW ERRORS")
        else:
            self.run_state.setText("COMPLETE  /  RESULTS READY")
            self.progress_state.setText("SCAN COMPLETE")
            self.progress.setRange(0, 100)
            self.progress.setValue(100)
            self.progress.setFormat("COMPLETE  •  100%")
            self.progress_counts.setText(
                f"RESOURCES: {self._resource_current} / {self._resource_total or self._resource_current}"
            )
            self.work_counts.setText(f"WORK UNITS: {self._work_completed} / {self._work_total or self._work_completed}")
        self.stop_btn.setEnabled(False)
        self.status_indicator.setText("●  SYSTEM READY")
        self.status_indicator.setObjectName("statusReady")
        self.status_indicator.style().unpolish(self.status_indicator)
        self.status_indicator.style().polish(self.status_indicator)

    def _thread_finished(self):
        thread = self.sender()
        if thread is self.worker_thread:
            self.worker_thread = None
            self.worker = None
            self.scan_btn.setEnabled(True)
        if thread is not None:
            thread.deleteLater()
        if self._close_when_idle:
            self._close_when_idle = False
            QTimer.singleShot(0, self.close)

    def closeEvent(self, event):
        if self.worker_thread is not None and self.worker_thread.isRunning():
            self._close_when_idle = True
            self.stop_scan()
            event.ignore()
            return
        event.accept()

    def stop_scan(self):
        self.stop_event.set()
        self.stop_btn.setEnabled(False)
        self.run_state.setText("STOP REQUESTED  •  WAITING FOR CURRENT REQUEST")

    def show_details(self):
        if not self.report or self.table.currentRow() < 0:
            return
        endpoint = self.report.endpoints[self.table.currentRow()]
        lines = [
            f"SERVICE  {endpoint.service}",
            f"URL  {redact_sensitive_url(endpoint.url)}",
            f"STATUS  {endpoint.status}",
            f"AUTHENTICATION EVIDENCE  {endpoint.auth_evidence}",
            f"SOURCE  {redact_sensitive_url(endpoint.source)}",
            f"TIMESTAMP  {endpoint.timestamp}",
            "",
            "DISCOVERY EVIDENCE",
            *("  •  " + item for item in endpoint.evidence),
            "",
            "TEST CONDITIONS",
            endpoint.test_condition or "No active test was performed.",
            "",
            "LIMITATIONS",
            *("  •  " + item for item in endpoint.limitations),
            "",
            "REMEDIATION",
            endpoint.remediation,
        ]
        self.details.setPlainText("\n".join(lines))

    def export(self, file_type="json"):
        if not self.report:
            QMessageBox.information(self, "No report", "Run a scan first.")
            return
        if file_type == "html":
            path, _ = QFileDialog.getSaveFileName(
                self, "Export HTML report", "telemetry-report.html", "HTML (*.html)"
            )
        elif file_type == "jsonl":
            path, _ = QFileDialog.getSaveFileName(self, "Export JSONL report", "telemetry-report.jsonl", "JSONL (*.jsonl)")
        elif file_type == "har":
            path, _ = QFileDialog.getSaveFileName(self, "Export sanitized HAR", "telemetry-report.har", "HAR (*.har)")
        else:
            path, _ = QFileDialog.getSaveFileName(
                self, "Export JSON report", "telemetry-report.json", "JSON (*.json)"
            )
        if not path:
            return
        try:
            {"html": export_html, "jsonl": export_jsonl, "har": export_har}.get(file_type, export_json)(self.report, path)
            QMessageBox.information(self, "Report exported", f"Report saved to {path}")
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))


def main():
    app = QApplication([])
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    return app.exec()
