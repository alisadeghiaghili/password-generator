"""Modern GUI for Password Generator using PySide6."""

import sys
import threading
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal, QTimer, QPropertyAnimation
from PySide6.QtGui import QFont, QColor, QPalette, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QSlider,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from password_generator import (
    generate,
    generate_passphrase,
    generate_pin,
    analyze,
    copy_to_clipboard,
    check_breach,
    export_json,
    export_csv,
    export_keepass,
    PasswordEntry,
)

# ── Colors ────────────────────────────────────────────────────────────────────

COLORS = {
    "bg": "#1e1e2e",
    "sidebar": "#181825",
    "surface": "#313244",
    "text": "#cdd6f4",
    "subtext": "#a6adc8",
    "accent": "#89b4fa",
    "green": "#a6e3a1",
    "red": "#f38ba8",
    "yellow": "#f9e2af",
    "peach": "#fab387",
    "overlay": "#45475a",
}

LIGHT_COLORS = {
    "bg": "#ffffff",
    "sidebar": "#f0f0f5",
    "surface": "#e8e8ee",
    "text": "#1c1c1c",
    "subtext": "#6c6c7c",
    "accent": "#2962ff",
    "green": "#2e7d32",
    "red": "#c62828",
    "yellow": "#f57f17",
    "peach": "#e65100",
    "overlay": "#d0d0d8",
}


def get_colors(dark: bool = True) -> dict:
    return COLORS if dark else LIGHT_COLORS


# ── Breach Check Worker ───────────────────────────────────────────────────────


class BreachWorker(QThread):
    finished = Signal(object)

    def __init__(self, password: str):
        super().__init__()
        self.password = password

    def run(self):
        result = check_breach(self.password)
        self.finished.emit(result)


# ── Sidebar Button ────────────────────────────────────────────────────────────


class NavButton(QPushButton):
    def __init__(self, label: str, parent=None):
        super().__init__(label, parent)
        self.setFixedHeight(44)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet(
            """
            QPushButton {
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 14px;
                font-weight: 500;
                text-align: left;
            }
            QPushButton:hover {
                background-color: rgba(137, 180, 250, 0.15);
            }
            """
        )

    def set_active(self, active: bool, colors: dict):
        if active:
            self.setStyleSheet(
                f"""
                QPushButton {{
                    border: none;
                    border-radius: 8px;
                    padding: 8px 16px;
                    font-size: 14px;
                    font-weight: 600;
                    text-align: left;
                    background-color: {colors['accent']};
                    color: {colors['bg']};
                }}
                """
            )
        else:
            self.setStyleSheet(
                f"""
                QPushButton {{
                    border: none;
                    border-radius: 8px;
                    padding: 8px 16px;
                    font-size: 14px;
                    font-weight: 500;
                    text-align: left;
                    color: {colors['text']};
                }}
                QPushButton:hover {{
                    background-color: rgba(137, 180, 250, 0.15);
                }}
                """
            )


# ── Main Window ───────────────────────────────────────────────────────────────


class PasswordGeneratorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.dark_mode = True
        self.current_password = ""
        self.current_tab = 0
        self._setup_ui()
        self._apply_theme()
        self._switch_tab(0)

    def _setup_ui(self):
        self.setWindowTitle("Password Generator")
        self.setMinimumSize(900, 600)
        self.resize(950, 650)

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Sidebar
        self.sidebar = QFrame()
        self.sidebar.setFixedWidth(200)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(12, 16, 12, 16)
        sidebar_layout.setSpacing(4)

        # Title
        title = QLabel("Password\nGenerator")
        title.setFont(QFont("", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(title)
        sidebar_layout.addSpacing(20)

        # Nav buttons
        self.nav_buttons = []
        nav_items = [
            ("  Password", 0),
            ("  Passphrase", 1),
            ("  PIN", 2),
            ("  Strength", 3),
        ]
        for label, idx in nav_items:
            btn = NavButton(label)
            btn.clicked.connect(lambda checked, i=idx: self._switch_tab(i))
            sidebar_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        sidebar_layout.addStretch()

        # Theme toggle
        self.theme_btn = QPushButton("  Light Mode")
        self.theme_btn.setFixedHeight(36)
        self.theme_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_btn.clicked.connect(self._toggle_theme)
        sidebar_layout.addWidget(self.theme_btn)

        # Version
        ver = QLabel("v2.0.0")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver.setFont(QFont("", 10))
        sidebar_layout.addWidget(ver)

        main_layout.addWidget(self.sidebar)

        # Right side
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        # Stacked widget for tabs
        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_password_tab())
        self.stack.addWidget(self._build_passphrase_tab())
        self.stack.addWidget(self._build_pin_tab())
        self.stack.addWidget(self._build_strength_tab())
        right_layout.addWidget(self.stack, 1)

        # Bottom action bar
        right_layout.addWidget(self._build_action_bar())

        main_layout.addWidget(right, 1)

    # ── Tab Builders ──────────────────────────────────────────────────────

    def _build_password_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(32, 24, 32, 16)
        layout.setSpacing(12)

        # Length
        len_row = QHBoxLayout()
        len_row.addWidget(QLabel("Length"))
        self.pw_length_slider = QSlider(Qt.Orientation.Horizontal)
        self.pw_length_slider.setRange(4, 64)
        self.pw_length_slider.setValue(16)
        self.pw_length_slider.setTickPosition(QSlider.TickPosition.NoTicks)
        self.pw_length_slider.valueChanged.connect(self._on_pw_length_change)
        len_row.addWidget(self.pw_length_slider, 1)
        self.pw_length_spin = QSpinBox()
        self.pw_length_spin.setRange(4, 64)
        self.pw_length_spin.setValue(16)
        self.pw_length_spin.setFixedWidth(60)
        self.pw_length_spin.valueChanged.connect(self._on_pw_length_spin)
        len_row.addWidget(self.pw_length_spin)
        layout.addLayout(len_row)

        # Checkboxes
        checks = QHBoxLayout()
        self.pw_upper = QCheckBox("Uppercase (A-Z)")
        self.pw_upper.setChecked(True)
        self.pw_lower = QCheckBox("Lowercase (a-z)")
        self.pw_lower.setChecked(True)
        self.pw_digits = QCheckBox("Digits (0-9)")
        self.pw_digits.setChecked(True)
        self.pw_symbols = QCheckBox("Symbols (!@#)")
        self.pw_symbols.setChecked(True)
        self.pw_ambiguous = QCheckBox("No ambiguous")
        for cb in [self.pw_upper, self.pw_lower, self.pw_digits, self.pw_symbols, self.pw_ambiguous]:
            checks.addWidget(cb)
        checks.addStretch()
        layout.addLayout(checks)

        # Custom symbols
        sym_row = QHBoxLayout()
        sym_row.addWidget(QLabel("Custom symbols:"))
        self.pw_symbol_entry = QLineEdit("!@#$%^&*()_+-=[]{}|;:,.<>?")
        self.pw_symbol_entry.setPlaceholderText("Enter custom symbols...")
        sym_row.addWidget(self.pw_symbol_entry, 1)
        layout.addLayout(sym_row)

        # Output
        self.pw_output = QLineEdit()
        self.pw_output.setReadOnly(True)
        self.pw_output.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_output.setFont(QFont("Consolas", 16))
        self.pw_output.setMinimumHeight(48)
        self.pw_output.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.pw_output)

        # Eye toggle
        eye_row = QHBoxLayout()
        eye_row.addStretch()
        self.pw_eye_btn = QPushButton("Show")
        self.pw_eye_btn.setFixedWidth(60)
        self.pw_eye_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.pw_eye_btn.clicked.connect(self._toggle_pw_eye)
        eye_row.addWidget(self.pw_eye_btn)
        layout.addLayout(eye_row)

        # Strength bar
        self.pw_strength_bar = QProgressBar()
        self.pw_strength_bar.setRange(0, 100)
        self.pw_strength_bar.setValue(0)
        self.pw_strength_bar.setTextVisible(False)
        self.pw_strength_bar.setFixedHeight(8)
        layout.addWidget(self.pw_strength_bar)

        self.pw_entropy_label = QLabel("Entropy: -- bits")
        layout.addWidget(self.pw_entropy_label)

        layout.addStretch()
        return w

    def _build_passphrase_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(32, 24, 32, 16)
        layout.setSpacing(12)

        # Word count
        wc_row = QHBoxLayout()
        wc_row.addWidget(QLabel("Words"))
        self.pp_words_spin = QSpinBox()
        self.pp_words_spin.setRange(2, 10)
        self.pp_words_spin.setValue(4)
        wc_row.addWidget(self.pp_words_spin)
        wc_row.addSpacing(20)

        # Separator
        wc_row.addWidget(QLabel("Separator"))
        self.pp_separator = QComboBox()
        self.pp_separator.addItems(["Hyphen (-)", "Space ( )", "Dot (.)", "Underscore (_)", "Comma (,)"])
        self.pp_separator.setFixedWidth(140)
        wc_row.addWidget(self.pp_separator)
        wc_row.addSpacing(20)

        # Capitalize
        self.pp_capitalize = QCheckBox("Capitalize")
        wc_row.addWidget(self.pp_capitalize)
        wc_row.addStretch()
        layout.addLayout(wc_row)

        # Output
        self.pp_output = QLineEdit()
        self.pp_output.setReadOnly(True)
        self.pp_output.setFont(QFont("Consolas", 16))
        self.pp_output.setMinimumHeight(48)
        self.pp_output.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.pp_output)

        self.pp_entropy_label = QLabel("Entropy: -- bits")
        layout.addWidget(self.pp_entropy_label)

        layout.addStretch()
        return w

    def _build_pin_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(32, 24, 32, 16)
        layout.setSpacing(12)

        # Length
        len_row = QHBoxLayout()
        len_row.addWidget(QLabel("Length"))
        self.pin_length_spin = QSpinBox()
        self.pin_length_spin.setRange(4, 12)
        self.pin_length_spin.setValue(6)
        len_row.addWidget(self.pin_length_spin)
        len_row.addSpacing(20)

        self.pin_avoid_repeats = QCheckBox("Avoid repeats")
        self.pin_avoid_repeats.setChecked(True)
        len_row.addWidget(self.pin_avoid_repeats)
        len_row.addSpacing(10)

        self.pin_avoid_sequential = QCheckBox("Avoid sequential")
        self.pin_avoid_sequential.setChecked(True)
        len_row.addWidget(self.pin_avoid_sequential)
        len_row.addStretch()
        layout.addLayout(len_row)

        # Output
        self.pin_output = QLineEdit()
        self.pin_output.setReadOnly(True)
        self.pin_output.setFont(QFont("Consolas", 28))
        self.pin_output.setMinimumHeight(64)
        self.pin_output.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.pin_output)

        layout.addStretch()
        return w

    def _build_strength_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(32, 24, 32, 16)
        layout.setSpacing(12)

        # Input
        input_row = QHBoxLayout()
        self.strength_input = QLineEdit()
        self.strength_input.setPlaceholderText("Enter a password to analyze...")
        self.strength_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.strength_input.setFont(QFont("Consolas", 14))
        self.strength_input.setMinimumHeight(40)
        self.strength_input.returnPressed.connect(self._run_strength_analysis)
        input_row.addWidget(self.strength_input, 1)

        self.strength_eye_btn = QPushButton("Show")
        self.strength_eye_btn.setFixedWidth(60)
        self.strength_eye_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.strength_eye_btn.clicked.connect(self._toggle_strength_eye)
        input_row.addWidget(self.strength_eye_btn)

        analyze_btn = QPushButton("Analyze")
        analyze_btn.setFixedWidth(100)
        analyze_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        analyze_btn.clicked.connect(self._run_strength_analysis)
        input_row.addWidget(analyze_btn)
        layout.addLayout(input_row)

        # Score bar
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setFixedHeight(12)
        layout.addWidget(self.strength_bar)

        self.strength_score_label = QLabel("")
        self.strength_score_label.setFont(QFont("", 14, QFont.Weight.Bold))
        layout.addWidget(self.strength_score_label)

        self.strength_entropy_label = QLabel("Entropy: -- bits")
        layout.addWidget(self.strength_entropy_label)

        # Crack times table
        layout.addWidget(QLabel("Crack Time Estimates:"))
        self.crack_table = QTableWidget(4, 2)
        self.crack_table.setHorizontalHeaderLabels(["Scenario", "Time"])
        self.crack_table.horizontalHeader().setStretchLastSection(True)
        self.crack_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.crack_table.verticalHeader().setVisible(False)
        self.crack_table.setShowGrid(False)
        self.crack_table.setMinimumHeight(120)
        layout.addWidget(self.crack_table)

        # Patterns & Feedback
        bottom_row = QHBoxLayout()

        pattern_col = QVBoxLayout()
        pattern_col.addWidget(QLabel("Detected Patterns:"))
        self.pattern_list = QListWidget()
        self.pattern_list.setMaximumHeight(100)
        pattern_col.addWidget(self.pattern_list)
        bottom_row.addLayout(pattern_col, 1)

        feedback_col = QVBoxLayout()
        feedback_col.addWidget(QLabel("Suggestions:"))
        self.feedback_list = QListWidget()
        self.feedback_list.setMaximumHeight(100)
        feedback_col.addWidget(self.feedback_list)
        bottom_row.addLayout(feedback_col, 1)

        layout.addLayout(bottom_row)
        layout.addStretch()
        return w

    # ── Action Bar ────────────────────────────────────────────────────────

    def _build_action_bar(self) -> QWidget:
        bar = QFrame()
        bar.setFixedHeight(64)
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(32, 8, 32, 8)

        self.generate_btn = QPushButton("Generate")
        self.generate_btn.setFixedHeight(44)
        self.generate_btn.setFixedWidth(120)
        self.generate_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.generate_btn.clicked.connect(self._generate)
        bar_layout.addWidget(self.generate_btn)

        self.copy_btn = QPushButton("Copy")
        self.copy_btn.setFixedHeight(44)
        self.copy_btn.setFixedWidth(80)
        self.copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.copy_btn.clicked.connect(self._copy)
        bar_layout.addWidget(self.copy_btn)

        self.breach_btn = QPushButton("Check Breach")
        self.breach_btn.setFixedHeight(44)
        self.breach_btn.setFixedWidth(130)
        self.breach_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.breach_btn.clicked.connect(self._check_breach)
        bar_layout.addWidget(self.breach_btn)

        bar_layout.addStretch()

        # Export button
        self.export_btn = QPushButton("Export")
        self.export_btn.setFixedHeight(44)
        self.export_btn.setFixedWidth(100)
        self.export_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.export_btn.clicked.connect(self._export)
        bar_layout.addWidget(self.export_btn)

        # Copy status
        self.copy_status = QLabel("")
        self.copy_status.setFont(QFont("", 10))
        bar_layout.addWidget(self.copy_status)

        return bar

    # ── Tab Switching ─────────────────────────────────────────────────────

    def _switch_tab(self, idx: int):
        self.current_tab = idx
        self.stack.setCurrentIndex(idx)
        for i, btn in enumerate(self.nav_buttons):
            btn.set_active(i == idx, get_colors(self.dark_mode))

    # ── Theme ─────────────────────────────────────────────────────────────

    def _toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self._apply_theme()

    def _apply_theme(self):
        c = get_colors(self.dark_mode)
        self.theme_btn.setText("  Light Mode" if self.dark_mode else "  Dark Mode")

        # Main
        self.setStyleSheet(f"""
            QMainWindow {{ background-color: {c['bg']}; }}
            QWidget {{ color: {c['text']}; }}
            QFrame {{ background-color: {c['sidebar']}; border: none; }}
        """)

        # Sidebar
        self.sidebar.setStyleSheet(f"""
            QFrame {{
                background-color: {c['sidebar']};
                border-right: 1px solid {c['overlay']};
            }}
        """)

        # Theme button
        self.theme_btn.setStyleSheet(f"""
            QPushButton {{
                border: 1px solid {c['overlay']};
                border-radius: 8px;
                padding: 6px 12px;
                color: {c['text']};
                background: transparent;
            }}
            QPushButton:hover {{
                background-color: {c['surface']};
            }}
        """)

        # Inputs
        input_style = f"""
            QLineEdit, QSpinBox, QComboBox {{
                background-color: {c['surface']};
                border: 1px solid {c['overlay']};
                border-radius: 8px;
                padding: 8px 12px;
                color: {c['text']};
                font-size: 14px;
            }}
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
                border: 1px solid {c['accent']};
            }}
            QComboBox::drop-down {{
                border: none;
                padding-right: 8px;
            }}
            QComboBox QAbstractItemView {{
                background-color: {c['surface']};
                color: {c['text']};
                border: 1px solid {c['overlay']};
                selection-background-color: {c['accent']};
            }}
        """
        self.setStyleSheet(self.styleSheet() + input_style)

        # Output fields
        for field in [self.pw_output, self.pp_output, self.pin_output, self.strength_input]:
            field.setStyleSheet(f"""
                QLineEdit {{
                    background-color: {c['surface']};
                    border: 2px solid {c['overlay']};
                    border-radius: 10px;
                    padding: 10px;
                    color: {c['text']};
                }}
            """)

        # Buttons
        btn_base = """
            QPushButton {
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 14px;
                font-weight: 600;
            }
        """
        self.generate_btn.setStyleSheet(
            btn_base
            + f"QPushButton {{ background-color: {c['green']}; color: {c['bg']}; }}"
            + f"QPushButton:hover {{ background-color: {c['accent']}; }}"
        )
        self.copy_btn.setStyleSheet(
            btn_base
            + f"QPushButton {{ background-color: {c['surface']}; color: {c['text']}; border: 1px solid {c['overlay']}; }}"
            + f"QPushButton:hover {{ background-color: {c['overlay']}; }}"
        )
        self.breach_btn.setStyleSheet(
            btn_base
            + f"QPushButton {{ background-color: {c['surface']}; color: {c['text']}; border: 1px solid {c['overlay']}; }}"
            + f"QPushButton:hover {{ background-color: {c['overlay']}; }}"
        )
        self.export_btn.setStyleSheet(
            btn_base
            + f"QPushButton {{ background-color: {c['surface']}; color: {c['text']}; border: 1px solid {c['overlay']}; }}"
            + f"QPushButton:hover {{ background-color: {c['overlay']}; }}"
        )

        # Eye buttons
        for eye in [self.pw_eye_btn, self.strength_eye_btn]:
            eye.setStyleSheet(
                btn_base
                + f"QPushButton {{ background-color: {c['surface']}; color: {c['text']}; border: 1px solid {c['overlay']}; }}"
                + f"QPushButton:hover {{ background-color: {c['overlay']}; }}"
            )

        # Progress bars
        for bar in [self.pw_strength_bar, self.strength_bar]:
            bar.setStyleSheet(f"""
                QProgressBar {{
                    background-color: {c['surface']};
                    border: none;
                    border-radius: 4px;
                }}
                QProgressBar::chunk {{
                    border-radius: 4px;
                    background-color: {c['accent']};
                }}
            """)

        # Checkboxes & Labels
        self.setStyleSheet(self.styleSheet() + f"""
            QCheckBox {{
                color: {c['text']};
                spacing: 6px;
                font-size: 13px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 2px solid {c['overlay']};
                background: {c['surface']};
            }}
            QCheckBox::indicator:checked {{
                background-color: {c['accent']};
                border-color: {c['accent']};
            }}
            QLabel {{
                color: {c['text']};
                font-size: 13px;
            }}
            QTableWidget {{
                background-color: {c['surface']};
                border: 1px solid {c['overlay']};
                border-radius: 8px;
                gridline-color: {c['overlay']};
                color: {c['text']};
                font-size: 13px;
            }}
            QTableWidget::item {{
                padding: 6px 12px;
            }}
            QHeaderView::section {{
                background-color: {c['sidebar']};
                color: {c['text']};
                border: none;
                padding: 8px 12px;
                font-weight: bold;
            }}
            QListWidget {{
                background-color: {c['surface']};
                border: 1px solid {c['overlay']};
                border-radius: 8px;
                padding: 4px;
                color: {c['text']};
                font-size: 13px;
            }}
            QListWidget::item {{
                padding: 4px 8px;
                border-radius: 4px;
            }}
            QListWidget::item:selected {{
                background-color: {c['accent']};
                color: {c['bg']};
            }}
            QSlider::groove:horizontal {{
                height: 6px;
                background: {c['overlay']};
                border-radius: 3px;
            }}
            QSlider::handle:horizontal {{
                background: {c['accent']};
                width: 18px;
                height: 18px;
                margin: -6px 0;
                border-radius: 9px;
            }}
            QSpinBox {{
                background-color: {c['surface']};
                border: 1px solid {c['overlay']};
                border-radius: 6px;
                padding: 4px 8px;
                color: {c['text']};
            }}
        """)

    # ── Password Tab Logic ────────────────────────────────────────────────

    def _on_pw_length_change(self, val):
        self.pw_length_spin.setValue(val)

    def _on_pw_length_spin(self, val):
        self.pw_length_slider.setValue(val)

    def _toggle_pw_eye(self):
        if self.pw_output.echoMode() == QLineEdit.EchoMode.Password:
            self.pw_output.setEchoMode(QLineEdit.EchoMode.Normal)
            self.pw_eye_btn.setText("Hide")
        else:
            self.pw_output.setEchoMode(QLineEdit.EchoMode.Password)
            self.pw_eye_btn.setText("Show")

    def _toggle_strength_eye(self):
        if self.strength_input.echoMode() == QLineEdit.EchoMode.Password:
            self.strength_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.strength_eye_btn.setText("Hide")
        else:
            self.strength_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.strength_eye_btn.setText("Show")

    def _generate_password(self) -> str:
        symbols_text = self.pw_symbol_entry.text() or "!@#$%^&*()_+-=[]{}|;:,.<>?"
        pwd = generate(
            length=self.pw_length_slider.value(),
            uppercase=self.pw_upper.isChecked(),
            lowercase=self.pw_lower.isChecked(),
            digits=self.pw_digits.isChecked(),
            symbols=self.pw_symbols.isChecked(),
            symbol_chars=symbols_text,
            exclude_ambiguous=self.pw_ambiguous.isChecked(),
        )
        self.pw_output.setText(pwd)
        self.current_password = pwd

        # Update strength
        report = analyze(pwd)
        score_pct = (report.score / 4) * 100
        self.pw_strength_bar.setValue(int(score_pct))
        self._color_strength_bar(self.pw_strength_bar, report.score)
        self.pw_entropy_label.setText(f"Entropy: {report.entropy:.0f} bits")
        return pwd

    def _generate_passphrase(self) -> str:
        sep_map = {"Hyphen (-)": "-", "Space ( )": " ", "Dot (.)": ".", "Underscore (_)": "_", "Comma (,)": ","}
        sep = sep_map.get(self.pp_separator.currentText(), "-")
        phrase = generate_passphrase(
            words=self.pp_words_spin.value(),
            separator=sep,
            capitalize=self.pp_capitalize.isChecked(),
        )
        self.pp_output.setText(phrase)
        self.current_password = phrase

        from password_generator.passphrase import passphrase_entropy
        ent = passphrase_entropy(self.pp_words_spin.value())
        self.pp_entropy_label.setText(f"Entropy: {ent} bits")
        return phrase

    def _generate_pin(self) -> str:
        pin = generate_pin(
            length=self.pin_length_spin.value(),
            avoid_repeats=self.pin_avoid_repeats.isChecked(),
            avoid_sequential=self.pin_avoid_sequential.isChecked(),
        )
        self.pin_output.setText(pin)
        self.current_password = pin
        return pin

    def _generate(self):
        tab = self.current_tab
        if tab == 0:
            self._generate_password()
        elif tab == 1:
            self._generate_passphrase()
        elif tab == 2:
            self._generate_pin()
        elif tab == 3:
            self._run_strength_analysis()

    def _copy(self):
        if self.current_password:
            copy_to_clipboard(self.current_password)
            self.copy_status.setText("Copied!")
            QTimer.singleShot(2000, lambda: self.copy_status.setText(""))

    def _check_breach(self):
        if not self.current_password:
            return
        self.breach_btn.setEnabled(False)
        self.breach_btn.setText("Checking...")

        self._breach_worker = BreachWorker(self.current_password)
        self._breach_worker.finished.connect(self._on_breach_result)
        self._breach_worker.start()

    def _on_breach_result(self, result):
        self.breach_btn.setEnabled(True)
        self.breach_btn.setText("Check Breach")

        if result.is_breached:
            QMessageBox.warning(
                self,
                "Breach Found",
                f"This password has been found {result.count:,} times in data breaches!\n\n"
                "You should NOT use this password.",
            )
        else:
            QMessageBox.information(
                self,
                "Not Breached",
                "This password was not found in known data breaches.",
            )

    def _export(self):
        if not self.current_password:
            QMessageBox.information(self, "Nothing to export", "Generate a password first.")
            return

        menu_text, ok = QFileDialog.getSaveFileName(
            self,
            "Export Password",
            "",
            "JSON Files (*.json);;CSV Files (*.csv);;KeePass XML (*.xml);;All Files (*)",
        )
        if not ok or not menu_text:
            return

        entry = PasswordEntry(
            title="Generated Password",
            username="",
            password=self.current_password,
        )

        path = Path(menu_text)
        if path.suffix == ".csv":
            content = export_csv([entry])
        elif path.suffix == ".xml":
            content = export_keepass([entry])
        else:
            content = export_json([entry])
            if not path.suffix:
                path = path.with_suffix(".json")

        path.write_text(content, encoding="utf-8")
        QMessageBox.information(self, "Exported", f"Saved to {path}")

    def _run_strength_analysis(self):
        pwd = self.strength_input.text()
        if not pwd:
            return

        report = analyze(pwd)

        # Score bar
        score_pct = (report.score / 4) * 100
        self.strength_bar.setValue(int(score_pct))
        self._color_strength_bar(self.strength_bar, report.score)

        # Score label
        score_labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
        score_colors = [COLORS["red"], COLORS["peach"], COLORS["yellow"], COLORS["green"], COLORS["green"]]
        self.strength_score_label.setText(score_labels[report.score])
        self.strength_score_label.setStyleSheet(f"color: {score_colors[report.score]}; font-weight: bold; font-size: 16px;")

        # Entropy
        self.strength_entropy_label.setText(f"Entropy: {report.entropy:.0f} bits")

        # Crack times table
        scenario_labels = {
            "online_throttled_100_per_hour": "Online (100/hr)",
            "online_no_throttling_10_per_second": "Online (10/sec)",
            "offline_slow_hashing_1e4_per_second": "Offline (10K/sec)",
            "offline_fast_hashing_1e10_per_second": "Offline (10B/sec)",
        }
        self.crack_table.setRowCount(4)
        for i, (key, label) in enumerate(scenario_labels.items()):
            time_str = report.crack_times.get(key, "--")
            self.crack_table.setItem(i, 0, QTableWidgetItem(label))
            self.crack_table.setItem(i, 1, QTableWidgetItem(time_str))

        # Patterns
        self.pattern_list.clear()
        if report.patterns:
            for p in report.patterns:
                self.pattern_list.addItem(f"  {p.replace('_', ' ').title()}")
        else:
            self.pattern_list.addItem("  None detected")

        # Feedback
        self.feedback_list.clear()
        for f in report.feedback:
            self.feedback_list.addItem(f"  {f}")

    def _color_strength_bar(self, bar: QProgressBar, score: int):
        c = get_colors(self.dark_mode)
        score_colors = {0: COLORS["red"], 1: COLORS["peach"], 2: COLORS["yellow"], 3: COLORS["green"], 4: COLORS["green"]}
        bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {c['surface']};
                border: none;
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                border-radius: 4px;
                background-color: {score_colors[score]};
            }}
        """)


# ── Entry Point ───────────────────────────────────────────────────────────────


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = PasswordGeneratorGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
