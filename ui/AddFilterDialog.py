import subprocess

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtWidgets import QVBoxLayout, QLabel, QMessageBox, QLineEdit, QDialog, QDialogButtonBox


# 校验BPF表达式
def check_bpf(filter_expression):
    command = ['windump', '-d', '-i', '1', filter_expression]

    try:
        # 运行 windump 并捕获输出
        subprocess.run(command, capture_output=True, text=True, check=True)
        return True  # 表达式语法合法
    except subprocess.CalledProcessError as e:
        # 检查错误信息是否包含“syntax error”
        if "syntax error" in e.stderr:
            return False  # 表达式语法错误
        else:
            print("Windump error:", e.stderr)
            return False


class AddFilterDialog(QDialog):
    def __init__(self, names, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add New Filter")
        self.setFixedWidth(600)

        self.setWindowIcon(QIcon("image/logo.png"))
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.names = names

        layout = QVBoxLayout(self)

        # 字体
        font = QFont()
        font.setFamily("Segoe UI")
        self.setFont(font)

        # 创建过滤器名称和表达式的输入框
        self.name_label = QLabel("Filter Name:")
        self.name_input = QLineEdit()

        self.filter_label = QLabel("BPF:")
        self.filter_input = QLineEdit()

        # 确认和取消按钮
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.check)
        self.button_box.rejected.connect(self.reject)

        # 布局
        layout.addWidget(self.name_label)
        layout.addWidget(self.name_input)
        layout.addWidget(self.filter_label)
        layout.addWidget(self.filter_input)
        layout.addWidget(self.button_box)

    def get_filter_data(self):
        # 返回输入的名称和表达式
        return self.name_input.text(), self.filter_input.text()

    def check(self):
        filter_expression = self.filter_input.text().strip()
        name = self.name_input.text().strip()
        if name not in self.names and check_bpf(filter_expression):
            self.accept()
        elif name not in self.names:
            QMessageBox.warning(self, "Invalid Expression", "BPF expression syntax is incorrect.")
        else:
            QMessageBox.warning(self, "Invalid Name", "Name already exists.")
