from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel, QComboBox, QTableWidget, QTableWidgetItem, \
    QHBoxLayout, QSizePolicy, QDialog

from ui.AddFilterDialog import AddFilterDialog


class FilterDialog(QDialog):
    def __init__(self, filters, selected_filter_index, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Capture Filters")

        self.filters = filters.copy()
        self.selected_filter_index = selected_filter_index

        self.resize(1440, 960)
        self.setWindowIcon(QIcon("image/logo.png"))
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)

        # 字体
        font = QFont()
        font.setFamily("Segoe UI")
        self.setFont(font)

        # 显示过滤器的表格
        self.filter_table = QTableWidget()
        self.filter_table.setColumnCount(2)
        self.filter_table.setHorizontalHeaderLabels(["Name", "Filter"])
        self.filter_table.horizontalHeader().setStretchLastSection(True)
        self.update_filter_table()

        # 添加、删除按钮
        self.add_button = QPushButton()
        self.add_button.setIcon(QIcon("image/add.png"))
        self.add_button.setToolTip("Add new filter")
        self.add_button.setFixedSize(QSize(50, 50))
        self.add_button.clicked.connect(self.add_filter)

        self.delete_button = QPushButton()
        self.delete_button.setIcon(QIcon("image/delete.png"))
        self.delete_button.setToolTip("Delete selected filter")
        self.add_button.setFixedSize(QSize(50, 50))
        self.delete_button.clicked.connect(self.delete_filter)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.add_button)
        button_layout.addWidget(self.delete_button)
        spacer = QWidget()  # 创建一个空的 QWidget
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)  # 让它占据空白空间
        button_layout.addWidget(spacer)

        # 选择过滤器的下拉框
        self.filter_label = QLabel("Select Capture Filter:")
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([""])
        self.filter_combo.addItems([f"{name}" for name, _ in self.filters])
        self.filter_combo.setCurrentIndex(self.selected_filter_index)
        self.filter_combo.setMinimumWidth(800)
        button_layout.addWidget(self.filter_label)
        button_layout.addWidget(self.filter_combo)

        # OK 和 Cancel 按钮
        self.ok_button = QPushButton("OK")
        self.ok_button.setFixedWidth(200)
        self.ok_button.clicked.connect(self.accept)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setFixedWidth(200)
        self.cancel_button.clicked.connect(self.reject)

        action_layout = QHBoxLayout()
        action_layout.addStretch()
        action_layout.addWidget(self.ok_button)
        action_layout.addWidget(self.cancel_button)

        layout.addWidget(self.filter_table)
        layout.addLayout(button_layout)
        layout.addLayout(action_layout)

    def get_filters(self):
        return self.filters

    def get_selected_filter_index(self):
        return self.selected_filter_index

    def update_filter_table(self):
        self.filter_table.setRowCount(len(self.filters))
        for i, (name, filt) in enumerate(self.filters):
            self.filter_table.setItem(i, 0, QTableWidgetItem(name))
            self.filter_table.setItem(i, 1, QTableWidgetItem(filt))

    def add_filter(self):
        # 弹出对话框，填写名称和表达式
        dialog = AddFilterDialog(set([name for name, _ in self.filters]), self)
        if dialog.exec_() == QDialog.Accepted:
            name, filt = dialog.get_filter_data()
            if name and filt:
                self.filters.append((name, filt))
                self.filter_combo.addItem(name)
                self.update_filter_table()

    def delete_filter(self):
        # 获取被选中的过滤器
        row = self.filter_table.currentRow()
        if row != -1:
            self.filters.pop(row)
            self.filter_combo.removeItem(row + 1)
            self.update_filter_table()

    def accept(self):
        self.selected_filter_index = self.filter_combo.currentIndex()
        super().accept()
