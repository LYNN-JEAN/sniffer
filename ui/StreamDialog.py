from PyQt5.QtCore import Qt
from PyQt5.QtGui import QTextCharFormat, QColor, QTextCursor, QFont
from PyQt5.QtWidgets import QVBoxLayout, QTextEdit, QLabel, QDialog, QWidget, QScrollArea, QSizePolicy
from scapy.layers.inet import TCP
from scapy.utils import hexdump


class StreamDialog(QDialog):
    def __init__(self, stream_id, packets, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"TCP Stream {stream_id}")
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.resize(1440, 960)

        font = QFont()
        font.setFamily("Segoe UI")
        self.setFont(font)

        # 创建滚动区域
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)

        # 创建一个容器窗口作为滚动区域的内容
        container = QWidget()
        scroll_area.setWidget(container)

        # 垂直布局，用于容纳所有QLabel
        layout = QVBoxLayout(container)

        # 遍历数据包，将每个数据包的 hexdump 内容放入单独的 QLabel
        st_src = packets[0]["src"]
        st_sport = packets[0]["packet"][TCP].sport
        for packet in packets:
            hex_text = hexdump(packet["packet"], dump=True)

            if packet["src"] == st_src and packet["packet"][TCP].sport == st_sport:
                bk_color = "#fbeded"
                color = "#9b3636"
            else:
                bk_color = "#ededfb"
                color = "#36369b"

            # 创建 QLabel 并设置背景颜色
            label = QLabel(hex_text)
            label.setStyleSheet(f"background-color: {bk_color}; color: {color}; padding: 8px;")
            label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            label.setFont(QFont("Consolas"))

            layout.addWidget(label, alignment=Qt.AlignTop)

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(scroll_area)
        self.setLayout(main_layout)
