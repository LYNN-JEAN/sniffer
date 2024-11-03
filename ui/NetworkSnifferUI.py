import psutil
from PyQt5 import QtWidgets
from PyQt5.QtCore import QSize, Qt, QTimer
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QComboBox, QMessageBox, \
    QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView, QHBoxLayout, QTreeWidget, QTreeWidgetItem, QSizePolicy, \
    QListView, QLineEdit, QDialog, QMenu
from scapy.all import sniff
from scapy.utils import hexdump, wrpcap

from core.PacketSnifferThread import PacketSnifferThread, filter2bpf
from ui.FilterDialog import FilterDialog
from ui.StreamDialog import StreamDialog


class NetworkSnifferUI(QWidget):
    def __init__(self):
        super().__init__()

        self.resize(1800, 1200)
        self.setWindowIcon(QIcon("image/logo.png"))

        # 嗅探线程
        self.sniffer_thread = None
        self.packet_data = []  # 存储捕获的包信息
        self.file_saved = False  # 是否已保存文件
        self.is_paused = False  # 是否暂停

        self.selected_row = None  # 被单击的行
        self.selected_filter_index = 0  # 捕获过滤器
        self.filters = self.load_filters()

        self.setWindowTitle("Sniffer")

        # 字体
        font = QFont()
        font.setFamily("Segoe UI")
        self.setFont(font)

        # 网络适配器选择
        self.interface_label = QLabel("Select Network Adapter:")
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(800)
        self.interface_combo.setFixedHeight(50)
        self.interface_combo.setStyleSheet("QAbstractItemView::item {height: 50px;}")
        self.interface_combo.setView(QListView())
        self.interface_combo.setFont(font)

        # 获取所有网络适配器
        self.interfaces = self.get_network_adapters()
        if self.interfaces:
            self.interface_combo.addItems(self.interfaces)

        # 嗅探器控制按钮
        self.start_button = QPushButton()
        self.start_button.setIcon(QIcon("image/start.png"))
        self.start_button.setToolTip("Start Sniffing")
        self.start_button.clicked.connect(self.start_sniffing)

        self.pause_button = QPushButton()
        self.pause_button.setIcon(QIcon("image/pause.png"))
        self.pause_button.setToolTip("Pause Sniffing")
        self.pause_button.clicked.connect(self.pause_sniffing)
        self.pause_button.setEnabled(False)

        self.refresh_button = QPushButton()
        self.refresh_button.setIcon(QIcon("image/refresh.png"))
        self.refresh_button.setToolTip("Refresh")
        self.refresh_button.clicked.connect(self.refresh)
        self.refresh_button.setEnabled(False)

        self.stop_button = QPushButton()
        self.stop_button.setIcon(QIcon("image/stop.png"))
        self.stop_button.setToolTip("Stop Sniffing")
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)

        self.save_button = QPushButton()
        self.save_button.setIcon(QIcon("image/save.png"))
        self.save_button.setToolTip("Save Capture")
        self.save_button.clicked.connect(self.save_capture)
        self.save_button.setEnabled(False)

        # 设置按钮大小
        button_size = QSize(60, 60)
        self.start_button.setFixedSize(button_size)
        self.pause_button.setFixedSize(button_size)
        self.stop_button.setFixedSize(button_size)
        self.refresh_button.setFixedSize(button_size)
        self.save_button.setFixedSize(button_size)

        # BPF捕获过滤器
        self.filter_before_button = QPushButton()
        self.filter_before_button.setText("Capture Filter")
        self.filter_before_button.setFixedHeight(50)
        self.filter_before_button.clicked.connect(self.show_filter_dialog)

        # 布局：按钮与网络适配器选择框在同一行
        top_layout = QHBoxLayout()

        # 按钮布局
        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self.start_button)
        buttons_layout.addWidget(self.pause_button)
        buttons_layout.addWidget(self.stop_button)
        buttons_layout.addWidget(self.refresh_button)
        buttons_layout.addWidget(self.save_button)

        top_layout.addLayout(buttons_layout)
        spacer = QWidget()  # 创建一个空的 QWidget
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)  # 让它占据空白空间
        top_layout.addWidget(spacer)
        top_layout.addWidget(self.interface_label)
        top_layout.addWidget(self.interface_combo)
        top_layout.addWidget(self.filter_before_button)

        # BPF显示过滤器
        filter_after_layout = QHBoxLayout()
        self.filter_after_text = QLineEdit()
        self.filter_after_text.setDisabled(True)
        self.filter_after_text.setFixedHeight(50)
        self.filter_after_text.returnPressed.connect(self.filter_after)  # 绑定回车事件

        self.filter_after_button = QPushButton()
        self.filter_after_button.setText("Display Filter")
        self.filter_after_button.setFixedHeight(50)
        self.filter_after_button.setEnabled(False)
        self.filter_after_button.clicked.connect(self.filter_after)
        filter_after_layout.addWidget(self.filter_after_text)
        filter_after_layout.addWidget(self.filter_after_button)

        # 捕获数据包表格
        self.packet_table = QTableWidget(0, 7)
        self.packet_table.setHorizontalHeaderLabels(["NO.", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.packet_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # 设置选择行为为整行
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.setMouseTracking(True)
        self.packet_table.setStyleSheet("""
            QTableWidget::item:hover {
                background-color: #d9ebf9;  /* 悬停时行高亮的颜色 */
            }
            QTableWidget::item:selected {
                background-color: #66cc66;  /* 选中时行高亮的颜色 */
            }
        """)

        # 绑定表格单击事件
        self.packet_table.cellClicked.connect(lambda row, col: self.show_packet_details(row))
        self.packet_table.currentCellChanged.connect(lambda row, col: self.show_packet_details(row))
        # 绑定表格右键菜单
        self.packet_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.packet_table.customContextMenuRequested.connect(self.show_context_menu)

        # 捕获数据包的详细内容
        self.packet_tree = QTreeWidget(self)
        self.packet_tree.setColumnCount(1)
        self.packet_tree.setHeaderHidden(True)

        self.packet_details = QTextEdit(self)
        self.packet_details.setReadOnly(True)
        self.packet_details.setFont(QFont("Consolas", 10))

        # 主布局
        layout = QVBoxLayout()
        layout.addLayout(top_layout)
        layout.addLayout(filter_after_layout)
        layout.addWidget(self.packet_table)
        layout.addWidget(self.packet_tree)
        layout.addWidget(self.packet_details)

        # 校验和显示
        self.check_label = QLabel(self)
        self.check_label.setAlignment(Qt.AlignCenter)
        self.check_label.setStyleSheet("color: rgba(0, 0, 0, 1.0);")
        self.check_label.setVisible(False)  # 初始化为不可见
        layout.addWidget(self.check_label)

        self.opacity = 1.0  # 初始透明度
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.fade_out)  # 连接到淡出效果

        self.setLayout(layout)

    # 获取所有网络接口的名称
    def get_network_adapters(self):
        adapters = psutil.net_if_stats()
        return [adapter for adapter in adapters]

    def start_sniffing(self):
        if not self.is_paused:  # 新的开始
            # 检查是否需要保存
            if self.packet_data and not self.file_saved:
                reply = QMessageBox.question(self, "Save Capture", "Do you want to save the captured packets?",
                                             QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
                if reply == QMessageBox.Yes:
                    self.save_capture()
                elif reply == QMessageBox.Cancel:
                    return

            # 清空之前的捕获内容
            self.packet_data.clear()
            self.packet_table.currentCellChanged.disconnect()
            self.packet_table.setRowCount(0)
            self.packet_table.currentCellChanged.connect(lambda row, col: self.show_packet_details(row))
            self.packet_tree.clear()
            self.packet_details.clear()
            self.file_saved = False

            selected = self.interface_combo.currentText()
            if selected:
                # 启动嗅探线程
                self.sniffer_thread = PacketSnifferThread(selected, self.filters[self.selected_filter_index-1][
                    1] if self.selected_filter_index else "")
                self.sniffer_thread.packet_captured.connect(self.display_packet)
                self.sniffer_thread.start()

                # 按钮状态
                self.start_button.setEnabled(False)
                self.pause_button.setEnabled(True)
                self.stop_button.setEnabled(True)
                self.save_button.setEnabled(False)
        else:  # 暂停后继续
            if self.sniffer_thread:
                self.sniffer_thread.resume_sniffing()  # 恢复嗅探
                self.pause_button.setEnabled(True)
                self.start_button.setEnabled(False)
            self.is_paused = False
        self.refresh_button.setEnabled(False)
        self.interface_combo.setEnabled(False)
        self.filter_before_button.setEnabled(False)
        self.filter_after_button.setEnabled(False)
        self.filter_after_text.setDisabled(True)

    def pause_sniffing(self):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.pause_sniffing()  # 暂停嗅探

            # 启用“继续”按钮，并禁用“暂停”按钮
            self.start_button.setIcon(QIcon("image/continue.png"))
            self.start_button.setToolTip("Continue Sniffing")
            self.start_button.setEnabled(True)
            self.pause_button.setEnabled(False)
            self.refresh_button.setEnabled(True)
            self.is_paused = True

    def stop_sniffing(self):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.pause_sniffing()
            self.sniffer_thread = None
            self.stop_button.setEnabled(False)
            self.start_button.setIcon(QIcon("image/start.png"))
            self.start_button.setToolTip("Start Sniffing")
            self.start_button.setEnabled(True)
            self.pause_button.setEnabled(False)
            self.save_button.setEnabled(True)
            self.interface_combo.setEnabled(True)
            self.refresh_button.setEnabled(True)
            self.filter_after_button.setEnabled(True)
            self.filter_after_text.setDisabled(False)
            self.filter_before_button.setEnabled(True)

    # 保存捕获内容
    def save_capture(self):
        if self.packet_data:
            options = QFileDialog.Options()
            filename, _ = QFileDialog.getSaveFileName(self, "Save Packet Capture", "", "PCAP Files (*.pcap)",
                                                      options=options)
            if filename:
                wrpcap(filename, [packet["packet"] for packet in self.packet_data])
                self.file_saved = True

    def refresh(self):
        self.packet_data.clear()
        self.packet_table.currentCellChanged.disconnect()
        self.packet_table.setRowCount(0)
        self.packet_table.currentCellChanged.connect(lambda row, col: self.show_packet_details(row))
        self.packet_tree.clear()
        self.packet_details.clear()

    def display_packet(self, packet_info):
        self.packet_data.append(packet_info)
        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)

        self.packet_table.setItem(row_position, 0, QTableWidgetItem(str(row_position + 1)))  # NO.
        self.packet_table.setItem(row_position, 1, QTableWidgetItem(packet_info.get("time", "Unknown")))  # Time
        self.packet_table.setItem(row_position, 2,
                                  QTableWidgetItem(packet_info.get("src", "Unknown")))  # Source
        self.packet_table.setItem(row_position, 3,
                                  QTableWidgetItem(packet_info.get("dst", "Unknown")))  # Destination
        self.packet_table.setItem(row_position, 4, QTableWidgetItem(packet_info.get("proto", "Unknown")))  # Protocol
        self.packet_table.setItem(row_position, 5, QTableWidgetItem(packet_info.get("len", "Unknown")))  # Length
        self.packet_table.setItem(row_position, 6, QTableWidgetItem(packet_info.get("info", "Unknown")))  # Info
        self.packet_table.resizeColumnsToContents()

    def show_packet_details(self, row):
        packet = self.packet_data[row]["packet"]
        lines = (packet.show(dump=True)).split('\n')
        last_tree_entry = None
        self.packet_tree.clear()
        for line in lines:
            if line.startswith('#'):
                line = line.strip('# ')
                last_tree_entry = QTreeWidgetItem(self.packet_tree)
                last_tree_entry.setText(0, line)
            else:
                if last_tree_entry:
                    child_item = QTreeWidgetItem(last_tree_entry)
                    child_item.setText(0, line.strip())

        self.packet_details.setText(hexdump(packet, dump=True))

        # 校验和信息
        if self.packet_data[row]["check"] is not None:
            self.check_label.setText(self.packet_data[row]["check"])
            self.opacity = 1.0  # 重置透明度
            self.check_label.setStyleSheet(f"color: rgba(0, 0, 0, {self.opacity});")  # 设置初始透明度
            self.check_label.setVisible(True)

        self.timer.start(15)  # 15秒后消失

    def filter_after(self):
        if not self.packet_data:
            return
        filter_expression = self.filter_after_text.text().strip()  # 获取用户输入的显示过滤器
        if filter_expression == "":
            self.packet_table.currentCellChanged.disconnect()
            self.packet_table.setRowCount(0)
            self.packet_table.currentCellChanged.connect(lambda row, col: self.show_packet_details(row))
            for i, packet_info in enumerate(self.packet_data):
                self.packet_table.insertRow(i)
                self.packet_table.setItem(i, 0, QTableWidgetItem(str(i+1)))  # NO.
                self.packet_table.setItem(i, 1, QTableWidgetItem(packet_info.get("time", "Unknown")))  # Time
                self.packet_table.setItem(i, 2, QTableWidgetItem(packet_info.get("src", "Unknown")))  # Source
                self.packet_table.setItem(i, 3, QTableWidgetItem(packet_info.get("dst", "Unknown")))  # Destination
                self.packet_table.setItem(i, 4, QTableWidgetItem(packet_info.get("proto", "Unknown")))  # Protocol
                self.packet_table.setItem(i, 5, QTableWidgetItem(packet_info.get("len", "Unknown")))  # Length
                self.packet_table.setItem(i, 6, QTableWidgetItem(packet_info.get("info", "Unknown")))  # Info
            self.packet_table.cellClicked.connect(lambda row, col: self.show_packet_details(row))
            self.packet_table.currentCellChanged.connect(lambda row, col: self.show_packet_details(row))
            return
        if filter_expression:
            try:
                mp = dict()
                # 应用过滤器
                row_position = 0
                packets = sniff(offline=[packet["packet"] for packet in self.packet_data], filter=filter2bpf(filter_expression))
                # 清空当前表格内容
                self.packet_table.currentCellChanged.disconnect()
                self.packet_table.setRowCount(0)
                self.packet_table.currentCellChanged.connect(lambda row, col: self.show_packet_details(row))
                j = 0
                for i, packet_info in enumerate(self.packet_data):
                    if j >= len(packets):
                        break
                    # 检查数据包是否满足过滤器条件
                    if packet_info["packet"] == packets[j]:
                        # 如果满足条件，显示数据包
                        self.packet_table.insertRow(row_position)
                        self.packet_table.setItem(row_position, 0, QTableWidgetItem(str(i+1)))  # NO.
                        self.packet_table.setItem(row_position, 1,
                                                  QTableWidgetItem(packet_info.get("time", "Unknown")))  # Time
                        self.packet_table.setItem(row_position, 2,
                                                  QTableWidgetItem(packet_info.get("src", "Unknown")))  # Source
                        self.packet_table.setItem(row_position, 3,
                                                  QTableWidgetItem(packet_info.get("dst", "Unknown")))  # Destination
                        self.packet_table.setItem(row_position, 4,
                                                  QTableWidgetItem(packet_info.get("proto", "Unknown")))  # Protocol
                        self.packet_table.setItem(row_position, 5,
                                                  QTableWidgetItem(packet_info.get("len", "Unknown")))  # Length
                        self.packet_table.setItem(row_position, 6,
                                                  QTableWidgetItem(packet_info.get("info", "Unknown")))  # Info
                        mp[row_position] = i
                        row_position += 1
                        j += 1
                self.packet_table.cellClicked.connect(lambda row, col: self.show_packet_details(mp[row]))
                self.packet_table.currentCellChanged.connect(lambda row, col: self.show_packet_details(mp[row]))
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Invalid filter")
        else:
            QMessageBox.warning(self, "Error", "Filter expression is empty")

    def load_filters(self):
        # 从文件或数据库中加载保存的过滤器
        # 示例使用文件存储:
        try:
            with open("data/filters.txt", "r") as f:
                return [tuple(line.strip().split(",", 1)) for line in f.readlines()]
        except FileNotFoundError:
            return []

    def save_filters(self):
        # 将过滤器保存到文件或数据库
        with open("data/filters.txt", "w") as f:
            for name, filt in self.filters:
                f.write(f"{name},{filt}\n")

    def show_filter_dialog(self):
        dialog = FilterDialog(self.filters, self.selected_filter_index, self)
        if dialog.exec_() == QDialog.Accepted:
            self.filters = dialog.get_filters()
            self.selected_filter_index = dialog.get_selected_filter_index()
            self.save_filters()

    def fade_out(self):
        self.opacity -= 0.01  # 每次淡出一点
        if self.opacity <= 0:
            self.opacity = 0
            self.check_label.setVisible(False)  # 隐藏标签
            self.timer.stop()  # 停止定时器
        else:
            self.check_label.setStyleSheet(f"color: rgba(0, 0, 0, {self.opacity});")  # 更新透明度

    # 创建右键菜单
    def show_context_menu(self, pos):
        menu = QMenu(self)
        view_action = menu.addAction("Tracing TCP Flows")
        id = self.packet_table.currentRow()
        if self.packet_data[id]["stream"] is None:
            view_action.setEnabled(False)  # 非TCP包禁用
        view_action.triggered.connect(self.tracing_tcp_flows)
        menu.exec_(self.packet_table.mapToGlobal(pos))

    # 追踪TCP流
    def tracing_tcp_flows(self):
        id = self.packet_table.currentRow()
        stream_id = self.packet_data[id]["stream"]
        window = StreamDialog(stream_id, [packet for packet in self.packet_data if packet["stream"] == stream_id], self)
        window.show()

    # 重写键盘事件
    def keyPressEvent(self, event):
        # ctrl+S 保存
        if event.modifiers() == Qt.ControlModifier and event.key() == Qt.Key_S and self.save_button.isEnabled():
            self.save_capture()
        super().keyPressEvent(event)
