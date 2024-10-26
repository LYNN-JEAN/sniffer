import sys

from PyQt5.QtWidgets import QApplication

from ui.NetworkSnifferUI import NetworkSnifferUI

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkSnifferUI()
    window.show()
    sys.exit(app.exec_())
