import sys
from PyQt5.QtCore import QSize
from PyQt5.QtWidgets import QFrame, QHBoxLayout, QMainWindow, QFileDialog, QLabel, QTextEdit, QApplication, QWidget, QPushButton, QAction, QLineEdit, QMessageBox, QVBoxLayout
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import pyqrcode
import zbarlight
from PIL import Image


class AESCipher(object):
    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


class MainWidget(QWidget):
    max_characters = 50
    iv = '\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'

    def __init__(self, parent):
        super().__init__(parent)
        self.fname = None
        self.layout = QVBoxLayout(self)

        # Frame 1: Welcome
        self.frame_start = QFrame()
        frame_start_layout = QVBoxLayout()
        frame_start_layout.addWidget(QLabel('Welcome!'))
        frame_start_layout.addSpacing(120)
        frame_start_layout.addWidget(QLabel('Please select an option:'))
        frame_start_btn_layout = QHBoxLayout()
        self.frame_start_create = QPushButton('Create')
        frame_start_btn_layout.addWidget(self.frame_start_create)
        self.frame_start_load = QPushButton('Load')
        frame_start_btn_layout.addWidget(self.frame_start_load)
        frame_start_layout.addLayout(frame_start_btn_layout)
        self.frame_start.setLayout(frame_start_layout)
        self.layout.addWidget(self.frame_start)

        # Frame 2: Password
        self.frame_pass = QFrame()
        frame_pass_layout = QVBoxLayout()
        frame_pass_layout.addSpacing(120)
        frame_pass_layout.addWidget(QLabel('Please enter your password:'))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        frame_pass_layout.addWidget(self.password)
        frame_pass_btn_layout = QHBoxLayout()
        self.frame_pass_back = QPushButton('Back')
        frame_pass_btn_layout.addWidget(self.frame_pass_back)
        self.frame_pass_next = QPushButton('Next')
        frame_pass_btn_layout.addWidget(self.frame_pass_next)
        frame_pass_layout.addLayout(frame_pass_btn_layout)
        self.frame_pass.setLayout(frame_pass_layout)
        self.layout.addWidget(self.frame_pass)

        # Frame 3: Message
        self.frame_msg = QFrame()
        frame_msg_layout = QVBoxLayout()
        frame_msg_layout.addWidget(QLabel('Message:'))
        self.message = QTextEdit(self)
        frame_msg_layout.addWidget(self.message)
        frame_msg_btn_layout = QHBoxLayout()
        self.frame_msg_back = QPushButton('Back')
        frame_msg_btn_layout.addWidget(self.frame_msg_back)
        self.frame_msg_save = QPushButton('Save')
        frame_msg_btn_layout.addWidget(self.frame_msg_save)
        frame_msg_layout.addLayout(frame_msg_btn_layout)
        self.frame_msg.setLayout(frame_msg_layout)
        self.layout.addWidget(self.frame_msg)
        # self.load_btn.clicked.connect(self.load)

        # Actions
        self.frame_start_create.clicked.connect(self.on_create)
        self.frame_start_load.clicked.connect(self.on_load)

        self.frame_pass_next.clicked.connect(self.on_next)
        self.frame_pass_back.clicked.connect(self.on_back_pass)

        self.frame_msg_back.clicked.connect(self.on_back_msg)
        self.frame_msg_save.clicked.connect(self.on_save)

        # Initial view
        self.frame_pass.hide()
        self.frame_msg.hide()

    def on_create(self):
        self.message.setText('')
        self.frame_start.hide()
        self.frame_pass.show()
        self.password.setFocus()

    def on_load(self):
        self.fname, _ = QFileDialog.getOpenFileName(self, "Open image containing a qr code", "qrcode.png", "PNG (*.png)")
        if self.fname:
            self.message.setText('')
            self.frame_start.hide()
            self.frame_pass.show()
            self.password.setFocus()

    def on_next(self):
        if self.fname:
            with open(self.fname, 'rb') as image_file:
                image = Image.open(image_file)
                image.load()
            passphrase = self.password.text()
            self.message.setPlainText('')
            cipher = AESCipher(passphrase)
            encoded = zbarlight.scan_codes('qrcode', image)[0]
            decoded = cipher.decrypt(encoded)
            self.message.setPlainText('{}'.format(decoded))
        self.frame_pass.hide()
        self.frame_msg.show()
        self.message.setFocus()

    def on_back_pass(self):
        self.frame_pass.hide()
        self.frame_start.show()

    def on_back_msg(self):
        self.frame_msg.hide()
        self.frame_pass.show()
        self.password.setFocus()

    def on_save(self):
        fname, _ = QFileDialog.getSaveFileName(self, "Open image containing a qr code", "qrcode.png", "PNG (*.png)")
        if fname:
            passphrase = self.password.text()
            message = self.message.toPlainText()
            cipher = AESCipher(passphrase)
            encoded = cipher.encrypt(message)
            decoded = cipher.decrypt(encoded)
            if decoded != message:
                QMessageBox.critical(self, "Error", "The decoded message does not match the original message: {}".format(decoded))
                return
            url = pyqrcode.create(encoded, mode='binary')
            url.png(fname, scale=8)
            QMessageBox.information(self, 'Success', 'File has been created')


class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('PassQr')
        # self.resize(300, 200)
        self.setFixedSize(QSize(300, 200))
        self.main_widget = MainWidget(self)
        self.setCentralWidget(self.main_widget)
        self.show()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())
