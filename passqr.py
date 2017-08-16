import sys
from PyQt5.QtWidgets import QMainWindow, QFileDialog, QLabel, QTextEdit, QApplication, QWidget, QPushButton, QAction, QLineEdit, QMessageBox, QVBoxLayout
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
        self.layout = QVBoxLayout(self)

        # Message
        self.message_lbl = QLabel('Message:')
        self.layout.addWidget(self.message_lbl)
        self.message = QTextEdit(self)
        self.layout.addWidget(self.message)

        # Password
        self.password_lbl = QLabel('Password:')
        self.layout.addWidget(self.password_lbl)
        self.password = QLineEdit(self)
        self.password.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password)

        # Create
        self.create_btn = QPushButton("Create")
        self.create_btn.clicked.connect(self.create)
        self.layout.addWidget(self.create_btn)

        # Load
        self.load_btn = QPushButton("Load")
        self.load_btn.clicked.connect(self.load)
        self.layout.addWidget(self.load_btn)

    def create(self):
        passphrase = self.password.text()
        message = self.message.toPlainText()
        cipher = AESCipher(passphrase)
        encoded = cipher.encrypt(message)
        decoded = cipher.decrypt(encoded)
        if decoded != message:
            QMessageBox.critical(self, "Error", "The decoded message does not match the original message: {}".format(decoded))
            return
        url = pyqrcode.create(encoded, mode='binary')
        url.png('passqr.png', scale=8)
        QMessageBox.information(self, 'Success', 'passqr.png has been created')

    def load(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Open image containing a qr code", "", "PNG (*.png)")
        with open(fname, 'rb') as image_file:
            image = Image.open(image_file)
            image.load()
        passphrase = self.password.text()
        self.message.setPlainText('')
        cipher = AESCipher(passphrase)
        encoded = zbarlight.scan_codes('qrcode', image)[0]
        decoded = cipher.decrypt(encoded)
        self.message.setPlainText('{}'.format(decoded))
        QMessageBox.information(self, 'Success', 'QR code has been read')

class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('PassQr')
        self.resize(400, 300)
        self.main_widget = MainWidget(self)
        self.setCentralWidget(self.main_widget)
        self.show()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())